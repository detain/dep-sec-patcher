<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use Detain\DepSecPatcher\Auditor\Auditor;
use Detain\DepSecPatcher\Auditor\ComposerAuditor;
use Detain\DepSecPatcher\Auditor\ConcurrencyPolicy;
use Detain\DepSecPatcher\Auditor\DotnetAuditor;
use Detain\DepSecPatcher\Auditor\GoAuditor;
use Detain\DepSecPatcher\Auditor\GradleAuditor;
use Detain\DepSecPatcher\Auditor\MavenAuditor;
use Detain\DepSecPatcher\Auditor\NodeAuditor;
use Detain\DepSecPatcher\Auditor\PythonAuditor;
use Detain\DepSecPatcher\Auditor\RubyAuditor;
use Detain\DepSecPatcher\Auditor\RustAuditor;
use Detain\DepSecPatcher\Auditor\SbtAuditor;
use Detain\DepSecPatcher\Auditor\SimpleAuditor;
use Detain\DepSecPatcher\Scanner\NetworkScanner;
use Detain\DepSecPatcher\Scanner\Scanners;
use RuntimeException;

/**
 * One run: GitHub collection, auto-fix, ecosystem updates and audits,
 * scanners, PR triage, optional push (branch, pull request or direct),
 * close-fixed, summary and JSON report.
 */
final class SecurityRun
{
    private const STATUS_RANK = ['SKIP' => 0, 'PASS' => 1, 'WARN' => 2, 'FAIL' => 3];

    /** @var array<string, array{status: string, vulns: int, outdated: int, note: string}> */
    private array $summary = [];
    private string $now;
    private ?GitHub $gh = null;
    private Context $ctx;
    private string $root;
    /** @var list<string> manifest edits made by auto-fix, for the commit message */
    private array $appliedFixes = [];
    /** @var array<string, list<string>|null> npm registry versions per package, asked once per run */
    private array $npmVersions = [];
    /** Which versions the registries publish, asked once per package per run */
    private RegistryProbe $registry;
    /** Whether this run's changes reached the base branch on origin; null when not pushing. */
    private ?bool $landed = null;
    /** Whether the git tree was clean before the run; null outside a work tree. */
    private ?bool $cleanAtStart = null;
    /** What the run found but left undone, for the closing "Next steps". */
    private int $readyFixes = 0;
    private int $needsMajor = 0;
    private int $mergeablePrs = 0;
    private int $wouldClose = 0;
    /** @var list<int>|null every open issue's number, when the collection read them all */
    private ?array $openIssueNumbers = null;
    private int $openIssueRecords = 0;

    public function __construct(
        private Options $opt,
        private Console $console,
        private Target $target,
        private string $vulnDb,
        private string $reportDir,
        private string $configFile = '',
        /** @var list<string> the command line, program first, for suggesting the next one */
        private array $argv = [],
        /** Where OSV answers are cached between runs; '' keeps them for this run only */
        private string $advisoryCache = '',
        ?RegistryProbe $registry = null,
    ) {
        $this->now      = gmdate('Y-m-d\TH:i:s\Z');
        $this->root     = $target->root;
        $this->registry = $registry ?? new RegistryProbe();
    }

    public function run(): int
    {
        $c = $this->console;
        if ($this->target->remote) {
            $c->line('target: ' . GitUrl::redact($this->target->url));
        }
        $c->line("root: {$this->root}");
        if ($this->target->subdir !== '') {
            $c->line("subdir: {$this->target->subdir}");
        }
        $c->line('github repo: ' . ($this->target->githubRepo !== '' ? $this->target->githubRepo : 'none')
            . ($this->target->repoNote !== '' ? " ({$this->target->repoNote})" : ''));
        if ($this->configFile !== '') {
            $c->line("config: {$this->configFile}");
        }
        $c->line("mode: {$this->opt->mode}");
        $c->line("vuln db: {$this->vulnDb}");
        $c->line("reports: {$this->reportDir}");
        $c->line('threads: ' . $this->opt->threads . ', command timeout: '
            . ($this->opt->timeout > 0 ? CommandResult::duration($this->opt->timeout) : 'none'));
        $c->line();

        $runner = new ProcessRunner($c, $this->opt->timeout, $this->opt->verbose, $this->opt->debug);
        $index  = $this->opt->applyStored
            ? ManifestIndex::fromList($this->root, [])
            : new ManifestIndex($this->root, $this->target->subdir, $this->opt->excludeDirs);
        $this->ctx = new Context($this->opt, $c, $runner, $this->root, $this->reportDir, $index, $this->target->subdir);
        $nvd = $this->opt->nvdApiKey !== '' ? $this->opt->nvdApiKey : TokenHarvester::find('NVD_API_KEY');
        $this->ctx->state['nvd_api_key'] = (string)$nvd;

        // --push publishes only this run's changes, so note the tree's state
        // before anything touches it
        $publisher    = null;
        $cleanAtStart = null;
        $startBranch  = '';
        if ($this->opt->mode === 'update') {
            // What is uncommitted now stays out of the commit --push makes
            $snapshotter = new BranchPublisher($runner, $c, $this->root, $this->opt->timeout > 0 ? $this->opt->timeout : 600);
            $before      = $snapshotter->snapshot();
            $this->cleanAtStart = $before === null ? null : $before === [];
            if ($this->opt->push) {
                $publisher    = $snapshotter;
                $cleanAtStart = $this->cleanAtStart;
                $startBranch  = $cleanAtStart === null ? '' : $publisher->currentBranch();
                if ($before !== null && $before !== []) {
                    $c->info('push: ' . count($before) . ' path(s) were already uncommitted before the run; they are left out of the commit');
                }
            }
        }

        // Authenticate gh once up front so every GitHub step shares the result
        if ($this->opt->githubEnabled() && $this->target->githubRepo !== '') {
            $this->gh = new GitHub($runner, $c, $this->root);
            $this->gh()->ensureAuth();
        }

        // When the result is pushed, merge the bot PRs first and pull them in,
        // so this run's updates are made on top of them instead of
        // conflicting with them at push time
        $triaged = false;
        if ($publisher !== null && $cleanAtStart !== null && !$this->opt->applyStored) {
            $this->triagePullRequests();
            $triaged = true;
            if ($startBranch !== '') {
                $publisher->syncWithOrigin($startBranch);
            }
        }

        // GitHub's alerts are written into the manifests before the ecosystem
        // updates run, so the lockfiles are regenerated from the fixed
        // manifests and the audits report the result
        $this->collectGitHub();
        $this->applyFixes();

        if ($this->opt->applyStored) {
            $c->info('Ecosystem updaters: skipped (--apply-stored)');
        } else {
            $this->runEcosystems();
        }

        $this->runScanners();
        $this->checkRepoSettings();
        if (!$triaged) {
            $this->triagePullRequests();
        }
        // Publish before close-fixed, which only closes what reached the base branch
        $this->publishChanges($publisher, $cleanAtStart, $startBranch);
        $this->closeFixedIssues();

        $this->printSummary();
        $this->nextSteps();
        $this->writeReport();

        if ($this->opt->strict && $this->failed()) {
            return 3;
        }
        return 0;
    }

    /**
     * Whether anything failed: a [FAIL] line, or a FAIL row in the summary.
     */
    public function failed(): bool
    {
        if ($this->console->fail > 0) {
            return true;
        }
        foreach ($this->summary as $row) {
            if ($row['status'] === 'FAIL') {
                return true;
            }
        }
        return false;
    }

    // ── ecosystems ───────────────────────────────────────────────────────────

    /**
     * @return list<Auditor>
     */
    private function auditors(): array
    {
        return [
            new MavenAuditor(), new GradleAuditor(), new SbtAuditor(), new NodeAuditor(), new ComposerAuditor(),
            new PythonAuditor(), new RubyAuditor(), new GoAuditor(), new RustAuditor(), new DotnetAuditor(),
            SimpleAuditor::dart(), SimpleAuditor::elixir(), SimpleAuditor::swift(), SimpleAuditor::r(),
        ];
    }

    private function runEcosystems(): void
    {
        $c        = $this->console;
        $jobs     = [];
        $limits   = [];
        $policies = [];
        $active   = [];

        foreach ($this->auditors() as $auditor) {
            $name = $auditor->name();
            if (!$this->opt->wants($name)) {
                continue;
            }
            $why = $auditor->skipReason($this->ctx);
            if ($why !== null) {
                $c->skip("{$name} ({$why})");
                $this->record($name, 'SKIP');
                continue;
            }
            $targets = $auditor->targets($this->ctx);
            if ($targets === []) {
                $c->skip("{$name} (no " . implode('/', $auditor->manifests()) . ' found)');
                $this->record($name, 'SKIP');
                continue;
            }
            $active[] = [$auditor, $targets];
            foreach ($targets as $dir) {
                $jobs[] = [$auditor, $dir, $auditor->group($this->ctx, $dir)];
            }
        }
        if ($jobs === []) {
            return;
        }

        if ($this->opt->threads > 1) {
            $used = array_flip(array_map(static fn ($j) => $j[2], $jobs));
            foreach ($active as [$auditor]) {
                foreach ($auditor->concurrency($this->ctx) as $group => $policy) {
                    if (isset($used[$group])) {
                        $policies[$group] = $policy;
                        $limits[$group]   = $policy->limit;
                    }
                }
            }
            $this->announceConcurrency($policies);
        }

        $c->heading('Preparing');
        foreach ($active as [$auditor, $targets]) {
            $auditor->prepare($this->ctx, $targets);
        }

        $c->heading('Auditing ' . count($jobs) . ' project' . (count($jobs) === 1 ? '' : 's'));
        $ctx = $this->ctx;
        ForkPool::run(
            $jobs,
            $this->opt->threads,
            static fn (array $job): string => $job[2],
            $limits,
            static function (array $job) use ($ctx): TargetResult {
                [$auditor, $dir] = $job;
                $guards = [];
                foreach ($auditor->guardDirs($ctx, $dir) as $g) {
                    $guards[] = new WorkspaceGuard(
                        $g === '' ? $ctx->root : $ctx->root . '/' . $g,
                        $ctx->checkMode(),
                        $g === $dir ? $auditor->guardPurge($ctx, $dir) : []
                    );
                }
                $start = microtime(true);
                try {
                    $result = $auditor->audit($ctx, $dir);
                } catch (\Throwable $e) {
                    $result = new TargetResult(TargetResult::ERROR, get_class($e) . ': ' . $e->getMessage());
                } finally {
                    $undone = [];
                    foreach ($guards as $guard) {
                        $undone = array_merge($undone, $guard->restore());
                    }
                }
                $result->seconds = microtime(true) - $start;
                if ($undone !== [] && $ctx->opt->debug) {
                    $result->note('check mode, undone: ' . implode(', ', $undone));
                }
                return $result;
            },
            function (array $job, mixed $result): void {
                [$auditor, $dir] = $job;
                if (is_array($result) && isset($result['__worker_error'])) {
                    $result = new TargetResult(TargetResult::ERROR, (string)$result['__worker_error']);
                }
                $this->report($auditor->name(), $dir, $result instanceof TargetResult
                    ? $result
                    : new TargetResult(TargetResult::ERROR, 'worker returned no result'));
            },
            // Two audits of one directory (package.json and composer.json side
            // by side) would undo each other's work through their guards
            static fn (array $job): array => array_map(
                static fn (string $g): string => $g === '' ? '.' : $g,
                $job[0]->guardDirs($ctx, $job[1])
            )
        );
    }

    /**
     * Startup notice for tools held to one job at a time, naming the version
     * that would lift the limit where there is one.
     *
     * @param array<string, ConcurrencyPolicy> $policies
     */
    private function announceConcurrency(array $policies): void
    {
        $alwaysSerial = [];
        $shown        = [];
        foreach ($policies as $policy) {
            if (!$policy->serialised() || isset($shown[$policy->tool])) {
                continue;
            }
            $shown[$policy->tool] = true;
            if ($policy->minimum !== '') {
                $this->console->warn($policy->notice());
            } else {
                $alwaysSerial[] = $policy->tool . ($policy->version !== '' ? ' ' . $policy->version : '');
            }
        }
        if ($alwaysSerial !== []) {
            $this->console->info('One job at a time regardless of version (no concurrency-safe release known): '
                . implode(', ', $alwaysSerial));
        }
    }

    private function report(string $name, string $dir, TargetResult $r): void
    {
        $c     = $this->console;
        $label = "[{$name}] " . ($dir === '' ? '.' : $dir);
        $msg   = $label . ($r->detail !== '' ? " — {$r->detail}" : '')
            . ($r->seconds >= 1 ? ' (' . CommandResult::duration($r->seconds) . ')' : '');
        match ($r->status) {
            TargetResult::PASS  => $c->ok($msg),
            TargetResult::FAIL  => $c->fail($msg),
            TargetResult::ERROR => $c->fail($msg . ' [tool error]'),
            TargetResult::WARN  => $c->warn($msg),
            default             => $c->skip($msg),
        };
        foreach ($r->notes as $note) {
            $c->detail($note);
        }
        if ($r->status !== TargetResult::PASS && !$this->opt->verbose) {
            foreach ($r->tail as $line) {
                $c->detail('| ' . $line);
            }
        }
        $this->record($name, $r->status === TargetResult::ERROR ? 'FAIL' : $r->status, $r->vulns, $r->outdated);
    }

    // ── scanners ─────────────────────────────────────────────────────────────

    private function runScanners(): void
    {
        $c = $this->console;
        if ($this->opt->wants('bandit')) {
            $this->scannerResult('bandit', Scanners::bandit($this->ctx));
        } elseif (!$this->opt->applyStored) {
            $c->skip('bandit (disabled)');
            $this->record('bandit', 'SKIP');
        }
        if ($this->opt->wants('trivy')) {
            $c->info('Starting Trivy filesystem scan...');
            $this->scannerResult('trivy', Scanners::trivy($this->ctx));
        } elseif (!$this->opt->applyStored) {
            $c->skip('trivy (disabled)');
            $this->record('trivy', 'SKIP');
        }
        if ($this->opt->wants('grype')) {
            foreach (Scanners::grype($this->ctx) as [$dir, $result]) {
                $this->report('grype', $dir, $result);
            }
        }
        if ($this->opt->wants('netsec')) {
            $this->networkChecks();
        }
    }

    private function scannerResult(string $name, ?TargetResult $r): void
    {
        if ($r === null) {
            return;
        }
        if ($r->status === TargetResult::SKIP) {
            $this->console->skip("{$name} ({$r->detail})");
            $this->record($name, 'SKIP');
            return;
        }
        $this->report($name, '', $r);
    }

    private function networkChecks(): void
    {
        $c = $this->console;
        $c->info('Running network/API security checks...');
        $found = NetworkScanner::scan($this->ctx->files->files(), NetworkScanner::fileReader($this->root), $this->opt->allowHttp);
        $total = 0;

        $list = static fn (array $files): string => implode(', ', array_slice($files, 0, 5)) . (count($files) > 5 ? ', …' : '');
        if ($found['http'] !== []) {
            $c->warn('netsec: ' . count($found['http']) . ' config files reference plain-HTTP endpoints: ' . $list($found['http']));
            $total += count($found['http']);
        } else {
            $c->ok('netsec: no plain-HTTP endpoints in config files');
        }
        if ($found['credentials'] !== []) {
            $files = array_values(array_unique(array_merge(...array_values($found['credentials']))));
            $c->fail('netsec: possible hardcoded credentials in ' . count($files) . ' files ('
                . implode(', ', array_map(static fn ($k, $v) => count($v) . " {$k}", array_keys($found['credentials']), $found['credentials'])) . ')');
            foreach (array_slice($files, 0, 10) as $file) {
                $c->detail($file);
            }
            $total += count($files);
        } else {
            $c->ok('netsec: no hardcoded credentials detected');
        }
        if ($found['tls'] !== []) {
            $c->warn('netsec: ' . count($found['tls']) . ' files mention TLS 1.0/1.1: ' . $list($found['tls']));
            $total += count($found['tls']);
        } else {
            $c->ok('netsec: no insecure TLS settings found');
        }
        $this->record('network-security', $found['credentials'] !== [] ? 'FAIL' : ($total > 0 ? 'WARN' : 'PASS'), $total);
    }

    // ── GitHub ───────────────────────────────────────────────────────────────

    private function githubReady(): bool
    {
        return $this->gh !== null && $this->gh->ready;
    }

    /**
     * The GitHub client, for steps that already checked githubReady().
     */
    private function gh(): GitHub
    {
        if ($this->gh === null) {
            throw new \LogicException('GitHub client used before githubReady() was checked');
        }
        return $this->gh;
    }

    private function repo(): string
    {
        return $this->gh?->resolveRepo($this->target->githubRepo) ?? '';
    }

    /**
     * Why there is no GitHub repository to work with, for SKIP lines.
     */
    private function noRepoReason(): string
    {
        return 'no GitHub repository' . ($this->target->repoNote !== '' ? ": {$this->target->repoNote}" : '')
            . '; pass --repo OWNER/NAME';
    }

    /**
     * Dependabot alerts, repository advisories and security-bot issues,
     * normalised into the local vulnerability database.
     */
    private function collectGitHub(): void
    {
        $c = $this->console;
        if (!$this->opt->githubEnabled()) {
            $c->skip('github (disabled via --no-github)');
            $this->record('dependabot', 'SKIP');
            return;
        }
        if ($this->opt->applyStored) {
            $c->info('github: skipping API collection (--apply-stored)');
            return;
        }
        if ($this->target->githubRepo === '') {
            $c->skip('github (' . $this->noRepoReason() . ')');
            $this->record('dependabot', 'SKIP');
            return;
        }
        if (!$this->githubReady()) {
            $c->skip('github (gh unavailable or unauthenticated)');
            $this->record('dependabot', 'SKIP');
            return;
        }
        $repo = $this->repo();
        $c->info("GitHub repository: {$repo}");

        $alerts = $this->gh()->paginate("repos/{$repo}/dependabot/alerts?state=open&per_page=100");
        $alertRecords = RecordNormalizer::fromDependabotAlerts($alerts ?? []);
        if ($alerts === null) {
            $c->warn('Dependabot: could not list alerts (API error or no access)');
            $this->record('dependabot', 'SKIP');
        } elseif ($alertRecords !== []) {
            $c->info('Dependabot: ' . count($alertRecords) . ' open alerts');
            $this->record('dependabot', 'FAIL', count($alertRecords));
            foreach (['ecosystem' => '  - %2$s: %1$d', 'severity' => '  severity %2$s: %1$d'] as $field => $fmt) {
                $counts = array_count_values(array_map(static fn ($r) => (string)$r[$field], $alertRecords));
                arsort($counts);
                foreach ($counts as $value => $n) {
                    $c->info(sprintf($fmt, $n, $value));
                }
            }
        } else {
            $c->ok('Dependabot: no open alerts');
            $this->record('dependabot', 'PASS');
        }

        $status     = null;
        $advisories = $this->gh()->paginate("repos/{$repo}/security-advisories?per_page=100", $status);
        $advRecords = RecordNormalizer::fromSecurityAdvisories($advisories ?? []);
        if ($advisories === null && $status !== 404) {
            $c->warn('Security advisories: could not list (API error)');
        } elseif ($advRecords !== []) {
            $c->info('Security advisories: ' . count($advRecords));
            $this->record('advisories', 'FAIL', count($advRecords));
        } else {
            $c->ok('Security advisories: none published');
            $this->record('advisories', 'PASS');
        }

        $limit    = $this->opt->maxIssues;
        $complete = false;
        $issues   = $this->gh()->openIssues($repo, $limit, true, $complete);
        $issueRecords = $botIssues = [];
        if ($issues === null) {
            $c->warn("Could not list issues for {$repo}");
            $this->record('sec-issues', 'SKIP');
        } else {
            if (!$complete) {
                // Records for the rest arrive as earlier issues are closed
                $c->warn("Security issues: only the newest {$limit} open issues were read (--max-issues; 0 reads them all)");
            } else {
                // close-fixed needs the same list; a complete one saves reading it twice
                $this->openIssueNumbers = array_map(static fn (array $i): int => (int)$i['number'], $issues);
            }
            // Issue bodies become manifest edits, so only a security bot's count
            $botIssues    = array_values(array_filter($issues, static fn ($i) => self::isBot($i['author'] ?? null)));
            // An issue whose fixes are all on another major line, or that lists
            // none, is completed from OSV; one that names no dependency file
            // (an sbt scan) is placed by the build.sbt declaring its library
            $osv          = new AdvisoryLookup($this->advisoryCache, null, $c);
            $sbt          = new SbtLocator($this->ctx->files->files(), function (string $rel): ?string {
                $abs = $this->insideRoot($rel);
                return $abs === null ? null : (string)@file_get_contents($abs);
            });
            $issueRecords = IssueParser::parse($botIssues, $osv->asCallable(), $sbt);
            $fromOsv = count(array_filter($issueRecords, static fn (array $r): bool => ($r['fix_source'] ?? '') === 'osv'));
            if ($fromOsv > 0) {
                $c->info("Security issues: {$fromOsv} records took their fix from OSV");
            }
            if ($issueRecords !== []) {
                $refs = count(array_unique(array_map(static fn ($r) => $r['ref'], $issueRecords)));
                $c->info("Security issues: {$refs} issues -> " . count($issueRecords) . ' remediation records');
                $this->record('sec-issues', 'FAIL', $refs);
            } else {
                $c->ok('Security issues: none parsed');
                $this->record('sec-issues', 'PASS');
            }
        }

        $merged = array_map([RecordNormalizer::class, 'withEcosystem'], array_merge($alertRecords, $advRecords, $issueRecords));
        $db     = $this->loadDb();
        if ($merged === [] && $db['vulns'] === []) {
            $c->info('No vulnerability records collected');
            return;
        }
        $db = VulnDb::upsert($db, $merged, $this->now, $this->gh()->slug);
        if ($issues !== null) {
            // What an issue reported when last read gives way to what it reports now
            $db = VulnDb::supersede($db, $issueRecords, array_fill_keys(array_map('intval', array_column($botIssues, 'number')), true));
        }
        // Alerts fixed or dismissed and issues closed since they were recorded
        // are retired, but only from a complete listing
        if ($alerts !== null) {
            $db = VulnDb::retire($db, 'dependabot', array_fill_keys(array_column($alertRecords, 'key'), true), $this->now);
        }
        if ($issues !== null && $complete) {
            $open = array_fill_keys(array_map('intval', array_column($issues, 'number')), true);
            $db   = VulnDb::retire($db, 'issue', array_fill_keys(array_column($issueRecords, 'key'), true), $this->now, $open);
        }
        $this->openIssueRecords = count(array_filter($db['vulns'], static fn ($v) => ($v['source'] ?? null) === 'issue'
            && in_array($v['state'] ?? null, ['pending', 'applied'], true)));
        if ($this->saveDb($db)) {
            $c->ok('vuln DB: ' . count($db['vulns']) . ' records (' . VulnDb::countState($db, 'pending') . " pending) -> {$this->vulnDb}");
        }
    }

    private function checkRepoSettings(): void
    {
        $c = $this->console;
        if (!$this->opt->githubEnabled() || $this->opt->applyStored) {
            $c->skip('secret scanning (GitHub checks disabled)');
            $this->record('secret-scanning', 'SKIP');
            return;
        }
        if ($this->target->githubRepo === '') {
            $c->skip('secret scanning (no GitHub repository)');
            $this->record('secret-scanning', 'SKIP');
            return;
        }
        if (!$this->githubReady()) {
            $c->skip('gh (unavailable or unauthenticated - cannot check secret scanning)');
            $this->record('secret-scanning', 'SKIP');
            return;
        }
        $c->info('Checking repository security settings...');
        $info = $this->gh()->json(['api', 'repos/' . $this->repo()], 60);
        $sa   = is_array($info) ? ($info['security_and_analysis'] ?? null) : null;
        if (!is_array($sa)) {
            $c->skip('Secret scanning: cannot determine status');
            $this->record('secret-scanning', 'SKIP');
            return;
        }
        $secret = (string)($sa['secret_scanning']['status'] ?? 'unknown');
        if ($secret === 'enabled') {
            $c->ok('Secret scanning: enabled');
            $this->record('secret-scanning', 'PASS');
        } else {
            $c->fail("Secret scanning: {$secret}");
            $this->record('secret-scanning', 'FAIL');
        }
        $dependabot = (string)($sa['dependabot_security_updates']['status'] ?? 'unknown');
        $dependabot === 'enabled'
            ? $c->ok('Dependabot security updates: enabled')
            : $c->fail("Dependabot security updates: {$dependabot}");
        $scanning = $sa['code_scanning']['default_setup']['summary'] ?? null;
        if (is_string($scanning)) {
            $scanning === 'configured' ? $c->ok('Code scanning: configured') : $c->info("Code scanning: {$scanning}");
        }
    }

    // ── dependency-bot PR triage ─────────────────────────────────────────────

    private function triagePullRequests(): void
    {
        $c = $this->console;
        if (!$this->opt->githubEnabled() || $this->opt->mergePrs === 'no') {
            $c->skip('PR triage (disabled)');
            return;
        }
        if ($this->opt->applyStored) {
            $c->info('PR triage: skipped (--apply-stored)');
            return;
        }
        if ($this->target->githubRepo === '') {
            $c->skip('PR triage (no GitHub repository)');
            return;
        }
        if (!$this->githubReady()) {
            $c->skip('PR triage (gh unavailable or unauthenticated)');
            return;
        }
        $repo = $this->repo();
        $c->info("Triaging dependency-bot PRs on {$repo}...");

        $prs = $this->gh()->json(['pr', 'list', '--repo', $repo, '--state', 'open', '--limit', '100',
            '--json', 'number,title,author,isDraft,headRefName,body']);
        if (!is_array($prs)) {
            $c->warn('PR triage: could not list pull requests');
            return;
        }
        // Only touch PRs raised by dependency bots, never a human contributor's work
        $bots = array_values(array_filter($prs, static fn ($pr) => empty($pr['isDraft']) && self::isBot($pr['author'] ?? null)));
        if ($bots === []) {
            $c->ok($prs === [] ? 'No open PRs' : 'No dependency-bot PRs open');
            $this->record('dep-prs', 'PASS');
            return;
        }
        $c->info('Found ' . count($bots) . ' dependency-bot PR(s)');

        $merged = $rebased = $blocked = 0;
        $defaultBranch = null;
        foreach ($bots as $pr) {
            $num    = (string)$pr['number'];
            $author = (string)($pr['author']['login'] ?? '');
            [$mergeable, $status] = $this->mergeState($repo, $num);
            $c->info("PR #{$num} [{$mergeable}/{$status}] " . ($pr['title'] ?? ''));
            // A bot PR moving a dependency to a new major version gets the
            // same opt-in as an auto-fix doing it
            $majors = $this->opt->allowMajor ? [] : self::majorBumps((string)($pr['title'] ?? ''), (string)($pr['body'] ?? ''));
            if ($this->opt->mode !== 'update') {
                if ($majors !== []) {
                    $this->needsMajor++;
                } else {
                    $this->mergeablePrs += $mergeable === 'MERGEABLE' && $status !== 'UNSTABLE' ? 1 : 0;
                }
                continue;
            }
            $rebaseCmd = self::rebaseCommand($author);
            if ($majors !== []) {
                $c->warn("  PR #{$num} is a major upgrade (" . implode(', ', $majors) . '); not merged without --allow-major');
                $this->needsMajor++;
                $blocked++;
            } elseif ($mergeable === 'MERGEABLE') {
                if ($status === 'UNSTABLE') {
                    // Failing or still-running checks: merging now could ship a broken build
                    $c->warn("  PR #{$num} has checks that are failing or still running; left for a later run");
                    $blocked++;
                } elseif ($status === 'BLOCKED') {
                    $c->warn("  PR #{$num} is mergeable but blocked by branch protection");
                    $blocked++;
                } elseif ($status === 'BEHIND') {
                    if ($rebaseCmd !== '' && !$this->rebaseRequested($repo, $num)) {
                        if ($this->comment($repo, $num, $rebaseCmd)) {
                            $c->ok("  Asked {$author} to rebase PR #{$num} (branch behind base)");
                            $rebased++;
                        }
                    } else {
                        $c->info("  PR #{$num} behind base, rebase already requested");
                    }
                } elseif ($this->gh()->run(['pr', 'merge', $num, '--repo', $repo, '--squash', '--delete-branch'])->ok()) {
                    $c->ok("  Merged PR #{$num}");
                    $merged++;
                } elseif ($this->gh()->run(['pr', 'merge', $num, '--repo', $repo, '--squash', '--auto', '--delete-branch'])->ok()) {
                    $c->ok("  Enabled auto-merge on PR #{$num} (pending required checks)");
                    $merged++;
                } else {
                    $c->fail("  Could not merge PR #{$num}");
                    $blocked++;
                }
            } elseif ($mergeable === 'CONFLICTING') {
                $comments = $this->prComments($repo, $num);
                $refused  = false;
                foreach ($comments['comments'] as $cm) {
                    if (preg_match('/can.t be rebased|Please close the PR/', (string)($cm['body'] ?? '')) === 1) {
                        $refused = true;
                    }
                }
                if ($refused) {
                    $c->warn("  PR #{$num} cannot be rebased by {$author} — close it so a fresh PR is raised");
                    $blocked++;
                } elseif ($this->rebaseRequested($repo, $num, $comments)) {
                    $c->info("  PR #{$num} conflicts, rebase already requested — waiting on {$author}");
                } elseif ($rebaseCmd !== '') {
                    if ($this->comment($repo, $num, $rebaseCmd)) {
                        $c->ok("  PR #{$num} conflicts — commented '{$rebaseCmd}'");
                        $rebased++;
                    } else {
                        $c->fail("  PR #{$num} conflicts — could not post rebase comment");
                    }
                } else {
                    // No bot command available: leave the human-runnable equivalent
                    if ($defaultBranch === null) {
                        $info          = $this->gh()->json(['repo', 'view', $repo, '--json', 'defaultBranchRef'], 60);
                        $defaultBranch = (string)($info['defaultBranchRef']['name'] ?? 'master');
                    }
                    $branch = (string)($pr['headRefName'] ?? '');
                    $body   = "This PR has merge conflicts. To rebase it manually:\n\n```bash\n"
                        . "git fetch origin && git checkout {$branch} && git rebase origin/{$defaultBranch} && git push --force-with-lease\n```";
                    if ($this->comment($repo, $num, $body)) {
                        $c->ok("  PR #{$num} conflicts — posted manual rebase instructions");
                        $rebased++;
                    }
                }
            } else {
                $c->warn("  PR #{$num} mergeability still {$mergeable} — skipped this run");
                $blocked++;
            }
        }
        $c->info("PR triage: merged={$merged} rebase-requested={$rebased} blocked={$blocked}");
        $this->record('dep-prs', $blocked > 0 ? 'FAIL' : 'PASS', $blocked, count($bots));
    }

    /**
     * GitHub computes mergeability lazily: the first query returns UNKNOWN and
     * starts the job, so poll until it settles.
     *
     * @return array{0: string, 1: string}
     */
    private function mergeState(string $repo, string $num): array
    {
        $state = ['UNKNOWN', 'UNKNOWN'];
        for ($i = 0; $i < 6; $i++) {
            $data = $this->gh()->json(['pr', 'view', $num, '--repo', $repo, '--json', 'mergeable,mergeStateStatus'], 60);
            $m    = (string)($data['mergeable'] ?? '');
            if ($m !== '' && $m !== 'UNKNOWN') {
                return [$m, (string)($data['mergeStateStatus'] ?? 'UNKNOWN')];
            }
            sleep(2);
        }
        return $state;
    }

    /**
     * @return array{comments: list<array<mixed>>, commits: list<array<mixed>>}
     */
    private function prComments(string $repo, string $num): array
    {
        $data = $this->gh()->json(['pr', 'view', $num, '--repo', $repo, '--json', 'comments,commits'], 60);
        $rows = static fn (mixed $v): array => is_array($v) ? array_values(array_filter($v, 'is_array')) : [];
        return [
            'comments' => $rows(is_array($data) ? ($data['comments'] ?? null) : null),
            'commits'  => $rows(is_array($data) ? ($data['commits'] ?? null) : null),
        ];
    }

    /**
     * Whether our last rebase request is still outstanding: nothing has been
     * pushed to the branch since we asked. (Comparing against the newest
     * comment would not do: the bot's own reply displaces ours.)
     *
     * @param array{comments: list<array<mixed>>, commits: list<array<mixed>>}|null $data
     */
    private function rebaseRequested(string $repo, string $num, ?array $data = null): bool
    {
        $data ??= $this->prComments($repo, $num);
        $lastReq = '';
        foreach ($data['comments'] as $cm) {
            if (str_contains((string)($cm['body'] ?? ''), 'security-update:rebase')) {
                $lastReq = (string)($cm['createdAt'] ?? '');
            }
        }
        if ($lastReq === '') {
            return false;
        }
        $commits  = $data['commits'];
        $headTime = $commits === [] ? '' : (string)($commits[count($commits) - 1]['committedDate'] ?? '');
        // Cannot compare: assume the request stands rather than risk comment spam
        return $headTime === '' || strcmp($lastReq, $headTime) > 0;   // ISO-8601 UTC sorts lexically
    }

    private function comment(string $repo, string $num, string $body): bool
    {
        return $this->gh()->run(['pr', 'comment', $num, '--repo', $repo, '--body', $body . "\n\n<!-- security-update:rebase -->"])->ok();
    }

    /**
     * A dependency or security bot: a GitHub App account (which no user can
     * impersonate) with one of the known names. A substring match on the
     * login alone would trust "amendoza" or a freshly registered "renovate-fan".
     */
    private static function isBot(mixed $author): bool
    {
        return is_array($author) && ($author['is_bot'] ?? false) === true
            && preg_match('#^(?:app/)?(?:dependabot|renovate|mend|whitesource|snyk)#i', (string)($author['login'] ?? '')) === 1;
    }

    /**
     * The version bumps in a bot PR that cross a major line, as
     * "bootstrap 3.4.1 -> 5.0.0". Read from Dependabot's title ("Bump x from
     * A to B") and body ("Updates `x` from A to B"), and Renovate's table
     * rows ("| [x](..) | `A` -> `B` |"); the changelog quoted further down a
     * body is not looked at.
     *
     * @return list<string>
     */
    private static function majorBumps(string $title, string $body): array
    {
        $bumps = [];
        $v     = '[vV]?([0-9][0-9A-Za-z.+-]*)';
        if (preg_match('/^Bump (\S+) from ' . $v . ' to ' . $v . '/', $title, $m) === 1) {
            $bumps[] = [$m[1], $m[2], $m[3]];
        }
        preg_match_all('/^Updates `([^`]+)` from ' . $v . ' to ' . $v . '/m', $body, $mm, PREG_SET_ORDER);
        foreach ($mm as $m) {
            $bumps[] = [$m[1], $m[2], $m[3]];
        }
        preg_match_all('/^\|\s*\[([^\]]+)\][^|]*\|.*?`' . $v . '`\s*->\s*`' . $v . '`/m', $body, $mm, PREG_SET_ORDER);
        foreach ($mm as $m) {
            $bumps[] = [$m[1], $m[2], $m[3]];
        }
        $out = [];
        foreach ($bumps as [$pkg, $from, $to]) {
            if (Version::majorLine($from) !== '' && Version::majorLine($from) !== Version::majorLine($to)) {
                $out["{$pkg} {$from} -> {$to}"] = true;
            }
        }
        return array_keys($out);
    }

    private static function rebaseCommand(string $author): string
    {
        return match (true) {
            stripos($author, 'dependabot') !== false => '@dependabot rebase',
            stripos($author, 'renovate') !== false   => '@renovatebot rebase',
            default                                  => '',
        };
    }

    // ── auto-fix ─────────────────────────────────────────────────────────────

    private function applyFixes(): void
    {
        $c = $this->console;
        if ($this->opt->autoFix === 'no') {
            $c->skip('auto-fix (disabled via --no-auto-fix)');
            return;
        }
        if (!is_file($this->vulnDb) || filesize($this->vulnDb) === 0) {
            $c->info('auto-fix: no vulnerability database yet');
            return;
        }
        $db      = $this->loadDb();
        $pending = VulnDb::countState($db, 'pending');
        if ($pending === 0) {
            $c->ok('auto-fix: nothing pending');
            return;
        }
        $plan       = FixPlanner::plan($db);
        $advisories = FixPlanner::advisories($db);
        $inScope = array_values(array_filter($plan, fn (array $row): bool => $this->target->inScope($row['manifest'])));
        // With --subdir, fixes for manifests elsewhere in the repository stay pending
        $scopeNote = $this->target->subdir === '' ? ''
            : ' (' . count($inScope) . ' of ' . count($plan) . " manifest/package fixes inside {$this->target->subdir})";
        // Check mode works out the same edits without writing them, so it can
        // say what update mode would do
        $write = $this->opt->mode === 'update';
        $c->info($write
            ? "auto-fix: applying {$pending} pending record(s) as " . count($plan) . " manifest/package fix(es) from {$this->vulnDb}{$scopeNote}"
            : "auto-fix: {$pending} pending record(s) as " . count($plan) . " manifest/package fix(es); check mode only works out what update mode would change{$scopeNote}");

        $lister  = $this->dirLister();
        $updates = [];
        $applied = $missing = $notDeclared = $satisfied = $unsupported = $major = $noValidFix = $edits = $majorRows = 0;
        $unplanned = FixPlanner::unplanned($db);
        $outside   = array_sum(array_map(static fn (array $row): int => count($row['keys']), $plan)) - array_sum(array_map(static fn (array $row): int => count($row['keys']), $inScope));
        // Pending but not fixable here: no fix released yet, nothing to edit,
        // or (with --subdir) a manifest elsewhere
        $rest = ' no-fix-yet=' . $unplanned['no-fix']
            . ($unplanned['unplaceable'] > 0 ? " unplaceable={$unplanned['unplaceable']}" : '')
            . ($this->target->subdir !== '' ? " outside-subdir={$outside}" : '');
        // Fixable in principle; written (or reported) after one more pass, so
        // one family cannot be pinned to two versions in one file
        $decisions = [];
        foreach ($inScope as $row) {
            // Tallied in records, so the buckets add up to what is pending
            $n      = count($row['keys']);
            $target = ManifestPaths::sourceManifestFor($row['manifest'], $lister);
            $via    = $target !== $row['manifest'] ? ' (via ' . basename($row['manifest']) . ')' : '';
            $abs    = $this->insideRoot($target);
            $eco    = ManifestPaths::ecosystemFor($target);
            $eco    = $eco !== 'unknown' ? $eco : $row['ecosystem'];
            $pkg    = $row['package'];
            $state  = 'pending';

            if ($abs === null) {
                $missing += $n;
                [$state, $note] = ['skipped', "manifest not found: {$target}"];
            } else {
                $content  = (string)file_get_contents($abs);
                $declared = ManifestEditor::declared($eco, $target, $content, $pkg);
                $pin      = $row['pkg_max'];
                $current  = $declared;
                $locked   = $declared === '' && $eco === 'npm' ? Lockfile::versions(dirname($abs), 'npm', $pkg) : null;
                // Transitive: what matters is what the lockfile resolved. With
                // no lockfile, the versions the issues found in use stand in,
                // so an override or <dependencyManagement> pin stays on the
                // line in use and --allow-major governs it like any bump
                $inUse = $locked !== null && $locked !== [] ? $locked
                    : ($declared === '' && $locked === null && in_array($eco, ['npm', 'maven'], true) && $row['installed'] !== [] ? $row['installed'] : null);
                $where = $locked !== null && $locked !== [] ? 'locked at' : 'found in use at';
                if ($inUse !== null) {
                    $lines = array_values(array_unique(array_map([Version::class, 'majorLine'], $inUse)));
                    if (array_filter($inUse, static fn (string $v): bool => !Version::clearsAll($v, $row['spec'])) === []) {
                        $ver = '';
                    } elseif (count($lines) > 1) {
                        // A package-wide pin would force every copy onto one line
                        $ver = null;
                    } else {
                        // From the newest copy, so the pin moves none of them back
                        $current = Version::max($inUse);
                        $ver     = $pin = Version::chooseTarget($current, $row['spec']) ?: $current;
                    }
                } else {
                    $ver = Version::chooseTarget($declared, $row['spec'], $pin);
                }
                // A Maven prerelease above every fix (netty 5.0.0.Alpha2,
                // spring 7.1.0-M2, both put there by versions:use-latest-*)
                // goes back to the newest release with the fix: off a
                // prerelease, a lower release is no downgrade that matters
                $release = $ver !== null && $eco === 'maven' ? Version::releaseForPrerelease($current, $row['spec']) : '';
                if ($release !== '') {
                    $ver = $pin = $release;
                    $c->info("  {$eco} {$pkg} is on prerelease {$current} in {$target}, above every fix; moving it to release {$release}");
                }

                if ($eco === 'npm' && preg_match(NodeWorkspace::PROTOCOL_RX, $declared) === 1) {
                    // A workspace link to a sibling package or the root's
                    // catalog, not an upstream dependency: there is no
                    // registry version here to bump, and "cannot edit" is
                    // for edits that genuinely failed
                    $notDeclared += $n;
                    [$state, $note] = ['skipped', "{$pkg} in {$target} is linked as {$declared} (a workspace specifier, not an upstream dependency)"];
                } elseif ($locked === []) {
                    // The lockfile is what gets installed, and it holds no
                    // copy: an override would add a pin that fixes nothing
                    $notDeclared += $n;
                    [$state, $note] = ['skipped', "{$pkg} is neither declared in {$target} nor in its lockfile"];
                } elseif ($ver === null) {
                    $unsupported += $n;
                    $note = "{$pkg} is {$where} " . implode(', ', $inUse) . " in several major versions; pin it by hand";
                } elseif ($release === '' && Version::prereleaseAboveFixes($current, $row['spec'])) {
                    // No fix is above it, and no single release clears every
                    // advisory to go back to
                    $unsupported += $n;
                    $fixes = Version::sortAscending(array_values(array_unique(array_merge(...array_values($row['spec'])))));
                    $note  = "{$pkg} is " . ($inUse !== null ? $where : 'declared as') . " prerelease {$current} in {$target}, which sorts above"
                        . ' every fix (' . implode(', ', $fixes) . ') without being known to include one; move it to a release by hand';
                    $c->warn("  {$eco} {$pkg} is on prerelease {$current} in {$target}, above every fix; move it to a release by hand");
                } elseif ($ver === '') {
                    // Every advisory for this package is already cleared
                    $satisfied += $n;
                    $state = 'applied';
                    $note  = match (true) {
                        $locked !== null => "already satisfied: the lockfile resolves {$pkg} to " . implode(', ', $locked),
                        $inUse !== null  => "already satisfied: {$pkg} was found in use at " . implode(', ', $inUse),
                        default          => "already satisfied: {$target} declares {$declared}",
                    };
                } elseif ($release === '' && !$this->opt->allowMajor && Version::floor($current) !== '' && Version::majorLine($current) !== Version::majorLine($ver)) {
                    // Left pending: --allow-major on a later run applies it
                    $major += $n;
                    $majorRows++;
                    $note = "needs a major upgrade: {$pkg} {$current} -> {$ver} in {$target} (rerun with --allow-major)";
                    $c->warn("  {$eco} {$pkg} needs a major upgrade ({$current} -> {$ver}) in {$target}; not applied without --allow-major");
                } else {
                    // The last gate before any manifest write: the target must
                    // exist in its registry, must not be a version this
                    // database itself knows is vulnerable for this exact
                    // coordinate, and must not move the package backwards.
                    $choice = $this->guardTarget($eco, $pkg, (string)$current, (string)$ver, dirname($abs), $row['spec'], $advisories, $release !== '');
                    if ($choice['version'] === '') {
                        // The no-fix-yet shape of a bad candidate: the record
                        // stays pending, so a registry that gains a real fix
                        // is picked up by a later run
                        $noValidFix += $n;
                        $c->warn("  {$eco} {$pkg}@{$ver} {$choice['why']}; nothing written to {$target}");
                        foreach ($row['keys'] as $key) {
                            $updates[] = ['key' => $key, 'state' => 'pending', 'note' => "no valid fix: {$choice['why']}"];
                        }
                        continue;
                    }
                    if ($choice['version'] !== $ver) {
                        $c->warn("  {$eco} {$pkg}@{$ver} {$choice['why']}; {$choice['version']} in its place");
                        $ver = $pin = $choice['version'];
                    }
                    $decisions[] = ['row' => $row, 'target' => $target, 'abs' => $abs, 'eco' => $eco, 'pkg' => $pkg,
                        'content' => $content, 'ver' => $ver, 'pin' => $pin, 'via' => $via, 'current' => (string)$current,
                        'declared' => (string)$declared, 'allowLower' => $release !== ''];
                    continue;
                }
            }
            foreach ($row['keys'] as $key) {
                $updates[] = ['key' => $key, 'state' => $state, 'note' => $note];
            }
        }

        // A second pass so one family (io.netty, org.springframework) cannot
        // be pinned to two versions in the same file by two records
        $this->alignFamilies($decisions, $advisories);
        foreach ($decisions as $d) {
            /** @var array{row: array<string, mixed>, target: string, abs: string, eco: string, pkg: string, content: string, ver: string, pin: string, via: string, current: string, declared: string, allowLower: bool} $d */
            $row  = $d['row'];
            $n    = count($row['keys']);
            $note = '';
            $state = 'skipped';
            // Two fixes can share one manifest: apply to what the file says
            // now, not to the snapshot taken before the first of them was
            // written, or the earlier edit is silently undone
            $live  = (string)@file_get_contents($d['abs']);
            $base  = $live === '' ? (string)$d['content'] : $live;
            $res   = ManifestEditor::apply(
                $d['eco'],
                $d['target'],
                $base,
                $d['pkg'],
                $d['ver'],
                $d['pin'] !== '' ? $d['pin'] : $d['ver'],
                is_file(dirname($d['abs']) . '/yarn.lock'),
                is_file(dirname($d['abs']) . '/package-lock.json') || is_file(dirname($d['abs']) . '/npm-shrinkwrap.json'),
                $d['allowLower']
            );
            if ($res['status'] === ManifestEditor::REFUSED) {
                $notDeclared += $n;
                $note = "refused: {$d['ver']} would downgrade the version declared in {$d['target']}";
            } elseif ($res['status'] === ManifestEditor::UNSUPPORTED) {
                $unsupported += $n;
                $state = 'pending';
                $note  = 'cannot edit ' . $d['pkg'] . ($d['declared'] !== '' ? " (declared as {$d['declared']})" : '') . " in {$d['target']}";
            } elseif ($res['status'] === ManifestEditor::INTERNAL) {
                // belt and braces: a workspace link reached the editor
                $notDeclared += $n;
                $note = "{$d['pkg']} in {$d['target']} is linked as {$d['declared']} (a workspace specifier, not an upstream dependency)";
            } elseif ($res['content'] !== $base && !$write) {
                $applied += $n;
                $edits++;
                $state = 'pending';
                $note  = "would set {$d['ver']} in {$d['target']}";
                $c->info("  would set {$d['eco']} {$d['pkg']} -> {$d['ver']} in {$d['target']}{$d['via']}");
            } elseif ($res['content'] !== $base && file_put_contents($d['abs'], $res['content']) !== false) {
                $applied += $n;
                $edits++;
                $state = 'applied';
                $note  = "set to {$d['ver']} in {$d['target']}";
                $c->ok("  {$d['eco']} {$d['pkg']} -> {$d['ver']} in {$d['target']}{$d['via']}");
                $this->appliedFixes[] = "{$d['eco']} {$d['pkg']} -> {$d['ver']} in {$d['target']}";
            } else {
                $notDeclared += $n;
                $note = 'package not declared in ' . $d['target'];
            }
            foreach ($row['keys'] as $key) {
                $updates[] = ['key' => $key, 'state' => $state, 'note' => $note];
            }
        }

        $this->needsMajor = $majorRows;
        $bad              = $noValidFix > 0 ? " no-valid-fix={$noValidFix}" : '';
        if (!$write) {
            $this->readyFixes = $edits;
            $c->info("auto-fix (check mode, in records): would-apply={$applied} already-ok={$satisfied} not-declared={$notDeclared}"
                . " missing-manifest={$missing} cannot-edit={$unsupported} needs-major={$major}{$bad}{$rest}"
                . ". {$edits} manifest edit(s); use --update to apply.");
            return;
        }
        $this->saveDb(VulnDb::applyStates($db, $updates, $this->now));

        $c->info("auto-fix (in records): applied={$applied} already-ok={$satisfied} not-declared={$notDeclared} missing-manifest={$missing}"
            . " cannot-edit={$unsupported} needs-major={$major}{$bad}{$rest}; {$edits} manifest edit(s)");
        if ($edits > 0) {
            $this->record('auto-fix', 'PASS', 0, 0, "{$edits} edit(s)");
            if (!$this->opt->push) {
                $c->warn("Manifests were modified in {$this->root} — review 'git diff' before committing");
            }
        } else {
            $this->record('auto-fix', 'SKIP');
        }
    }

    /**
     * The last gate before any manifest write. The target version must exist
     * in its registry, must not sit inside an affected range the database
     * knows for this exact coordinate, and must not compare below what the
     * manifest declares - unless it is the deliberate prerelease-to-release
     * channel, which may. FixPlanner::safeTarget() walks down to the next
     * valid candidate; '' version means write nothing.
     *
     * @param array<string, list<string>> $spec
     * @param array<string, array<string, array{fixes: list<string>, ranges: list<string>}>> $advisories
     * @return array{version: string, why: string}
     */
    private function guardTarget(
        string $eco,
        string $pkg,
        string $current,
        string $ver,
        string $dir,
        array $spec,
        array $advisories,
        bool $allowLower
    ): array {
        // Gradle and sbt coordinates are Maven coordinates: same Central
        // layout, same records (GitHub files them as "Maven")
        if ($eco === 'gradle' || $eco === 'sbt') {
            $eco = 'maven';
        }
        $known    = $advisories[$eco . '|' . $pkg] ?? [];
        $registry = $this->publishedVersionsFor($eco, $pkg, $dir);
        $exists   = $registry === null ? null : static fn (string $v): bool => in_array($v, $registry, true);
        return FixPlanner::safeTarget($eco, $current, $ver, $spec, $known, $registry, $exists, $allowLower, $this->opt->allowMajor);
    }

    /**
     * The versions the registry publishes for a package, or null when nobody
     * can say: an unanswered check never blocks a fix, and only the three
     * registries with published version lists are asked. npm is asked through
     * the project's own npm first (a private registry is authoritative where
     * registry.npmjs.org is not); the plain HTTP answer covers the hosts
     * without a working npm, where the old check failed open and lodash
     * 4.18.0 - a version that exists nowhere - reached a manifest.
     *
     * @return list<string>|null
     */
    private function publishedVersionsFor(string $eco, string $pkg, string $dir): ?array
    {
        if ($eco === 'npm') {
            if (ProcessRunner::has('npm')) {
                if (!array_key_exists($pkg, $this->npmVersions)) {
                    $this->npmVersions[$pkg] = NodeAuditor::registryVersions($this->ctx->runner, $dir, $pkg);
                }
                if ($this->npmVersions[$pkg] !== null) {
                    return $this->npmVersions[$pkg];
                }
            }
            return $this->registry->versions('npm', $pkg);
        }
        return $this->registry->versions($eco, $pkg);
    }

    /**
     * Where two records each pinned a netty or spring artifact in one pom,
     * the file ends up holding the family at two versions (4.1.133 beside
     * 4.1.94). These artifacts ship together; raise the lower pins to the
     * highest candidate that every one of them can bear - same guards, and
     * any artifact that refuses the join keeps its own version with a note.
     *
     * @param list<array<string, mixed>> $decisions
     * @param array<string, array<string, array{fixes: list<string>, ranges: list<string>}>> $advisories
     */
    private function alignFamilies(array &$decisions, array $advisories): void
    {
        $c    = $this->console;
        $sets = [];
        foreach ($decisions as $i => $d) {
            if ($d['eco'] !== 'maven' || !str_contains($d['pkg'], ':')) {
                continue;
            }
            $group = explode(':', $d['pkg'], 2)[0];
            if (!str_starts_with($group, 'io.netty') && !str_starts_with($group, 'org.springframework')) {
                continue;
            }
            $sets[$d['target'] . "\0" . $group . "\0" . Version::majorLine($d['ver'])][] = $i;
        }
        foreach ($sets as $members) {
            if (count($members) < 2) {
                continue;
            }
            $best = Version::maxMaven(array_map(static fn (int $i): string => (string)$decisions[$i]['ver'], $members));
            foreach ($members as $i) {
                $d = $decisions[$i];
                if ($d['ver'] === $best) {
                    continue;
                }
                $choice = $this->guardTarget((string)$d['eco'], (string)$d['pkg'], (string)$d['current'],
                    $best, dirname((string)$d['abs']), $d['row']['spec'], $advisories, false);
                if ($choice['version'] === $best) {
                    $c->info("  maven {$d['pkg']}: joining the {$this->groupId($d['pkg'])} family at {$best}");
                    $decisions[$i]['ver'] = $decisions[$i]['pin'] = $best;
                } else {
                    $c->warn("  maven {$d['pkg']} stays at {$d['ver']}; {$best} {$choice['why']} for it");
                }
            }
        }
    }

    private function groupId(string $pkg): string
    {
        return str_contains($pkg, ':') ? explode(':', $pkg, 2)[0] : $pkg;
    }

    // ── close-fixed ──────────────────────────────────────────────────────────

    /**
     * Close security issues whose every remediation record is satisfied by
     * what the manifests declare right now. Anything unverifiable stays open:
     * under-closing is recoverable, closing a live vulnerability is not.
     */
    private function closeFixedIssues(): void
    {
        $c = $this->console;
        if (!$this->opt->closeFixed) {
            return;
        }
        if ($this->target->githubRepo === '') {
            $c->skip('close-fixed (no GitHub repository)');
            return;
        }
        if (!$this->githubReady()) {
            $c->skip('close-fixed (GitHub unavailable)');
            return;
        }
        if (!is_file($this->vulnDb) || filesize($this->vulnDb) === 0) {
            $c->info('close-fixed: no vulnerability database');
            return;
        }
        $repo   = $this->repo();
        $update = $this->opt->mode === 'update';
        if ($update && $this->landed === false) {
            // The fixes are on a side branch or an unmerged pull request, not
            // on the branch the issues are judged against
            $c->info("close-fixed: this run's changes have not reached the base branch; only listing what would close");
            $update = false;
        } elseif ($update && $this->landed === null && (new BranchPublisher($this->ctx->runner, $c, $this->root))->isClean() === false) {
            // Uncommitted edits are not a fix yet, and a clone's are deleted
            // with it
            $c->info('close-fixed: the tree has uncommitted changes; only listing what would close'
                . ' (commit and push them, or use --push-direct or --pr)');
            $update = false;
        }

        // The repo's existing "security fix" label means a Mend-generated fix
        // PR, so a dedicated marker label is used
        $labelOk = false;
        $label   = $this->opt->closeLabel;
        if ($label !== '') {
            $labels = $this->gh()->json(['label', 'list', '--repo', $repo, '--limit', '200', '--json', 'name'], 60);
            if (is_array($labels) && in_array($label, array_column($labels, 'name'), true)) {
                $labelOk = true;
            } elseif ($update && $this->gh()->run(['label', 'create', $label, '--repo', $repo, '--color', '0E8A16',
                '--description', 'Vulnerability verified resolved in the manifests'], 60)->ok()) {
                $c->ok("created label '{$label}'");
                $labelOk = true;
            } else {
                $c->warn("label '{$label}' unavailable; issues will be closed without it");
            }
        }

        $byIssue = FixPlanner::issueRequirements($this->loadDb());
        // The database keeps refs forever and most are long closed; only
        // consider issues that are actually open, so a run does not burn the
        // content-creation quota on failures
        $open = $this->openIssueNumbers;
        if ($open === null) {
            $rows = $this->gh()->openIssues($repo, 0, false, $complete);
            $open = $rows !== null && $complete ? array_map(static fn (array $i): int => (int)$i['number'], $rows) : null;
        }
        if ($open === null) {
            // Working through every ref ever recorded would re-close closed
            // issues and spend the content-creation quota doing it
            $c->warn('close-fixed: could not list open issues; skipped');
            $this->record('close-fixed', 'SKIP');
            return;
        }
        $openSet = array_flip($open);
        $c->info('close-fixed: ' . count($openSet) . ' issues open, ' . count($byIssue) . ' in the database');
        $byIssue = array_intersect_key($byIssue, $openSet);
        $c->info('close-fixed: checking ' . count($byIssue) . ' issue(s) against the current manifests');

        $branch = 'master';
        $r = $this->ctx->runner->run(['git', '-C', $this->root, 'rev-parse', '--abbrev-ref', 'HEAD'], $this->root, ['timeout' => 30, 'label' => 'git']);
        if ($r->ok() && trim($r->stdout) !== '') {
            $branch = trim($r->stdout);
        }

        $verifier = new IssueVerifier(
            $this->root,
            $this->dirLister(),
            fn (string $m): bool => $this->target->inScope($m),
            $this->target->subdir,
            $this->removedIn(...)
        );
        $closed = $unresolved = $unverifiable = $rateLimited = $outOfScope = 0;
        $whyUnverifiable = [];
        foreach ($byIssue as $ref => $needs) {
            ['ok' => $ok, 'reason' => $reason, 'detail' => $detail, 'evidence' => $evidence] = $verifier->verify($needs);
            if (!$ok) {
                match ($reason) {
                    'unresolved'   => $unresolved++,
                    'out-of-scope' => $outOfScope++,
                    default        => $unverifiable++,
                };
                if ($reason === 'unverifiable') {
                    $why = match (true) {
                        str_contains($detail, 'no fixed version') => 'no fix known',
                        str_contains($detail, 'manifest missing') => 'manifest missing',
                        str_contains($detail, 'nor in its lockfile') => 'not declared or locked',
                        default => 'transitive, no lockfile',
                    };
                    $whyUnverifiable[$why] = ($whyUnverifiable[$why] ?? 0) + 1;
                }
                if ($this->opt->debug) {
                    $c->info("  #{$ref} " . ($reason === 'unresolved' ? 'still open' : $reason) . ": {$detail}");
                }
                continue;
            }
            if (!$update) {
                $c->info("  would close #{$ref} (all fixes verified)");
                $this->wouldClose++;
                continue;
            }
            // Label first, so the marker survives even if the close fails
            if ($labelOk) {
                $this->gh()->run(['issue', 'edit', (string)$ref, '--repo', $repo, '--add-label', $label], 60);
            }
            // GitHub applies a secondary limit to content-creating calls
            // (~80/minute, ~500/hour) separate from the REST quota: pace the
            // loop and back off hard when told "submitted too quickly"
            if ($closed > 0 && $this->opt->closeDelay > 0) {
                sleep($this->opt->closeDelay);
            }
            $body = "### Resolved — verified against the current manifests\n\n"
                . "Every package this issue reports now declares a version at or above the required fix on `{$branch}`"
                . (str_contains($evidence, '**manifest removed**') ? ', or the project that used it has been removed' : '') . ":\n\n"
                . "| Package | Required | Declared | Manifest |\n| --- | --- | --- | --- |\n{$evidence}\n"
                . 'Checked by [dep-sec-patcher](https://github.com/detain/dep-sec-patcher) `--close-fixed`, which reads the version each manifest'
                . " declares rather than assuming an earlier fix succeeded. Reopen if this is wrong.\n\n"
                . '<!-- security-update:closed-verified -->';
            for ($attempt = 1; ; $attempt++) {
                $res = $this->gh()->run(['issue', 'close', (string)$ref, '--repo', $repo, '--reason', 'completed', '--comment', $body], 120);
                if ($res->ok()) {
                    $c->ok("  closed #{$ref} (all fixes verified)");
                    $closed++;
                    break;
                }
                if (preg_match('/submitted too quickly|rate limit|abuse|secondary/i', $res->output) === 1) {
                    if ($attempt >= 4) {
                        $c->fail("  gave up on #{$ref} after {$attempt} attempts (rate limited)");
                        $rateLimited++;
                        break;
                    }
                    $wait = $attempt * $attempt * 60;
                    $c->warn("  rate limited on #{$ref}, waiting {$wait}s (attempt {$attempt}/4)");
                    sleep($wait);
                    continue;
                }
                $c->fail("  could not close #{$ref}: " . substr(str_replace("\n", ' ', $res->output), 0, 160));
                break;
            }
            // Stop cleanly at the cap so a run stays inside the hourly quota
            if ($this->opt->closeLimit > 0 && $closed >= $this->opt->closeLimit) {
                $c->info("close-fixed: reached --close-limit {$this->opt->closeLimit}; re-run to continue");
                break;
            }
        }
        // A listing run closed nothing, and must not say it did
        $tally = $update ? "closed={$closed}" : "would-close={$this->wouldClose}";
        arsort($whyUnverifiable);
        $c->info("close-fixed: {$tally} still-vulnerable={$unresolved} unverifiable={$unverifiable} rate-limited={$rateLimited}"
            . ($this->target->subdir !== '' ? " outside-subdir={$outOfScope}" : '')
            . ($whyUnverifiable !== [] ? ' (unverifiable: ' . implode(', ', array_map(static fn ($k, $n) => "{$n} {$k}", array_keys($whyUnverifiable), $whyUnverifiable)) . ')' : ''));
        $this->record('close-fixed', 'PASS', 0, 0, $update ? "closed {$closed}" : "would close {$this->wouldClose} (not closed)");
    }

    // ── --push / --pr / --push-direct ────────────────────────────────────────

    private function publishChanges(?BranchPublisher $publisher, ?bool $cleanAtStart, string $startBranch): void
    {
        $c = $this->console;
        if (!$this->opt->push) {
            return;
        }
        if ($this->opt->mode !== 'update' || $publisher === null) {
            $c->info('push: --check mode, nothing to push');
            return;
        }
        // Until this run's changes are known to be on the base branch,
        // close-fixed must not close anything on the strength of them
        $this->landed = false;
        if ($cleanAtStart === null) {
            $c->skip("push ({$this->root} is not the top of a git work tree)");
            return;
        }
        // Paths that were dirty before the run and that it changed too are
        // left uncommitted, so the base branch does not have all the fixes
        $plan     = $publisher->plan();
        $complete = $plan !== null && $plan['conflicted'] === [];
        if (!$publisher->hasChanges()) {
            // The base branch already is what the manifests say
            $this->landed = $complete;
            $this->record('push', $complete ? 'SKIP' : 'WARN');
            return;
        }

        $files   = $plan['commit'] ?? $publisher->changedFiles();
        $title   = 'Dependency security updates';
        $message = $title . "\n\n" . $this->changeSummary($files, false);
        $branch  = $this->opt->branch !== '' ? $this->opt->branch : BranchPublisher::defaultBranch($this->now);

        if ($this->opt->pushMode === 'direct') {
            $result = $publisher->publishDirect($message, $branch);
            $this->landed = $result === 'pushed' && $complete;
            $this->record('push', $result === 'pushed' ? 'PASS' : 'FAIL');
            return;
        }

        $base = $startBranch;
        if ($base === '' && $this->opt->pushMode === 'pr' && $this->githubReady()) {
            $info = $this->gh()->json(['repo', 'view', $this->repo(), '--json', 'defaultBranchRef'], 60);
            $base = (string)($info['defaultBranchRef']['name'] ?? '');
        }
        if (!$publisher->publish($branch, $message, $base)) {
            $this->record('push', 'FAIL');
            return;
        }
        if ($this->opt->pushMode !== 'pr') {
            if ($this->target->githubRepo !== '') {
                $c->info("open a pull request: gh pr create --repo {$this->target->githubRepo} --head {$branch} --fill");
            }
            $this->record('push', 'PASS');
            return;
        }
        $this->record('push', $this->openPullRequest($publisher, $branch, $base, $title, $files) ? 'PASS' : 'FAIL');
        if (!$complete) {
            $this->landed = false;
        }
    }

    /**
     * --pr: open a pull request from the pushed $branch into $base, then
     * merge it and delete the branch, unless --pr-merge none.
     *
     * @param list<string> $files
     * @return bool false when the pull request could not be opened, or merging it failed
     */
    private function openPullRequest(BranchPublisher $publisher, string $branch, string $base, string $title, array $files): bool
    {
        $c = $this->console;
        if ($this->target->githubRepo === '' || !$this->githubReady()) {
            $c->fail("push: --pr needs gh and a GitHub repository; open a pull request for {$branch} by hand");
            return false;
        }
        if ($base === '') {
            $c->fail("push: could not tell which branch to open the pull request against; open one for {$branch} by hand");
            return false;
        }
        $repo = $this->repo();
        $body = "## {$title}\n\n" . $this->changeSummary($files, true) . "\n<!-- dep-sec-patcher:pr -->";
        $r    = $this->gh()->run(['pr', 'create', '--repo', $repo, '--base', $base, '--head', $branch,
            '--title', $title, '--body', $body], 120);
        if (!$r->ok() || preg_match('#/pull/(\d+)#', $r->stdout, $m) !== 1) {
            $c->fail("push: could not open a pull request for {$branch} (" . $r->failureReason() . ')');
            foreach ($r->tail(4) as $line) {
                $c->detail('| ' . $line);
            }
            return false;
        }
        $num = $m[1];
        $url = trim($r->stdout);
        $c->ok("push: opened pull request #{$num} {$url}");
        if ($this->opt->prMerge === 'none') {
            $c->info("push: leaving #{$num} open for review (--pr-merge none)");
            return true;
        }

        [$mergeable] = $this->mergeState($repo, $num);
        if ($mergeable === 'CONFLICTING') {
            $c->fail("push: pull request #{$num} conflicts with {$base}; left open");
            return false;
        }
        $method = '--' . $this->opt->prMerge;
        $merge  = $this->gh()->run(['pr', 'merge', $num, '--repo', $repo, $method, '--delete-branch'], 300);
        if ($merge->ok()) {
            $c->ok("push: merged pull request #{$num} into {$base} and deleted {$branch}");
            $publisher->deleteLocalBranch($branch);
            if ($publisher->currentBranch() === $base) {
                $publisher->syncWithOrigin($base);
            }
            $this->landed = true;
            return true;
        }
        $auto = $this->gh()->run(['pr', 'merge', $num, '--repo', $repo, $method, '--auto', '--delete-branch'], 120);
        if ($auto->ok()) {
            $c->ok("push: enabled auto-merge on pull request #{$num}; it merges once the required checks pass");
            return true;
        }
        $c->fail("push: could not merge pull request #{$num}; left open (" . $merge->failureReason() . ')');
        foreach ($merge->tail(4) as $line) {
            $c->detail('| ' . $line);
        }
        return false;
    }

    /**
     * What the run changed, for the commit message and the pull request.
     *
     * @param list<string> $files
     */
    private function changeSummary(array $files, bool $markdown): string
    {
        $text = ($markdown ? 'Automated run of [dep-sec-patcher](https://github.com/detain/dep-sec-patcher) ' : 'Updated by dep-sec-patcher ')
            . Application::VERSION . " in update mode on {$this->now}"
            . ($this->target->subdir !== '' ? " (scope: {$this->target->subdir})" : '') . ".\n";
        if ($this->appliedFixes !== []) {
            $text .= "\n" . ($markdown ? '### ' : '') . 'Fixes applied from the vulnerability database' . ($markdown ? '' : ':') . "\n\n";
            foreach (array_slice($this->appliedFixes, 0, 200) as $fix) {
                $text .= "- {$fix}\n";
            }
            if (count($this->appliedFixes) > 200) {
                $text .= '- ... and ' . (count($this->appliedFixes) - 200) . " more\n";
            }
        }
        if ($files !== []) {
            $text .= "\n" . ($markdown ? '### ' : '') . 'Files changed' . ($markdown ? '' : ':') . "\n\n";
            foreach (array_slice($files, 0, 200) as $file) {
                $text .= $markdown ? "- `{$file}`\n" : "- {$file}\n";
            }
            if (count($files) > 200) {
                $text .= '- ... and ' . (count($files) - 200) . " more\n";
            }
        }
        return $text;
    }

    // ── summary & report ─────────────────────────────────────────────────────

    /**
     * When the run found fixes it did not apply or publish, say so and print
     * the command that would, built from the one that was run.
     */
    private function nextSteps(): void
    {
        $c       = $this->console;
        $reasons = [];
        $add     = [];
        $check   = $this->opt->mode === 'check';
        $git     = $this->target->remote || file_exists($this->root . '/.git');
        $changed = false;

        if ($check) {
            $vulns = 0;
            foreach ($this->summary as $key => $row) {
                if (in_array($key, Options::ECOSYSTEMS, true) && $row['status'] === 'FAIL') {
                    $vulns += $row['vulns'];
                }
            }
            if ($vulns > 0) {
                $reasons[] = "the audits found {$vulns} vulnerabilities; update mode updates the dependencies and audits again";
            }
            if ($this->readyFixes > 0) {
                $reasons[] = "{$this->readyFixes} fix(es) from GitHub's alerts and issues would be written into the manifests";
            }
            if ($this->mergeablePrs > 0) {
                $reasons[] = "{$this->mergeablePrs} dependency-bot pull request(s) can be merged";
            }
        } elseif (!$this->opt->push && $git && $this->cleanAtStart === true
            && (new BranchPublisher($this->ctx->runner, $c, $this->root))->isClean() === false) {
            $changed   = true;
            $reasons[] = "this run's changes are only in {$this->root}" . match (true) {
                !$this->target->remote => ', uncommitted',
                $this->opt->keepClone  => ', a clone the next run resets',
                default                => ', a clone that is deleted when this run ends (--keep-clone keeps it)',
            };
        }
        if ($this->wouldClose > 0) {
            $reasons[] = "{$this->wouldClose} issue(s) can be closed once the fixes are on the base branch";
        }
        if ($this->needsMajor > 0 && !$this->opt->allowMajor) {
            $reasons[]  = "{$this->needsMajor} fix(es) or bot pull request(s) need a major version upgrade, which may break the code that uses them";
            $add[]      = '--allow-major';
        }
        if (!$this->opt->closeFixed && $this->openIssueRecords > 0 && $this->target->githubRepo !== '') {
            $reasons[] = 'security issues are recorded; --close-fixed closes the ones the manifests prove fixed';
            $add[]     = '--close-fixed';
        }
        if ($reasons === []) {
            return;
        }

        $c->line();
        $c->heading('Next steps');
        foreach ($reasons as $reason) {
            $c->info($reason);
        }
        if (($check || $changed || !$this->opt->push) && $git && $this->target->githubRepo !== '') {
            $base = $this->target->remote ? 'the default branch' : 'the checked-out branch';
            $c->line('  Apply the fixes, commit them, open a pull request and merge it:');
            $c->line('    ' . NextSteps::command($this->argv, array_merge(['--update', '--pr'], $add)));
            $c->line("  Or commit straight to {$base}:");
            $c->line('    ' . NextSteps::command($this->argv, array_merge(['--update', '--push-direct'], $add)));
            $c->line('  Or push a branch for review only:');
            $c->line('    ' . NextSteps::command($this->argv, array_merge(['--update', '--push'], $add)));
        } elseif ($check || !$this->opt->push) {
            $c->line('  Apply the fixes:');
            $c->line('    ' . NextSteps::command($this->argv, array_merge(['--update'], $add)));
        } elseif ($add !== []) {
            $c->line('  Run again with:');
            $c->line('    ' . NextSteps::command($this->argv, $add, false));
        }
    }

    /**
     * $note is for what is neither a vulnerability nor an outdated package
     * (issues closed, fixes applied), so it is not counted as either.
     */
    private function record(string $key, string $status, int $vulns = 0, int $outdated = 0, string $note = ''): void
    {
        $prev = $this->summary[$key] ?? null;
        if ($prev === null) {
            $this->summary[$key] = ['status' => $status, 'vulns' => $vulns, 'outdated' => $outdated, 'note' => $note];
            return;
        }
        if ($note !== '') {
            $prev['note'] = $note;
        }
        // Several targets per ecosystem: worst status wins, counts add up.
        // (The original shell script overwrote, so the table showed the last pom only.)
        if ((self::STATUS_RANK[$status] ?? 0) > (self::STATUS_RANK[$prev['status']] ?? 0)) {
            $prev['status'] = $status;
        }
        $prev['vulns']    += $vulns;
        $prev['outdated'] += $outdated;
        $this->summary[$key] = $prev;
    }

    private function printSummary(): void
    {
        $c = $this->console;
        $c->line();
        $c->heading('Summary');
        $c->line("  PASS={$c->pass}  FAIL={$c->fail}  WARN={$c->warn}  SKIP={$c->skip}  INFO={$c->info}");
        $c->line();
        $c->line($c->blue() . rtrim(sprintf('%-17s %-8s %-16s %-10s %s', 'Ecosystem', 'Status', 'Vulnerabilities', 'Outdated', 'Notes')) . $c->reset());
        $c->line($c->blue() . str_repeat('─', 60) . $c->reset());
        foreach ($this->summary as $key => $row) {
            $c->line($c->colorFor($row['status']) . self::summaryLine($key, $row) . $c->reset());
        }
        $c->line('done');
    }

    /**
     * @param array{status: string, vulns: int, outdated: int, note: string} $row
     */
    private static function summaryLine(string $key, array $row): string
    {
        return rtrim(sprintf('%-17s %-8s %-16d %-10d %s', $key, $row['status'], $row['vulns'], $row['outdated'], $row['note']));
    }

    private function writeReport(): void
    {
        $ecosystems = [];
        foreach ($this->summary as $key => $row) {
            $ecosystems[$key] = [
                'status'            => $row['status'],
                'vulnerabilities'   => $row['vulns'],
                'outdated_packages' => $row['outdated'],
                'last_scan'         => $this->now,
            ] + ($row['note'] !== '' ? ['note' => $row['note']] : []);
        }
        $report = [
            'tool'           => 'dep-sec-patcher ' . Application::VERSION,
            'scan_timestamp' => $this->now,
            'root_dir'       => $this->root,
            'subdir'         => $this->target->subdir,
            'target'         => $this->target->remote ? GitUrl::redact($this->target->url) : $this->root,
            'github_repo'    => $this->target->githubRepo,
            'mode'           => $this->opt->mode,
            'cvss_threshold' => (float)$this->opt->cvssThreshold,
            'summary'        => [
                'pass' => $this->console->pass,
                'fail' => $this->console->fail,
                'warn' => $this->console->warn,
                'skip' => $this->console->skip,
                'info' => $this->console->info,
            ],
            'ecosystems'     => $ecosystems === [] ? new \stdClass() : $ecosystems,
            'tools'          => [
                'trivy'  => ['enabled' => $this->opt->trivy !== 'no'],
                'gosec'  => ['enabled' => $this->opt->gosec !== 'no'],
                'bandit' => ['enabled' => $this->opt->bandit !== 'no'],
                'grype'  => ['enabled' => $this->opt->trivy !== 'no' && $this->opt->grype !== 'no'],
                'netsec' => ['enabled' => $this->opt->netsec !== 'no'],
            ],
        ];
        $file = $this->reportDir . '/security-scan-report.json';
        if (@file_put_contents($file, JsonFile::encode($report)) !== false) {
            $this->console->info("JSON report generated: {$file}");
        } else {
            $this->console->warn("could not write {$file}");
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /**
     * @return array<string, mixed>
     */
    private function loadDb(): array
    {
        $corrupt = false;
        $db      = VulnDb::load($this->vulnDb, $corrupt);
        if ($corrupt) {
            $this->console->warn("vuln DB was corrupt, reinitialising: {$this->vulnDb}");
        }
        return $db;
    }

    /**
     * @param array<string, mixed> $db
     */
    private function saveDb(array $db): bool
    {
        try {
            VulnDb::save($this->vulnDb, $db);
            return true;
        } catch (RuntimeException $e) {
            $this->console->warn("failed to update vuln DB: {$this->vulnDb} ({$e->getMessage()})");
            return false;
        }
    }

    /**
     * Absolute path of a manifest named by a record, or null when it does not
     * exist or resolves (through "..", or a symlink) outside the tree.
     */
    private function insideRoot(string $rel): ?string
    {
        $real = realpath($this->root . '/' . $rel);
        $root = realpath($this->root);
        if ($real === false || $root === false || !is_file($real) || !str_starts_with($real, rtrim($root, '/') . '/')) {
            return null;
        }
        return $real;
    }

    /**
     * The commit on HEAD's history that deleted a manifest HEAD no longer
     * has, or null. Without that history (a shallow clone) the answer is
     * null, which leaves the issue unverifiable rather than closed.
     */
    private function removedIn(string $rel): ?string
    {
        $opt = ['timeout' => 60, 'label' => 'git'];
        if ($this->ctx->runner->run(['git', '-C', $this->root, 'cat-file', '-e', "HEAD:{$rel}"], $this->root, $opt)->ok()) {
            return null;
        }
        $r   = $this->ctx->runner->run(['git', '-C', $this->root, 'log', '-1', '--diff-filter=D', '--format=%H', 'HEAD', '--', $rel], $this->root, $opt);
        $sha = trim($r->stdout);
        return $r->ok() && preg_match('/^[0-9a-f]{40,64}$/', $sha) === 1 ? $sha : null;
    }

    private function dirLister(): callable
    {
        $root = $this->root;
        return static function (string $dir) use ($root): array {
            $entries = @scandir($dir === '' ? $root : $root . '/' . $dir);
            return $entries === false ? [] : array_values(array_diff($entries, ['.', '..']));
        };
    }
}
