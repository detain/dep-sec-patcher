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

    /** @var array<string, array{status: string, vulns: int, outdated: int}> */
    private array $summary = [];
    private string $now;
    private ?GitHub $gh = null;
    private Context $ctx;
    private string $root;
    /** @var list<string> manifest edits made by auto-fix, for the commit message */
    private array $appliedFixes = [];
    /** Whether this run's changes reached the base branch on origin; null when not pushing. */
    private ?bool $landed = null;
    /** Whether the git tree was clean before the run; null outside a work tree. */
    private ?bool $cleanAtStart = null;
    /** What the run found but left undone, for the closing "Next steps". */
    private int $readyFixes = 0;
    private int $needsMajor = 0;
    private int $mergeablePrs = 0;
    private int $wouldClose = 0;
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
    ) {
        $this->now  = gmdate('Y-m-d\TH:i:s\Z');
        $this->root = $target->root;
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
            $this->cleanAtStart = (new BranchPublisher($runner, $c, $this->root))->isClean();
        }
        if ($this->opt->push && $this->opt->mode === 'update') {
            $publisher    = new BranchPublisher($runner, $c, $this->root, $this->opt->timeout > 0 ? $this->opt->timeout : 600);
            $cleanAtStart = $this->cleanAtStart;
            $startBranch  = $cleanAtStart === null ? '' : $publisher->currentBranch();
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
        if ($publisher !== null && $cleanAtStart === true && !$this->opt->applyStored) {
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
                    $guards[] = new WorkspaceGuard($g === '' ? $ctx->root : $ctx->root . '/' . $g, $ctx->checkMode());
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

        $limit  = $this->opt->maxIssues === 0 ? 100000 : $this->opt->maxIssues;
        $issues = $this->gh()->openIssues($repo, $limit, 'number,title,body,author,url');
        $issueRecords = [];
        if ($issues === null) {
            $c->warn("Could not list issues for {$repo}");
            $this->record('sec-issues', 'SKIP');
        } else {
            if (count($issues) >= $limit) {
                // Records for the rest arrive as earlier issues are closed
                $c->warn("Security issues: only the first {$limit} open issues were read (--max-issues; 0 reads them all)");
            }
            // Issue bodies become manifest edits, so only a security bot's count
            $issueRecords = IssueParser::parse(array_values(array_filter($issues, static fn ($i) => self::isBot($i['author'] ?? null))));
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
        // Alerts fixed or dismissed and issues closed since they were recorded
        // are retired, but only from a complete listing
        if ($alerts !== null) {
            $db = VulnDb::retire($db, 'dependabot', array_fill_keys(array_column($alertRecords, 'key'), true), $this->now);
        }
        if ($issues !== null && count($issues) < $limit) {
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
        $plan    = FixPlanner::plan($db);
        $inScope = array_values(array_filter($plan, fn (array $row): bool => $this->target->inScope($row['manifest'])));
        // With --subdir, fixes for manifests elsewhere in the repository stay pending
        $scopeNote = $this->target->subdir === '' ? ''
            : ' (' . count($inScope) . ' of ' . count($plan) . " manifest/package fixes inside {$this->target->subdir})";
        // Check mode works out the same edits without writing them, so it can
        // say what update mode would do
        $write = $this->opt->mode === 'update';
        $c->info($write
            ? "auto-fix: applying {$pending} pending fix(es) from {$this->vulnDb}{$scopeNote}"
            : "auto-fix: {$pending} pending fix(es); check mode only works out what update mode would change{$scopeNote}");

        $lister  = $this->dirLister();
        $updates = [];
        $applied = $missing = $notDeclared = $satisfied = $unsupported = $major = 0;
        foreach ($inScope as $row) {
            $target = ManifestPaths::sourceManifestFor($row['manifest'], $lister);
            $via    = $target !== $row['manifest'] ? ' (via ' . basename($row['manifest']) . ')' : '';
            $abs    = $this->insideRoot($target);
            $eco    = ManifestPaths::ecosystemFor($target);
            $eco    = $eco !== 'unknown' ? $eco : $row['ecosystem'];
            $pkg    = $row['package'];
            $state  = 'pending';

            if ($abs === null) {
                $missing++;
                [$state, $note] = ['skipped', "manifest not found: {$target}"];
            } else {
                $content  = (string)file_get_contents($abs);
                $declared = ManifestEditor::declared($eco, $target, $content, $pkg);
                $pin      = $row['pkg_max'];
                $current  = $declared;
                $locked   = $declared === '' && $eco === 'npm' ? Lockfile::versions(dirname($abs), 'npm', $pkg) : null;
                if ($locked !== null && $locked !== []) {
                    // Transitive: what matters is what the lockfile resolved
                    $lines = array_values(array_unique(array_map([Version::class, 'majorLine'], $locked)));
                    if (array_filter($locked, static fn (string $v): bool => !Version::clearsAll($v, $row['spec'])) === []) {
                        $ver = '';
                    } elseif (count($lines) > 1) {
                        // A package-wide pin would force every copy onto one line
                        $ver = null;
                    } else {
                        $current = $locked[0];
                        $ver     = $pin = Version::chooseTarget($locked[0], $row['spec']);
                    }
                } else {
                    $ver = Version::chooseTarget($declared, $row['spec'], $pin);
                }

                if ($locked === []) {
                    // The lockfile is what gets installed, and it holds no
                    // copy: an override would add a pin that fixes nothing
                    $notDeclared++;
                    [$state, $note] = ['skipped', "{$pkg} is neither declared in {$target} nor in its lockfile"];
                } elseif ($ver === null) {
                    $unsupported++;
                    $note = "{$pkg} is locked at " . implode(', ', $locked) . " in several major versions; pin it by hand";
                } elseif ($ver === '') {
                    // Every advisory for this package is already cleared
                    $satisfied++;
                    $state = 'applied';
                    $note  = $locked !== null
                        ? "already satisfied: the lockfile resolves {$pkg} to " . implode(', ', $locked)
                        : "already satisfied: {$target} declares {$declared}";
                } elseif (!$this->opt->allowMajor && Version::floor($current) !== '' && Version::majorLine($current) !== Version::majorLine($ver)) {
                    // Left pending: --allow-major on a later run applies it
                    $major++;
                    $note = "needs a major upgrade: {$pkg} {$current} -> {$ver} in {$target} (rerun with --allow-major)";
                    $c->warn("  {$eco} {$pkg} needs a major upgrade ({$current} -> {$ver}) in {$target}; not applied without --allow-major");
                } else {
                    $res = ManifestEditor::apply(
                        $eco,
                        $target,
                        $content,
                        $pkg,
                        $ver,
                        $pin !== '' ? $pin : $ver,
                        is_file(dirname($abs) . '/yarn.lock'),
                        is_file(dirname($abs) . '/package-lock.json') || is_file(dirname($abs) . '/npm-shrinkwrap.json')
                    );
                    if ($res['status'] === ManifestEditor::REFUSED) {
                        $notDeclared++;
                        [$state, $note] = ['skipped', "refused: {$ver} would downgrade the version declared in {$target}"];
                    } elseif ($res['status'] === ManifestEditor::UNSUPPORTED) {
                        $unsupported++;
                        $note = "cannot edit {$pkg}" . ($declared !== '' ? " (declared as {$declared})" : '') . " in {$target}";
                    } elseif ($res['content'] !== $content && !$write) {
                        $applied++;
                        $note = "would set {$ver} in {$target}";
                        $c->info("  would set {$eco} {$pkg} -> {$ver} in {$target}{$via}");
                    } elseif ($res['content'] !== $content && file_put_contents($abs, $res['content']) !== false) {
                        $applied++;
                        [$state, $note] = ['applied', "set to {$ver} in {$target}"];
                        $c->ok("  {$eco} {$pkg} -> {$ver} in {$target}{$via}");
                        $this->appliedFixes[] = "{$eco} {$pkg} -> {$ver} in {$target}";
                    } else {
                        $notDeclared++;
                        [$state, $note] = ['skipped', "package not declared in {$target}"];
                    }
                }
            }
            foreach ($row['keys'] as $key) {
                $updates[] = ['key' => $key, 'state' => $state, 'note' => $note];
            }
        }
        $this->needsMajor = $major;
        if (!$write) {
            $this->readyFixes = $applied;
            $c->info("auto-fix (check mode): would-apply={$applied} already-ok={$satisfied} not-declared={$notDeclared}"
                . " missing-manifest={$missing} cannot-edit={$unsupported} needs-major={$major}. Use --update to apply.");
            return;
        }
        $this->saveDb(VulnDb::applyStates($db, $updates, $this->now));

        $c->info("auto-fix: applied={$applied} already-ok={$satisfied} not-declared={$notDeclared} missing-manifest={$missing}"
            . " cannot-edit={$unsupported} needs-major={$major}");
        if ($applied > 0) {
            $this->record('auto-fix', 'PASS', 0, $applied);
            if (!$this->opt->push) {
                $c->warn("Manifests were modified in {$this->root} — review 'git diff' before committing");
            }
        } else {
            $this->record('auto-fix', 'SKIP');
        }
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
        $open = $this->gh()->json(['issue', 'list', '--repo', $repo, '--state', 'open', '--limit', '100000', '--json', 'number'], 900);
        if (!is_array($open)) {
            // Working through every ref ever recorded would re-close closed
            // issues and spend the content-creation quota doing it
            $c->warn('close-fixed: could not list open issues; skipped');
            $this->record('close-fixed', 'SKIP');
            return;
        }
        $openSet = array_flip(array_map('intval', array_column($open, 'number')));
        $c->info('close-fixed: ' . count($openSet) . ' issues open, ' . count($byIssue) . ' in the database');
        $byIssue = array_intersect_key($byIssue, $openSet);
        $c->info('close-fixed: checking ' . count($byIssue) . ' issue(s) against the current manifests');

        $branch = 'master';
        $r = $this->ctx->runner->run(['git', '-C', $this->root, 'rev-parse', '--abbrev-ref', 'HEAD'], $this->root, ['timeout' => 30, 'label' => 'git']);
        if ($r->ok() && trim($r->stdout) !== '') {
            $branch = trim($r->stdout);
        }

        $lister   = $this->dirLister();
        $contents = [];
        $closed = $unresolved = $unverifiable = $rateLimited = $outOfScope = 0;
        foreach ($byIssue as $ref => $needs) {
            $ok       = true;
            $reason   = '';
            $detail   = '';
            $evidence = '';
            foreach ($needs as $need) {
                if ($need['package'] === '') {
                    continue;
                }
                // With --subdir, an issue is only judged when every manifest
                // it names is inside the scanned part
                if (!$this->target->inScope($need['manifest'])) {
                    [$ok, $reason, $detail] = [false, 'out-of-scope', "{$need['manifest']} is outside {$this->target->subdir}"];
                    break;
                }
                if ($need['fixed_version'] === '') {
                    [$ok, $reason, $detail] = [false, 'unverifiable', "no fixed version is known for one of the {$need['package']} vulnerabilities"];
                    break;
                }
                $target = ManifestPaths::sourceManifestFor($need['manifest'], $lister);
                $abs    = $this->insideRoot($target);
                if ($abs === null) {
                    [$ok, $reason, $detail] = [false, 'unverifiable', "manifest missing: {$target}"];
                    break;
                }
                // Where a lockfile exists, what it resolved is what gets installed
                $eco    = ManifestPaths::ecosystemFor($target);
                $locked = in_array($eco, ['npm', 'composer'], true) ? Lockfile::versions(dirname($abs), $eco, $need['package']) : null;
                if ($locked !== null && $locked !== []) {
                    $behind = array_values(array_filter($locked, static fn (string $v): bool => !FixPlanner::requirementMet($v, $need)));
                    if ($behind !== []) {
                        [$ok, $reason, $detail] = [false, 'unresolved', "{$need['package']} is locked at " . implode(', ', $behind) . ", needs >= {$need['fixed_version']}"];
                        break;
                    }
                    $evidence .= "| `{$need['package']}` | {$need['fixed_version']} | **" . implode(', ', $locked) . " (locked)** | `{$target}` |\n";
                    continue;
                }
                $contents[$abs] ??= (string)file_get_contents($abs);
                $cur = ManifestEditor::declared($need['ecosystem'], $target, $contents[$abs], $need['package']);
                if ($cur === '') {
                    [$ok, $reason, $detail] = [false, 'unverifiable', "{$need['package']} not declared in {$target}"];
                    break;
                }
                if (!FixPlanner::requirementMet($cur, $need)) {
                    [$ok, $reason, $detail] = [false, 'unresolved', "{$need['package']} is {$cur}, needs >= {$need['fixed_version']}"];
                    break;
                }
                // Record the evidence so the closing comment shows its working
                $evidence .= "| `{$need['package']}` | {$need['fixed_version']} | **{$cur}** | `{$target}` |\n";
            }

            if (!$ok) {
                match ($reason) {
                    'unresolved'   => $unresolved++,
                    'out-of-scope' => $outOfScope++,
                    default        => $unverifiable++,
                };
                if ($this->opt->debug) {
                    $c->info("  #{$ref} " . ($reason === 'unresolved' ? 'still open' : $reason) . ": {$detail}");
                }
                continue;
            }
            if (!$update) {
                $c->info("  would close #{$ref} (all fixes verified)");
                $closed++;
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
                . "Every package this issue reports now declares a version at or above the required fix on `{$branch}`:\n\n"
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
        $c->info("close-fixed: closed={$closed} still-vulnerable={$unresolved} unverifiable={$unverifiable} rate-limited={$rateLimited}"
            . ($this->target->subdir !== '' ? " outside-subdir={$outOfScope}" : ''));
        $this->record('close-fixed', 'PASS', 0, $closed);
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
        if ($cleanAtStart === false) {
            $c->warn('push: the working tree had uncommitted changes before the run; not committing, so they cannot be mixed in');
            return;
        }
        if (!$publisher->hasChanges()) {
            // The base branch already is what the manifests say
            $this->landed = true;
            $this->record('push', 'SKIP');
            return;
        }

        $files   = $publisher->changedFiles();
        $title   = 'Dependency security updates';
        $message = $title . "\n\n" . $this->changeSummary($files, false);
        $branch  = $this->opt->branch !== '' ? $this->opt->branch : BranchPublisher::defaultBranch($this->now);

        if ($this->opt->pushMode === 'direct') {
            $result = $publisher->publishDirect($message, $branch);
            $this->landed = $result === 'pushed';
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

    private function record(string $key, string $status, int $vulns = 0, int $outdated = 0): void
    {
        $prev = $this->summary[$key] ?? null;
        if ($prev === null) {
            $this->summary[$key] = ['status' => $status, 'vulns' => $vulns, 'outdated' => $outdated];
            return;
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
        $c->line($c->blue() . sprintf('%-17s %-8s %-16s %-10s', 'Ecosystem', 'Status', 'Vulnerabilities', 'Outdated') . $c->reset());
        $c->line($c->blue() . str_repeat('─', 53) . $c->reset());
        foreach ($this->summary as $key => $row) {
            $c->line($c->colorFor($row['status']) . sprintf('%-17s %-8s %-16d %-10d', $key, $row['status'], $row['vulns'], $row['outdated']) . $c->reset());
        }
        $c->line('done');
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
            ];
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

    private function dirLister(): callable
    {
        $root = $this->root;
        return static function (string $dir) use ($root): array {
            $entries = @scandir($dir === '' ? $root : $root . '/' . $dir);
            return $entries === false ? [] : array_values(array_diff($entries, ['.', '..']));
        };
    }
}
