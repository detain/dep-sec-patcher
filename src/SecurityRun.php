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
 * optional security-posture remediation, close-fixed, summary and JSON report.
 *
 * @phpstan-import-type Need from IssueVerifier
 * @phpstan-import-type Verdict from IssueVerifier
 * @phpstan-import-type Item from NotFixedReport
 * @phpstan-import-type Counted from NotFixedReport
 * @phpstan-import-type Bucket from NotFixedReport
 * @phpstan-import-type Section from NotFixedReport
 * @phpstan-import-type Report from NotFixedReport
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
    /** The repo's PR triage memory; null until the triage step needs it. */
    private ?PrTriageState $prTriageState = null;
    /** Whether saving that memory failed; say so once, not per PR. */
    private bool $prStateWarned = false;
    /** The repo's close-fixed memory; null until that step needs it. */
    private ?CloseState $closeState = null;
    /** Whether saving that memory failed; say so once, not per issue. */
    private bool $closeStateWarned = false;
    /** The commit verdicts are drawn against, read once the close memory is consulted. */
    private ?string $headSha = null;
    private bool $headShaRead = false;
    /**
     * The dependency-bot PRs this run's complete triage listing saw; null
     * when it never saw one whole.
     * @var list<array{title: string, body: string}>|null
     */
    private ?array $openBotPrs = null;
    /**
     * The run's "not fixed and why" section, shaped for the JSON report.
     * @var Report|null
     */
    private ?array $notFixed = null;
    /**
     * Dependabot's open alerts, read once per pass; null when the read failed.
     * @var list<array<string, mixed>>|null
     */
    private ?array $openAlerts = null;
    private bool $openAlertsRead = false;
    /** Whether a triage pass got past its guards (the recheck needs that). */
    private bool $triageListed = false;
    /** @var array<string, true> PRs the first pass of this run already handled */
    private array $triageHandled = [];
    /** The repository's default branch, read once when a PR needs its name. */
    private string $defaultBranchRef = '';
    /**
     * Security posture settings this run switched on, for the JSON report.
     * @var list<string>
     */
    private array $postureEnabled = [];
    /** Whether a posture pass ran at all, so the report says "checked, nothing to change". */
    private bool $postureAttempted = false;

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
        /** Per-repo PR triage memory; '' puts it beside the reports */
        private string $triageStateFile = '',
        /** Per-repo close-fixed memory; '' puts it beside the reports */
        private string $closeStateFile = '',
        ?RegistryProbe $registry = null,
    ) {
        $this->now             = gmdate('Y-m-d\TH:i:s\Z');
        $this->root            = $target->root;
        $this->registry        = $registry ?? new RegistryProbe();
        $this->triageStateFile = $triageStateFile !== '' ? $triageStateFile : dirname($reportDir) . '/triage-state.json';
        $this->closeStateFile  = $closeStateFile !== '' ? $closeStateFile : dirname($reportDir) . '/close-state.json';
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
        // The pushed fixes raise Dependabot alerts of their own, and the bot
        // opens PRs for them while the run is still going; look once more
        // before the run ends so a clean one does not wait for a whole cycle
        if ($triaged && $this->opt->retriage && $this->triageListed && $this->appliedFixes !== []) {
            $this->triagePullRequests(true);
        }
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
        // An available auditor that finds nothing everywhere is the empty-repo
        // case; without this flag a `--only`-nothing run could claim it
        $looked = false;

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
            $looked = true;
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
            if ($looked) {
                $label = $this->target->githubRepo !== '' ? $this->target->githubRepo : basename($this->root);
                $c->skip("{$label} — no manifest-bearing projects found (empty repo?)");
                $this->record('projects', 'SKIP', 0, 0, 'no manifest-bearing projects found (empty repo?)');
            }
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

        // The same rows the triage step reads to spot superseded PRs; when
        // it already looked, no second call is made
        $alertRows    = $this->openDependabotAlerts();
        $alertsReadOk = $alertRows !== null;
        $alertRecords = $alertRows ?? [];
        if (!$alertsReadOk) {
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
        if ($alertsReadOk) {
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
        $repo = $this->repo();
        $info = $this->gh()->json(['api', 'repos/' . $repo], 60);
        $sa   = is_array($info) ? ($info['security_and_analysis'] ?? null) : null;
        if (!is_array($sa)) {
            $c->skip('Secret scanning: cannot determine status');
            $this->record('secret-scanning', 'SKIP');
            return;
        }
        /** @var array<string, mixed> $info */
        $write = $this->opt->enablePosture && $this->opt->mode === 'update';
        if ($write) {
            $this->postureAttempted = true;
        }
        $gh  = $this->gh();
        /** @param list<string> $args */
        $api = fn (array $args): CommandResult => $gh->run(array_values($args), 60);
        $this->postureEnabled = self::reportSecurityPosture($write, $repo, $info, $api, $c);
        $this->record('secret-scanning', in_array('secret-scanning', $this->postureEnabled, true)
            || ($sa['secret_scanning']['status'] ?? null) === 'enabled' ? 'PASS' : 'FAIL');
    }

    /**
     * Report the repository's security posture and, where the run was asked to
     * improve it ($write), switch on what is off and this run is able to enable.
     * Every enable is one idempotent API call and best-effort: an error is
     * reported with its HTTP status and never raised, so a repository the token
     * cannot administer surfaces as a WARN rather than failing the run. When
     * $write is false nothing is called and only the standing status is shown.
     *
     * @param array<string, mixed>                $info the GET repos/{owner}/{repo} body
     * @param callable(list<string>): CommandResult $api one `gh api ...` call (args after "gh")
     * @return list<string> what was actually switched on
     */
    private static function reportSecurityPosture(bool $write, string $repo, array $info, callable $api, Console $c): array
    {
        $sa         = is_array($info['security_and_analysis'] ?? null) ? $info['security_and_analysis'] : [];
        $secret     = (string)($sa['secret_scanning']['status'] ?? 'unknown');
        $dependabot = (string)($sa['dependabot_security_updates']['status'] ?? 'unknown');
        $push       = (string)($sa['secret_scanning_push_protection']['status'] ?? 'unknown');
        $public     = ($info['visibility'] ?? '') === 'public'
            || (!isset($info['visibility']) && ($info['private'] ?? true) === false);
        $enabled    = [];

        if ($dependabot === 'enabled') {
            $c->ok('Dependabot security updates: enabled');
        } elseif ($write) {
            if (self::tryEnable($api, $c, $repo, 'Dependabot security updates', 'cannot enable security updates',
                ['api', '-X', 'PUT', "repos/{$repo}/vulnerability-alerts"])) {
                $enabled[] = 'dependabot-security-updates';
            }
        } else {
            $c->fail("Dependabot security updates: {$dependabot}");
        }

        $secretOn = $secret === 'enabled';
        if ($secretOn) {
            $c->ok('Secret scanning: enabled');
        } elseif ($write && $public) {
            if (self::tryEnable($api, $c, $repo, 'Secret scanning', 'cannot enable secret scanning',
                ['api', '-X', 'PATCH', "repos/{$repo}", '-f', 'security_and_analysis[secret_scanning][status]=enabled'])) {
                $enabled[]  = 'secret-scanning';
                $secretOn   = true;
            }
        } elseif ($write) {
            $c->info('Secret scanning: ' . $secret . ' (private repository - needs an advanced security licence, left as is)');
        } else {
            $c->fail("Secret scanning: {$secret}");
        }

        if ($write && $public && $secretOn && $push !== 'enabled') {
            if (self::tryEnable($api, $c, $repo, 'Secret scanning push protection', 'cannot enable push protection',
                ['api', '-X', 'PATCH', "repos/{$repo}", '-f', 'security_and_analysis[secret_scanning_push_protection][status]=enabled'])) {
                $enabled[] = 'secret-scanning-push-protection';
            }
        }

        if ($write) {
            $r = $api(['api', '-X', 'POST', "repos/{$repo}/private-vulnerability-reporting"]);
            if ($r->ok() || self::httpStatus($r) === 409) {
                $c->ok('Private vulnerability reporting: ' . ($r->ok() ? 'enabled' : 'already enabled'));
                $enabled[] = 'private-vulnerability-reporting';
            } else {
                self::enableFailure($c, $repo, 'cannot enable private vulnerability reporting', $r);
            }
        }

        $scanning = $sa['code_scanning']['default_setup']['summary'] ?? null;
        if (is_string($scanning)) {
            $scanning === 'configured' ? $c->ok('Code scanning: configured') : $c->info("Code scanning: {$scanning}");
        }

        return $enabled;
    }

    /**
     * One enable attempt: an idempotent write that stays quiet on success and
     * says which HTTP status blocked it otherwise.
     *
     * @param callable(list<string>): CommandResult $api
     * @param list<string> $args
     */
    private static function tryEnable(callable $api, Console $c, string $repo, string $label, string $why, array $args): bool
    {
        $r = $api($args);
        if (!$r->ok()) {
            self::enableFailure($c, $repo, $why, $r);
            return false;
        }
        $c->ok("{$label}: enabled (was disabled)");
        return true;
    }

    private static function enableFailure(Console $c, string $repo, string $why, CommandResult $r): void
    {
        $code = self::httpStatus($r);
        $c->warn("{$repo} — {$why}: " . ($code !== null ? "HTTP {$code}" : $r->failureReason()));
    }

    /**
     * The HTTP status gh names in its output ("... (HTTP 404)"), or null when
     * the call failed for some other reason.
     */
    private static function httpStatus(CommandResult $r): ?int
    {
        return preg_match('/HTTP (\d{3})/', $r->output, $m) === 1 ? (int)$m[1] : null;
    }

    // ── dependency-bot PR triage ─────────────────────────────────────────────

    /**
     * Merge what dependency bots raised and GitHub can merge, ask the bots
     * to rebase what conflicts or fell behind, close what another change has
     * made redundant, and remember every verdict in the repo's triage state
     * so the next pass escalates instead of rediscovering. $recheck is the
     * second pass after a push: the run's own changes may have raised alerts
     * the bot opened PRs for while the run was going.
     */
    private function triagePullRequests(bool $recheck = false): void
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
        $c->info($recheck
            ? "Re-checking {$repo} for dependency-bot PRs opened during the run..."
            : "Triaging dependency-bot PRs on {$repo}...");
        $this->triageListed = true;
        if ($recheck) {
            // This run's own push may have resolved the alerts the first
            // pass read; the supersede test needs the list as it stands now
            $this->openAlertsRead = false;
            $this->openAlerts     = null;
        }

        // A listing capped at 100 silently dropped the rest on busy repos,
        // so page through the REST list until a short page ends it
        $prs = self::pullRequestRows(GitHub::collectPulls(
            fn (int $page): ?array => $this->pullRequestPage($repo, $page),
            $complete
        ));
        if ($prs === [] && !$complete) {
            $c->warn('PR triage: could not list pull requests');
            return;
        }
        if (!$complete) {
            $c->warn('PR triage: the pull request listing was cut short; acting on what was read, '
                . 'and the triage state stays unpruned');
        }
        // Only touch PRs raised by dependency bots, never a human contributor's work
        $bots = array_values(array_filter($prs, static fn ($pr) => empty($pr['isDraft']) && self::isBot($pr['author'] ?? null)));
        if ($complete) {
            // The report may call an alert covered by an open PR only when
            // the listing saw every PR; a cut-short one proves nothing
            $this->openBotPrs = array_map(static fn (array $pr): array => [
                'title' => (string)($pr['title'] ?? ''),
                'body'  => (string)($pr['body'] ?? ''),
            ], $bots);
        }
        if ($bots === []) {
            $c->ok($prs === [] ? 'No open PRs' : 'No dependency-bot PRs open');
            if (!$recheck) {
                $this->record('dep-prs', 'PASS');
            }
            $this->pruneTriageState($complete, []);
            return;
        }
        $c->info('Found ' . count($bots) . ' dependency-bot PR(s)');

        $merged = $rebased = $blocked = $pending = $closed = $handled = 0;
        $seen   = [];
        foreach ($bots as $pr) {
            $num    = (string)$pr['number'];
            $seen[] = $num;
            $author = (string)($pr['author']['login'] ?? '');
            if ($recheck && isset($this->triageHandled[$num])) {
                $handled++;   // the first pass of this run already dealt with it
                continue;
            }
            [$mergeable, $status] = $this->mergeState($repo, $num);
            $c->info("PR #{$num} [{$mergeable}/{$status}] " . ($pr['title'] ?? '')
                . self::seenNote($this->triageState()->get($num)));
            // A bot PR moving a dependency to a new major version gets the
            // same opt-in as an auto-fix doing it
            $majors = $this->opt->allowMajor ? [] : self::majorBumps((string)($pr['title'] ?? ''), (string)($pr['body'] ?? ''));
            [$outcome, $fields] = match (true) {
                $this->opt->mode !== 'update' => $this->countCheckMode($mergeable, $status, $majors),
                $majors !== []                => $this->needsMajorPullRequest($num, $majors),
                $mergeable === 'MERGEABLE'    => $this->mergeablePullRequest($repo, $num, $author, $status, $pr),
                $mergeable === 'CONFLICTING'  => $this->conflictingPullRequest($repo, $pr, $author),
                default                       => $this->unsettledMergeability($num, $mergeable),
            };
            match (self::tallyOf($outcome)) {
                'merged'  => $merged++,
                'rebased' => $rebased++,
                'closed'  => $closed++,
                'pending' => $pending++,
                'blocked' => $blocked++,
                default   => null,
            };
            if ($this->opt->mode === 'update') {
                $this->triageState()->record($num, [
                    'outcome' => $outcome,
                    'title'   => mb_substr((string)($pr['title'] ?? ''), 0, 120),
                ] + $fields);
                $this->saveTriageState();
            }
            $this->triageHandled[$num] = true;
        }
        $c->info('PR triage: merged=' . $merged . ' rebase-requested=' . $rebased
            . ($closed > 0 ? ' superseded-closed=' . $closed : '')
            . ($handled > 0 ? ' already-handled=' . $handled : '')
            . ' blocked=' . $blocked
            . ($pending > 0 ? ' pending=' . $pending : ''));
        if (!$recheck) {
            $this->record('dep-prs', $blocked > 0 ? 'FAIL' : ($pending > 0 ? 'WARN' : 'PASS'), $blocked, count($bots),
                $pending > 0 ? "{$pending} pending (--push, --allow-major or a human)" : '');
        } elseif ($merged + $closed > 0) {
            $this->record('dep-prs', 'PASS', 0, 0, "{$merged} merged and {$closed} superseded closed on the re-check");
        }
        $this->pruneTriageState($complete, $seen);
    }

    /**
     * Which tally an outcome belongs in. "pending" is by design: the tool
     * did all its mode allows and waits for --push (would-supersede, and
     * close-failed is a close the next run retries), for --allow-major
     * (needs-major), or for the human the bot itself addressed
     * (rebase-refused). None of those makes a run wrong. "blocked" stays
     * for what is genuinely stuck: failed merges and comments, protection,
     * CI and undecided mergeability the next pass must revisit.
     */
    private static function tallyOf(string $outcome): string
    {
        return match (true) {
            in_array($outcome, ['merged', 'auto-merge'], true) => 'merged',
            in_array($outcome, ['rebase-requested', 'rebase-nudged', 'manual-instructions'], true) => 'rebased',
            $outcome === 'superseded-closed' => 'closed',
            in_array($outcome, ['counted', 'behind-waiting', 'rebase-waiting'], true) => 'none',
            in_array($outcome, ['would-supersede', 'needs-major', 'rebase-refused', 'close-failed'], true) => 'pending',
            default => 'blocked',
        };
    }

    /**
     * One page of the open pull requests, as the REST API lists them; null
     * when the call failed.
     *
     * @return list<array<string, mixed>>|null
     */
    private function pullRequestPage(string $repo, int $page): ?array
    {
        $rows = $this->gh()->json(
            ['api', "repos/{$repo}/pulls?state=open&per_page=" . GitHub::PULL_PAGE . "&page={$page}"],
            300
        );
        return is_array($rows) ? array_values(array_filter($rows, 'is_array')) : null;
    }

    /**
     * The REST /pulls rows in the shape `gh pr list --json number,title,
     * author,isDraft,headRefName,body` gives, so the triage loop reads one
     * format whoever produced the listing. REST names the author's account
     * "dependabot[bot]" where gh's GraphQL prints "app/dependabot"; isBot()
     * accepts both.
     *
     * @param list<array<string, mixed>> $rows
     * @return list<array<string, mixed>>
     */
    public static function pullRequestRows(array $rows): array
    {
        $out = [];
        foreach ($rows as $pr) {
            if (!isset($pr['number'])) {
                continue;
            }
            $user = is_array($pr['user'] ?? null) ? $pr['user'] : [];
            $head = is_array($pr['head'] ?? null) ? $pr['head'] : [];
            $out[] = [
                'number'      => (int)$pr['number'],
                'title'       => (string)($pr['title'] ?? ''),
                'author'      => [
                    'login'  => (string)($user['login'] ?? ''),
                    'is_bot' => ($user['type'] ?? '') === 'Bot',
                ],
                'isDraft'     => ($pr['draft'] ?? false) === true,
                'headRefName' => (string)($head['ref'] ?? ''),
                'body'        => (string)($pr['body'] ?? ''),
            ];
        }
        return $out;
    }

    /**
     * What earlier passes remembered about a PR, for its listing line, so a
     * PR blocked for the tenth time reads differently from a new arrival.
     *
     * @param array<string, mixed> $prior
     */
    private static function seenNote(array $prior): string
    {
        if ($prior === [] || (int)($prior['sightings'] ?? 0) < 2) {
            return '';
        }
        return ' (seen ' . (int)$prior['sightings'] . 'x since ' . substr((string)($prior['first_seen'] ?? '?'), 0, 10)
            . ', last: ' . (string)($prior['outcome'] ?? '?') . ')';
    }

    /**
     * Check mode touches nothing, not even the bots: it only counts what
     * update mode could do.
     *
     * @param list<string> $majors
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function countCheckMode(string $mergeable, string $status, array $majors): array
    {
        if ($majors !== []) {
            $this->needsMajor++;
        } else {
            $this->mergeablePrs += $mergeable === 'MERGEABLE' && $status !== 'UNSTABLE' ? 1 : 0;
        }
        return ['counted', []];
    }

    /**
     * @param list<string> $majors
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function needsMajorPullRequest(string $num, array $majors): array
    {
        $this->console->warn("  PR #{$num} is a major upgrade (" . implode(', ', $majors) . '); not merged without --allow-major');
        $this->needsMajor++;
        return ['needs-major', []];
    }

    /**
     * GitHub has not decided whether the PR merges (a big diff still being
     * computed, or a just-opened one); the next pass looks again.
     *
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function unsettledMergeability(string $num, string $mergeable): array
    {
        $this->console->warn("  PR #{$num} mergeability still {$mergeable} — skipped this run");
        return ['unknown-mergeability', []];
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
     * A mergeable bot PR: take it when GitHub's checks allow it, ask the bot
     * to rebase a branch that trails the base, and leave branch protection
     * and failing checks to a human or a later run.
     *
     * @param array<string, mixed> $pr
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function mergeablePullRequest(string $repo, string $num, string $author, string $status, array $pr): array
    {
        $c = $this->console;
        if ($status === 'UNSTABLE') {
            // Failing or still-running checks: merging now could ship a broken build
            $c->warn("  PR #{$num} has checks that are failing or still running; left for a later run");
            return ['blocked-ci', []];
        }
        if ($status === 'BLOCKED') {
            $c->warn("  PR #{$num} is mergeable but blocked by branch protection");
            return ['blocked-protection', []];
        }
        if ($status === 'BEHIND') {
            return $this->behindPullRequest($repo, $pr, $author);
        }
        if ($this->gh()->run(['pr', 'merge', $num, '--repo', $repo, '--squash', '--delete-branch'])->ok()) {
            $c->ok("  Merged PR #{$num}");
            $view   = $this->gh()->json(['pr', 'view', $num, '--repo', $repo, '--json', 'mergeCommit'], 60);
            $commit = is_array($view) ? (string)($view['mergeCommit'] ?? '') : '';
            return ['merged', $commit === '' ? [] : ['merge_commit' => $commit]];
        }
        if ($this->gh()->run(['pr', 'merge', $num, '--repo', $repo, '--squash', '--auto', '--delete-branch'])->ok()) {
            $c->ok("  Enabled auto-merge on PR #{$num} (pending required checks)");
            return ['auto-merge', []];
        }
        $c->fail("  Could not merge PR #{$num}");
        return ['merge-failed', []];
    }

    /**
     * Mergeable but behind base: redundant once the alert that raised it is
     * resolved by other work; otherwise the bot gets its rebase request,
     * within the throttle.
     *
     * @param array<string, mixed> $pr
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function behindPullRequest(string $repo, array $pr, string $author): array
    {
        $c    = $this->console;
        $num  = (string)$pr['number'];
        [$superseded, $fields] = $this->supersede($repo, $pr);
        if ($superseded !== null) {
            return [$superseded, $fields];
        }
        $rebaseCmd = self::rebaseCommand($author);
        if ($rebaseCmd === '') {
            $c->info("  PR #{$num} is behind base; {$author} takes no rebase command");
            return ['behind-waiting', $fields];
        }
        $comments = $this->prComments($repo, $num);
        if ($this->rebaseRequested($repo, $num, $comments)) {
            [$outcome, $extra] = $this->unansweredRebase($repo, $num, $author, $rebaseCmd, 'is still behind base');
            return [$outcome, $fields + $extra];
        }
        if (!$this->comment($repo, $num, $rebaseCmd)) {
            $c->fail("  PR #{$num} is behind base — could not post the rebase request");
            return ['rebase-failed', $fields];
        }
        $c->ok("  Asked {$author} to rebase PR #{$num} (branch behind base)");
        return ['rebase-requested', $fields + $this->firstRebaseRequest($num, $comments)];
    }

    /**
     * The PR conflicts: redundant when its alert is resolved anyway; a PR the
     * bot itself refuses to rebase waits for a human; otherwise the rebase
     * request goes out, and an unanswered one escalates only within the
     * throttle instead of being rediscovered forever.
     *
     * @param array<string, mixed> $pr
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function conflictingPullRequest(string $repo, array $pr, string $author): array
    {
        $c   = $this->console;
        $num = (string)$pr['number'];
        [$superseded, $fields] = $this->supersede($repo, $pr);
        if ($superseded !== null) {
            return [$superseded, $fields];
        }
        $comments = $this->prComments($repo, $num);
        foreach ($comments['comments'] as $cm) {
            if (preg_match('/can.t be rebased|Please close the PR/', (string)($cm['body'] ?? '')) === 1) {
                $c->warn("  PR #{$num} cannot be rebased by {$author} — close it so a fresh PR is raised");
                return ['rebase-refused', $fields];
            }
        }
        $rebaseCmd = self::rebaseCommand($author);
        if ($rebaseCmd !== '') {
            if ($this->rebaseRequested($repo, $num, $comments)) {
                [$outcome, $extra] = $this->unansweredRebase($repo, $num, $author, $rebaseCmd, 'conflicts');
                return [$outcome, $fields + $extra];
            }
            if ($this->comment($repo, $num, $rebaseCmd)) {
                $c->ok("  PR #{$num} conflicts — commented '{$rebaseCmd}'");
                return ['rebase-requested', $fields + $this->firstRebaseRequest($num, $comments)];
            }
            $c->fail("  PR #{$num} conflicts — could not post rebase comment");
            return ['rebase-failed', $fields];
        }
        // No bot command available: leave the human-runnable equivalent
        $default = $this->defaultBranch($repo);
        $branch  = (string)($pr['headRefName'] ?? '');
        $body    = "This PR has merge conflicts. To rebase it manually:\n\n```bash\n"
            . "git fetch origin && git checkout {$branch} && git rebase origin/{$default} && git push --force-with-lease\n```";
        if (!$this->comment($repo, $num, $body)) {
            $c->fail("  PR #{$num} conflicts — could not post the manual rebase instructions");
            return ['rebase-failed', $fields];
        }
        $c->ok("  PR #{$num} conflicts — posted manual rebase instructions");
        return ['manual-instructions', $fields];
    }

    /**
     * The rebase request went unanswered, and a day or more has passed. Ask
     * once a day at most, MAX_REBASE_REQUESTS times in all, then say so once
     * and stop: a PR the bot has ignored three times is blocked on something
     * another comment cannot fix.
     *
     * @return array{0: string, 1: array<string, mixed>}
     */
    private function unansweredRebase(string $repo, string $num, string $author, string $rebaseCmd, string $what): array
    {
        $c        = $this->console;
        $prior    = $this->triageState()->get($num);
        $requests = max(1, (int)($prior['rebase_requests'] ?? 1));
        $since    = PrTriageState::secondsSince((string)($prior['rebase_last_at'] ?? ''), $this->now);
        if ($since === null) {
            // An earlier pass asked but this state file cannot say when:
            // start the clock now rather than risk a comment flood
            $c->info("  PR #{$num} {$what}, rebase requested — waiting on {$author}");
            return ['rebase-waiting', ['rebase_requested_at' => $this->now, 'rebase_requests' => $requests, 'rebase_last_at' => $this->now]];
        }
        $action = PrTriageState::rebaseAction($requests, $since);
        if ($action === 'nudge') {
            if ($this->comment($repo, $num, $rebaseCmd)) {
                $c->ok("  PR #{$num} {$what} after a day — asked {$author} again (" . ($requests + 1)
                    . '/' . PrTriageState::MAX_REBASE_REQUESTS . ')');
                return ['rebase-nudged', ['rebase_requests' => $requests + 1, 'rebase_last_at' => $this->now]];
            }
            $c->fail("  PR #{$num} {$what} — could not post the rebase nudge");
            return ['rebase-failed', ['rebase_last_at' => $this->now]];
        }
        if ($action === 'stop') {
            if (($prior['outcome'] ?? '') === 'blocked-permanent') {
                $c->info("  PR #{$num} {$what} — permanently blocked, not asking again");
                return ['blocked-permanent', []];
            }
            $body = "This PR has been asked to rebase {$requests} times over the last "
                . (int)round($since / 86400) . " days and still needs it, so dep-sec-patcher will not ask again."
                . " Close it so {$author} raises a fresh one, or rebase it manually.\n"
                . '<!-- security-update:stop -->';
            $this->commentRaw($repo, $num, $body);
            $c->warn("  PR #{$num} {$what} after {$requests} requests — marked permanently blocked, said so once");
            return ['blocked-permanent', []];
        }
        $c->info("  PR #{$num} {$what}, rebase requested {$requests}x (last "
            . CommandResult::duration($since) . ' ago) — waiting on ' . $author);
        return ['rebase-waiting', []];
    }

    /**
     * The fields a fresh rebase request leaves in the state file. A request
     * counts as answered when the head commit is newer than it — but a head
     * dated ahead of our own clock only proves the committer's clock runs
     * hot, not that the bot pushed: carry the earlier count forward then,
     * so skew cannot reset the throttle into a comment flood.
     *
     * @param array{comments: list<array<mixed>>, commits: list<array<mixed>>} $data
     * @return array<string, mixed>
     */
    private function firstRebaseRequest(string $num, array $data): array
    {
        $commits  = $data['commits'];
        $headTime = $commits === [] ? '' : (string)($commits[count($commits) - 1]['committedDate'] ?? '');
        $requests = $headTime !== '' && strcmp($headTime, $this->now) > 0
            ? max(1, (int)($this->triageState()->get($num)['rebase_requests'] ?? 1))
            : 1;
        return ['rebase_requested_at' => $this->now, 'rebase_requests' => $requests, 'rebase_last_at' => $this->now];
    }

    /**
     * Whether this PR is redundant now: no open Dependabot alert covers it
     * anymore, and the PR is latched as raised for one. Scheduled version
     * updates never were, and an alert list that cannot be read proves
     * nothing, so both are left alone; the alert-driven link is latched
     * into the state file on any sighting with a strictly covering alert —
     * the PR's directory when its title names one — which is what lets a
     * later run notice it is gone.
     *
     * @param array<string, mixed> $pr
     * @return array{0: string|null, 1: array<string, mixed>} outcome null when not superseded
     */
    private function supersede(string $repo, array $pr): array
    {
        $covered = $this->alertCoverage($pr);
        // Only strict coverage latches: the memory that lets a later run
        // close this PR must be about an alert in the very directory the PR
        // names, not one that merely shares a package name
        $fields  = $covered !== null && $covered['strict'] ? ['alert_driven' => 'yes'] : [];
        if ($covered === null || $covered['covered']
            || ($this->triageState()->get((string)$pr['number'])['alert_driven'] ?? null) !== 'yes') {
            return [null, $fields];
        }
        $num = (string)$pr['number'];
        if (!$this->opt->push) {
            // Merging a bot PR is update mode's job and needs no --push;
            // ending one holds to the stricter gate this tool sets itself,
            // so the close waits for --push
            $this->console->info("  PR #{$num} is superseded — " . self::supersedeClaim() . '; --push would close it');
            return ['would-supersede', $fields];
        }
        $body = 'Superseded — ' . self::supersedeClaim() . "; closing.\n\n<!-- security-update:superseded -->";
        $r    = $this->gh()->run(['pr', 'close', $num, '--repo', $repo, '--comment', $body]);
        if (!$r->ok()) {
            $this->console->warn("  PR #{$num} is superseded but could not be closed (" . $r->failureReason() . ')');
            return ['close-failed', $fields];
        }
        $this->console->ok("  PR #{$num} superseded — closed (" . self::supersedeClaim() . ')');
        return ['superseded-closed', $fields];
    }

    /**
     * What superseding asserts, and nothing beyond it: the open alert list
     * no longer covers the PR. A human dismissing an alert empties the list
     * exactly the same way, which is why the claim never says the advisory
     * was "resolved by another change".
     */
    public static function supersedeClaim(): string
    {
        return 'no open Dependabot alert covers these packages anymore';
    }

    /**
     * Whether the open Dependabot alerts still cover one of the packages the
     * PR moves, and whether any covering alert sits in the directory the PR
     * names. null when the PR cannot be judged on alerts at all: not a
     * Dependabot PR (the alerts speak only for what raised them), no package
     * could be read from it, or the alert list could not be read.
     *
     * @param array<string, mixed> $pr
     * @return array{covered: bool, strict: bool}|null
     */
    private function alertCoverage(array $pr): ?array
    {
        if (stripos((string)($pr['author']['login'] ?? ''), 'dependabot') === false) {
            return null;
        }
        $packages = self::prPackages((string)($pr['title'] ?? ''), (string)($pr['body'] ?? ''));
        if ($packages === []) {
            return null;
        }
        $alerts = $this->openDependabotAlerts();
        if ($alerts === null) {
            return null;
        }
        return self::alertsCoverPr($packages, self::prDirectory((string)($pr['title'] ?? '')), $alerts);
    }

    /**
     * The packages a bot PR moves: the name in "Bump x from A to B" (with or
     * without a conventional-commit prefix) plus every "Updates `x` from A
     * to B" line in the body, which is where grouped PRs list theirs. The
     * changelog quoted further down a body is not read.
     *
     * @return list<string>
     */
    public static function prPackages(string $title, string $body): array
    {
        $names = [];
        $bare  = (string)preg_replace('/^[a-z]+(?:\([^)]*\))?!?:\s*/i', '', trim($title));
        if (preg_match('/^bump (\S+) from /i', $bare, $m) === 1) {
            $names[strtolower($m[1])] = true;
        }
        preg_match_all('/^Updates `([^`]+)` from /m', $body, $mm);
        foreach ($mm[1] as $name) {
            $names[strtolower($name)] = true;
        }
        return array_keys($names);
    }

    /**
     * The manifest directory a PR title names — "Bump x from A to B in /app
     * ..." is about app/ — or null when it names none, as grouped
     * multi-directory titles do, leaving matching to the package alone.
     */
    public static function prDirectory(string $title): ?string
    {
        return preg_match('# in (/[^ ]+)#', $title, $m) === 1 ? trim($m[1], '/') : null;
    }

    /**
     * Whether one open alert still covers one of the packages, and whether
     * any covering alert is strict: in the very directory the PR title
     * names, when it names one. Only a strict cover may latch the
     * "raised for this alert" memory that later justifies a close, so an
     * unrelated alert sharing the package name cannot close the PR. A mere
     * cover still counts when deciding: an alert that names no manifest
     * proves nothing about where it lives, and keeping the PR open is the
     * safe direction for an auto-close. The ecosystem is deliberately not
     * compared — GitHub files Maven, Gradle and sbt apart from how a PR
     * groups them, and a too-generous match only keeps a PR open.
     *
     * @param list<string> $packages
     * @param list<array<string, mixed>> $alerts normalised Dependabot alert rows
     * @return array{covered: bool, strict: bool}
     */
    public static function alertsCoverPr(array $packages, ?string $dir, array $alerts): array
    {
        if ($packages === []) {
            return ['covered' => false, 'strict' => false];
        }
        $covered = false;
        $strict  = false;
        $wanted  = array_map('strtolower', $packages);
        foreach ($alerts as $alert) {
            if (!in_array(strtolower((string)($alert['package'] ?? '')), $wanted, true)) {
                continue;
            }
            $manifest = (string)($alert['manifest'] ?? '');
            if ($dir === null || $manifest === '') {
                $covered = true; // grouped title, or an alert that cannot be placed
                if ($dir === null) {
                    $strict = true; // a grouped title names no directory to contradict
                }
                continue;
            }
            $alertDir = dirname($manifest);
            $alertDir = $alertDir === '.' ? '' : trim($alertDir, '/');
            if ($alertDir === $dir) {
                $covered = true;
                $strict  = true;
            }
        }
        return ['covered' => $covered, 'strict' => $strict];
    }

    /**
     * Dependabot's open alerts as normalised records, read once per pass and
     * shared with the collection step; null when the read failed. After the
     * re-check's reset, this run's own push is what the answer reflects.
     *
     * @return list<array<string, mixed>>|null
     */
    private function openDependabotAlerts(): ?array
    {
        if ($this->openAlertsRead) {
            return $this->openAlerts;
        }
        $this->openAlertsRead = true;
        $raw                  = $this->gh()->paginate("repos/{$this->repo()}/dependabot/alerts?state=open&per_page=100");
        $this->openAlerts     = $raw === null ? null : array_map(
            [RecordNormalizer::class, 'withEcosystem'],
            RecordNormalizer::fromDependabotAlerts($raw)
        );
        return $this->openAlerts;
    }

    /**
     * The repository's default branch, read once per run.
     */
    private function defaultBranch(string $repo): string
    {
        if ($this->defaultBranchRef === '') {
            $info = $this->gh()->json(['repo', 'view', $repo, '--json', 'defaultBranchRef'], 60);
            $name = is_array($info) ? (string)($info['defaultBranchRef']['name'] ?? '') : '';
            $this->defaultBranchRef = $name !== '' ? $name : 'master';
        }
        return $this->defaultBranchRef;
    }

    /**
     * The triage memory of this run's repository, read on first use.
     */
    private function triageState(): PrTriageState
    {
        if ($this->prTriageState === null) {
            $corrupt = false;
            $this->prTriageState = PrTriageState::load($this->triageStateFile, $this->now, $this->repo(), $corrupt);
            if ($corrupt) {
                $this->console->warn("the PR triage state was unreadable and starts fresh: {$this->triageStateFile}");
            }
        }
        return $this->prTriageState;
    }

    private function saveTriageState(): void
    {
        if ($this->prStateWarned) {
            return;
        }
        try {
            $this->triageState()->save();
        } catch (RuntimeException $e) {
            $this->prStateWarned = true;
            $this->console->warn("PR triage state cannot be saved ({$e->getMessage()}); this run's verdicts are not remembered");
        }
    }

    /**
     * Forget what a complete listing no longer sees; a truncated one says
     * nothing about the PRs missing from it.
     *
     * @param list<string> $openNumbers
     */
    private function pruneTriageState(bool $complete, array $openNumbers): void
    {
        if (!$complete) {
            return;
        }
        $this->triageState()->retain($openNumbers);
        $this->saveTriageState();
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
        // Cannot compare, or a head dated ahead of our clock — which only
        // proves the committer's clock runs hot, not that the bot pushed:
        // assume the request stands rather than risk comment spam
        return $headTime === '' || strcmp($headTime, $this->now) > 0 || strcmp($lastReq, $headTime) > 0;   // ISO-8601 UTC sorts lexically
    }

    private function comment(string $repo, string $num, string $body): bool
    {
        return $this->commentRaw($repo, $num, $body . "\n\n<!-- security-update:rebase -->");
    }

    private function commentRaw(string $repo, string $num, string $body): bool
    {
        return $this->gh()->run(['pr', 'comment', $num, '--repo', $repo, '--body', $body])->ok();
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
        // npm override edits awaiting the lockfile's verdict (applied means
        // applied and verified)
        $verifications = [];
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
                $edits++;
                // An override for a transitive package is only a request: npm
                // can leave the vulnerable copy resolved (a parent's pinned
                // spec wins). With a npm lockfile present the edit waits for
                // verifyOverrides() below before it counts as applied. A
                // declared pin shows up in every later audit of this file
                // anyway, and yarn.lock 'resolutions' would need a yarn run
                // this tool must not start, so both take the immediate path.
                if ($d['eco'] === 'npm' && $d['declared'] === ''
                    && (is_file(dirname($d['abs']) . '/package-lock.json') || is_file(dirname($d['abs']) . '/npm-shrinkwrap.json'))) {
                    $verifications[] = ['keys' => $row['keys'], 'n' => $n, 'dir' => dirname($d['abs']),
                        'pkg' => $d['pkg'], 'spec' => $row['spec'], 'ver' => $d['ver'],
                        'target' => $d['target'], 'via' => $d['via']];
                    continue;
                }
                $applied += $n;
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

        $this->needsMajor += $majorRows;  // triage may already have counted PR majors this run
        $bad              = $noValidFix > 0 ? " no-valid-fix={$noValidFix}" : '';
        if (!$write) {
            $this->readyFixes = $edits;
            $c->info("auto-fix (check mode, in records): would-apply={$applied} already-ok={$satisfied} not-declared={$notDeclared}"
                . " missing-manifest={$missing} cannot-edit={$unsupported} needs-major={$major}{$bad}{$rest}"
                . ". {$edits} manifest edit(s); use --update to apply.");
            return;
        }
        // Every override written above now faces the lockfile: re-resolve it
        // and count the edit applied only when the vulnerable copy is gone.
        $notEvicted = $lockUnreadable = 0;
        foreach ($this->verifyOverrides($verifications) as $v) {
            if ($v['unreadable']) {
                // An absent or undecodable lock says nothing: an empty read
                // is a "not found", and "not found" must not stand in for
                // "evicted and applied"
                $lockUnreadable += $v['n'];
                $c->warn("  npm {$v['pkg']} -> {$v['ver']} in {$v['target']}: lock unreadable, not verified");
                foreach ($v['keys'] as $key) {
                    $updates[] = ['key' => $key, 'state' => 'pending', 'note' => 'lock unreadable, not verified'];
                }
                continue;
            }
            if ($v['still'] === []) {
                $applied += $v['n'];
                $c->ok("  npm {$v['pkg']} -> {$v['ver']} in {$v['target']}{$v['via']} (verified in the lockfile)");
                $this->appliedFixes[] = "npm {$v['pkg']} -> {$v['ver']} in {$v['target']}";
                foreach ($v['keys'] as $key) {
                    $updates[] = ['key' => $key, 'state' => 'applied', 'note' => "set to {$v['ver']} in {$v['target']} (override verified in the lockfile)"];
                }
                continue;
            }
            $still      = implode(', ', $v['still']);
            $notEvicted += $v['n'];
            $c->warn("  npm {$v['pkg']} -> {$v['ver']} in {$v['target']}: override written but lock still resolves {$v['pkg']}@{$still}");
            foreach ($v['keys'] as $key) {
                $updates[] = ['key' => $key, 'state' => 'pending', 'note' => "override written but lock still resolves {$v['pkg']}@{$still}"];
            }
        }
        $bad .= $notEvicted > 0 ? " override-not-evicted={$notEvicted}" : '';
        $bad .= $lockUnreadable > 0 ? " lock-unreadable={$lockUnreadable}" : '';
        $this->saveDb(VulnDb::applyStates($db, $updates, $this->now));

        $c->info("auto-fix (in records): applied={$applied} already-ok={$satisfied} not-declared={$notDeclared} missing-manifest={$missing}"
            . " cannot-edit={$unsupported} needs-major={$major}{$bad}{$rest}; {$edits} manifest edit(s)");
        if ($edits > 0) {
            $this->record('auto-fix', $notEvicted + $lockUnreadable > 0 ? 'WARN' : 'PASS', 0, 0,
                "{$edits} edit(s)" . ($notEvicted > 0 ? ", {$notEvicted} override(s) not evicted from the lockfile" : '')
                . ($lockUnreadable > 0 ? ", {$lockUnreadable} override(s) not verified (lock unreadable)" : ''));
            if (!$this->opt->push) {
                $c->warn("Manifests were modified in {$this->root} — review 'git diff' before committing");
            }
        } else {
            $this->record('auto-fix', 'SKIP');
        }
    }

    /**
     * Re-resolve each lockfile an override edit touched (`npm install
     * --package-lock-only`, update mode only — the write path that got us
     * here), then report per edit the versions the lock still resolves that
     * do not clear every advisory. A failed install is answered by what the
     * lock says anyway: an override npm could not honour has evicted nothing.
     * A lock that is absent or cannot be decoded at all says nothing, and is
     * reported as unreadable rather than as an empty — verified — dependency
     * tree.
     *
     * @param list<array{keys: list<string>, n: int, dir: string, pkg: string, spec: array<string, list<string>>, ver: string, target: string, via: string}> $verifications
     * @return list<array{n: int, keys: list<string>, pkg: string, ver: string, target: string, via: string, still: list<string>, unreadable: bool}>
     */
    private function verifyOverrides(array $verifications): array
    {
        if ($verifications === []) {
            return [];
        }
        $dirs  = [];
        $quiet = ['--ignore-scripts', '--no-audit', '--no-fund'];
        foreach ($verifications as $v) {
            $dirs[$v['dir']] = true;
        }
        foreach (array_keys($dirs) as $dir) {
            $argv = array_merge(['npm', 'install', '--package-lock-only'], $quiet);
            $r    = $this->ctx->runner->run($argv, $dir, ['label' => "npm verify {$dir}"]);
            if (!$r->ok() && stripos($r->output, 'ERESOLVE') !== false) {
                // the same fallback the auditor uses for a conflicted manifest
                $this->ctx->runner->run(array_merge($argv, ['--legacy-peer-deps']), $dir, ['label' => "npm verify {$dir}"]);
            }
        }
        $out = [];
        foreach ($verifications as $v) {
            $locked     = Lockfile::versions($v['dir'], 'npm', $v['pkg']);
            $unreadable = $locked === null || Lockfile::unreadable($v['dir'], 'npm');
            $still      = [];
            if (!$unreadable) {
                foreach ($locked as $version) {
                    if (!Version::clearsAll($version, $v['spec'])) {
                        $still[] = $version;
                    }
                }
            }
            $out[] = ['n' => $v['n'], 'keys' => $v['keys'], 'pkg' => $v['pkg'], 'ver' => $v['ver'],
                'target' => $v['target'], 'via' => $v['via'], 'still' => array_values(array_unique($still)),
                'unreadable' => $unreadable];
        }
        return $out;
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

        $db      = $this->loadDb();
        $byIssue = FixPlanner::issueRequirements($db);
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
        // Cross-run memory: a verdict younger than the reuse window stands
        // while the files it read are untouched since it was drawn, so a
        // re-run pays per changed manifest, not per open issue.
        $state   = $this->closeState();
        $changed = $this->changedSinceChecks($state);
        $meta    = FixPlanner::issueMeta($db);
        $lister  = $this->dirLister();
        $verify  = [$verifier, 'verify'];

        $closed = $unresolved = $unverifiable = $rateLimited = $outOfScope = $cached = $shared = 0;
        $whyUnverifiable = [];
        /** @var array<string, array{ok: bool, reason: string, detail: string, evidence: string}> $batch */
        $batch = [];
        /** @var list<array{ref: string, days: int, entry: array<string, mixed>}> $annotate */
        $annotate = [];
        foreach ($byIssue as $ref => $needs) {
            $refNum = (string)$ref;
            $entry  = $state->get($refNum);
            $age    = PrTriageState::secondsSince((string)($entry['checked_at'] ?? ''), $this->now);
            [$verdict, $origin] = CloseState::resolve(
                $needs,
                $entry,
                $age,
                $changed === null || $this->entryPathsTouched($entry, $changed),
                $this->lockfileAppeared($entry),
                $verify,
                $batch
            );
            ['ok' => $ok, 'reason' => $reason, 'detail' => $detail, 'evidence' => $evidence] = $verdict;
            match ($origin) {
                'cached' => $cached++,
                'shared' => $shared++,
                default  => null,
            };
            if ($origin !== 'cached' && $changed !== null) {
                // Remember what this run verified — but only while every file
                // the verdict leans on is clean: a verdict drawn from an
                // uncommitted edit would outlive it (the edit reverted, the
                // memory kept), and reuse would then rest on nothing.
                $paths = $this->needsPaths($needs, $lister);
                $head  = (string)$this->headSha();   // set: $changed !== null answers for it
                if ($head !== '' && !self::pathsTouched($paths, $changed)) {
                    $m = $meta[$ref] ?? ['title' => '', 'cve' => '', 'package' => ''];
                    $state->remember($refNum, $ok ? 'fixed' : $reason, [
                        'key'        => CloseState::key($needs),
                        'head'       => $head,
                        'why'        => $reason === 'unverifiable' ? self::unverifiableWhy($detail) : '',
                        'detail'     => mb_substr($detail, 0, 240),
                        'evidence'   => $ok ? mb_substr($evidence, 0, 4000) : '',
                        'paths'      => $paths,
                        'title_hash' => $m['title'] !== '' ? substr(sha1($m['title']), 0, 12) : '',
                        'cve'        => $m['cve'],
                        'package'    => $m['package'] !== '' ? $m['package'] : (string)($needs[0]['package'] ?? ''),
                    ]);
                }
            }
            if (!$ok) {
                match ($reason) {
                    'unresolved'   => $unresolved++,
                    'out-of-scope' => $outOfScope++,
                    default        => $unverifiable++,
                };
                if ($reason === 'unverifiable') {
                    $why = $origin === 'cached' && ($entry['why'] ?? '') !== '' ? (string)$entry['why'] : self::unverifiableWhy($detail);
                    $whyUnverifiable[$why] = ($whyUnverifiable[$why] ?? 0) + 1;
                    // An issue unverifiable for over a week gets one comment
                    // saying what the repository is missing. It ages on
                    // `since`, which re-verification does not reset.
                    $sinceAge = PrTriageState::secondsSince((string)($entry['since'] ?? ''), $this->now);
                    if (CloseState::needsAnnotation($entry, $sinceAge)) {
                        $annotate[] = ['ref' => $refNum, 'days' => intdiv((int)$sinceAge, 86400), 'entry' => $entry];
                    }
                }
                if ($this->opt->debug) {
                    $c->info("  #{$ref} " . ($reason === 'unresolved' ? 'still open' : $reason) . ($origin === 'cached' ? ' (cached)' : '') . ": {$detail}");
                }
                continue;
            }
            if (!$update) {
                $c->info("  would close #{$ref} (all fixes verified)" . ($origin === 'cached' ? ', from the remembered verdict' : ''));
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
                    $c->ok("  closed #{$ref} (all fixes verified)" . ($origin === 'cached' ? ', from the remembered verdict' : ''));
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
            // (0 means uncapped, matching the help text: only a positive
            // limit can cut the loop short)
            if ($this->opt->closeLimit > 0 && $closed >= $this->opt->closeLimit) {
                $c->info("close-fixed: reached --close-limit {$this->opt->closeLimit}; re-run to continue");
                break;
            }
        }
        // A listing run closed nothing, and must not say it did
        $tally = $update ? "closed={$closed}" : "would-close={$this->wouldClose}";
        arsort($whyUnverifiable);
        $c->info("close-fixed: {$tally} still-vulnerable={$unresolved} unverifiable={$unverifiable} rate-limited={$rateLimited} cached={$cached}"
            . ($shared > 0 ? " shared-checks={$shared}" : '')
            . ($this->target->subdir !== '' ? " outside-subdir={$outOfScope}" : '')
            . ($whyUnverifiable !== [] ? ' (unverifiable: ' . implode(', ', array_map(static fn ($k, $n) => "{$n} {$k}", array_keys($whyUnverifiable), $whyUnverifiable)) . ')' : ''));
        $dupes = FixPlanner::duplicateTitles($byIssue, $meta);
        if ($dupes['issues'] > 0) {
            $top = implode(', ', array_map(static fn (array $t): string => '"' . $t['title'] . '" x' . $t['count'], $dupes['titles']));
            $c->info("close-fixed: {$dupes['issues']} duplicate-title issues (>2 per title) — consider closing dupes as duplicates on the tracker: {$top}");
        }
        $this->annotateUnverifiable($repo, $annotate, $update && $this->opt->push);
        // Issues GitHub no longer lists as open have been closed, by this
        // tool or by anyone else: their memory is spent.
        $state->retain(array_map(static fn (int $n): string => (string)$n, $open));
        $this->saveCloseState();
        $this->notFixedSection($db);
        $this->record('close-fixed', 'PASS', 0, 0, $update ? "closed {$closed}" : "would close {$this->wouldClose} (not closed)");
    }

    /**
     * Why an unverifiable detail says so, in tally words.
     */
    private static function unverifiableWhy(string $detail): string
    {
        return match (true) {
            str_contains($detail, 'no fixed version')    => 'no fix known',
            str_contains($detail, 'manifest missing')    => 'manifest missing',
            str_contains($detail, 'nor in its lockfile') => 'not declared or locked',
            default                                      => CloseState::TRANSITIVE_WHY,
        };
    }

    /**
     * The files a verdict leans on: every manifest a requirement names, the
     * source manifest a lockfile would stand in for, and every lockfile the
     * verifier may have read there. A change to any of them can change the
     * verdict — a lockfile-only regression must not close on a manifest-only
     * watch. Names that do not exist simply never appear in the changed-set,
     * so watching them is free.
     *
     * @param list<array{manifest: string}>  $needs
     * @param callable(string): list<string> $lister
     * @return list<string>
     */
    private function needsPaths(array $needs, callable $lister): array
    {
        $paths = [];
        foreach ($needs as $need) {
            $manifest = $need['manifest'];
            if ($manifest === '') {
                continue;
            }
            $paths[$manifest] = true;
            $source           = ManifestPaths::sourceManifestFor($manifest, $lister);
            $paths[$source]   = true;
            $dir              = dirname($source);
            $prefix           = $dir === '.' ? '' : $dir . '/';
            foreach (Lockfile::lockNamesFor(ManifestPaths::ecosystemFor($source)) as $lock) {
                $paths[$prefix . $lock] = true;
            }
        }
        $out = array_keys($paths);
        sort($out);
        return $out;
    }

    /**
     * @param array<string, mixed> $entry
     * @param array<string, true>  $changed
     */
    private function entryPathsTouched(array $entry, array $changed): bool
    {
        return self::pathsTouched(array_values(array_filter((array)($entry['paths'] ?? []), 'is_string')), $changed);
    }

    /**
     * @param list<string>        $paths
     * @param array<string, true> $changed
     */
    private static function pathsTouched(array $paths, array $changed): bool
    {
        return array_intersect($paths, array_keys($changed)) !== [];
    }

    /**
     * Whether a cached "transitive, no lockfile" verdict has been overtaken
     * by events: a lockfile now standing where the verifier found none.
     * Without a package name to look for, the answer is unknown, and unknown
     * means re-verify.
     *
     * @param array<string, mixed> $entry
     */
    private function lockfileAppeared(array $entry): bool
    {
        if ((string)($entry['verdict'] ?? '') !== 'unverifiable'
            || (string)($entry['why'] ?? '') !== CloseState::TRANSITIVE_WHY) {
            return false;
        }
        $package = (string)($entry['package'] ?? '');
        if ($package === '') {
            return true;
        }
        foreach ((array)($entry['paths'] ?? []) as $path) {
            if (!is_string($path) || $path === '') {
                continue;
            }
            $eco = ManifestPaths::ecosystemFor($path);
            if (!in_array($eco, ['npm', 'composer'], true)) {
                continue;
            }
            if (Lockfile::versions($this->root . '/' . dirname($path), $eco, $package) !== null) {
                return true;
            }
        }
        return false;
    }

    /**
     * The commit HEAD points at, or null when git will not answer. Read once:
     * verdicts are remembered against it, and the change scan diffs from it.
     */
    private function headSha(): ?string
    {
        if (!$this->headShaRead) {
            $this->headShaRead = true;
            $r = $this->ctx->runner->run(['git', '-C', $this->root, 'rev-parse', 'HEAD'], $this->root, ['timeout' => 30, 'label' => 'git']);
            $sha = trim($r->stdout);
            $this->headSha = $r->ok() && preg_match('/^[0-9a-f]{40,64}$/', $sha) === 1 ? $sha : null;
        }
        return $this->headSha;
    }

    /**
     * Whether this clone still holds the object as a commit.
     */
    private function commitExists(string $sha): bool
    {
        return $this->ctx->runner->run(['git', '-C', $this->root, 'cat-file', '-e', $sha . '^{commit}'], $this->root, ['timeout' => 30, 'label' => 'git'])->ok();
    }

    /**
     * Every path changed since remembered verdicts were drawn: whatever is
     * uncommitted right now, plus — for each remembered verdict — every
     * commit landed since the SHA it was drawn against, read with
     * `git diff --name-only`. SHAs, not dates, because committer dates lie:
     * a fast-forward pull or a `git am` lands old-dated commits that a
     * `git log --since` window never sees. Entries from before SHAs were
     * recorded have nothing to diff from; until re-verification replaces
     * them, the date scan covers the run for those, as it always did.
     * Null when git cannot answer — a shallow clone's history proves nothing
     * about a month of it, and a rewritten one proves nothing about the
     * SHAs in memory — and null means no reuse and no new memory: today's
     * verification stands on its own, never yesterday's verdict on
     * unprovable ground.
     *
     * @return array<string, true>|null
     */
    private function changedSinceChecks(CloseState $state): ?array
    {
        $opt     = ['timeout' => 120, 'label' => 'git'];
        $head    = $this->headSha();
        if ($head === null) {
            return null;
        }
        $shallow = $this->ctx->runner->run(['git', '-C', $this->root, 'rev-parse', '--is-shallow-repository'], $this->root, ['timeout' => 30, 'label' => 'git']);
        if (!$shallow->ok() || trim($shallow->stdout) !== 'false') {
            return null;
        }
        $status = $this->ctx->runner->run(['git', '-C', $this->root, 'status', '--porcelain', '-z', '--untracked-files=all'], $this->root, $opt);
        if (!$status->ok()) {
            return null;
        }
        $changed = [];
        $entries = explode("\0", rtrim($status->stdout, "\0"));
        for ($i = 0; $i < count($entries); $i++) {
            if (strlen($entries[$i]) < 4) {
                continue;
            }
            $changed[substr($entries[$i], 3)] = true;
            // A rename or copy is followed by its original path
            if (in_array($entries[$i][0], ['R', 'C'], true)) {
                $i++;
                if (isset($entries[$i]) && $entries[$i] !== '') {
                    $changed[$entries[$i]] = true;
                }
            }
        }
        $byDate = false;
        foreach ($state->rememberedHeads() as $sha) {
            if ($sha === '') {
                $byDate = true; // an entry from before SHAs were recorded
                continue;
            }
            if (!$this->commitExists($sha)) {
                return null;    // rewritten or collected history proves nothing
            }
            // --no-renames: a watched path renamed away must still list its
            // source side, or the move would hide from the verdict it guards
            $diff = $this->ctx->runner->run(['git', '-C', $this->root, 'diff', '--no-renames', '--name-only', $sha, $head], $this->root, $opt);
            if (!$diff->ok()) {
                return null;
            }
            foreach (preg_split('/\R/', $diff->stdout) ?: [] as $line) {
                $line = trim($line);
                if ($line !== '') {
                    $changed[$line] = true;
                }
            }
        }
        if (!$byDate) {
            return $changed;
        }
        $oldest = $state->oldestCheck();
        if ($oldest === '') {
            return $changed;
        }
        $epoch = strtotime($oldest);
        if ($epoch === false) {
            return null;
        }
        $log = $this->ctx->runner->run(['git', '-C', $this->root, 'log', '--since=@' . ($epoch - 86400), '--pretty=format:', '--name-only', 'HEAD'], $this->root, $opt);
        if (!$log->ok()) {
            return null;
        }
        foreach (preg_split('/\R/', $log->stdout) ?: [] as $line) {
            $line = trim($line);
            if ($line !== '') {
                $changed[$line] = true;
            }
        }
        return $changed;
    }

    /**
     * Tell the issues that have been unverifiable for over a week exactly
     * what the repository is missing — once. The comment is a write, so it
     * rides on --push; without it the intention is only logged, and the
     * memory stays unmarked so a later pushing run can still annotate.
     *
     * @param list<array{ref: string, days: int, entry: array<string, mixed>}> $annotate
     */
    private function annotateUnverifiable(string $repo, array $annotate, bool $write): int
    {
        if ($annotate === []) {
            return 0;
        }
        $c   = $this->console;
        $log = 0;
        foreach ($annotate as $a) {
            if (!$write) {
                $log++;
                if ($log <= 10) {
                    $c->info("close-fixed: #{$a['ref']} has been unverifiable for {$a['days']} days — would annotate (run with --push to post)");
                }
                continue;
            }
            $body = self::unverifiableNote($a['entry'], $a['days']);
            if ($this->gh()->run(['issue', 'comment', $a['ref'], '--repo', $repo, '--body', $body], 120)->ok()) {
                $this->closeState()->markAnnotated($a['ref']);
                $c->ok("  annotated #{$a['ref']} (unverifiable {$a['days']}d)");
            } else {
                $c->warn("  could not annotate #{$a['ref']}");
            }
        }
        if (!$write && $log > 10) {
            $c->info('close-fixed: ' . ($log - 10) . ' more long-unverifiable issue(s) would be annotated');
        }
        return count($annotate);
    }

    /**
     * The one-shot comment body: what the check needs that the repository
     * does not have, phrased per reason.
     *
     * @param array<string, mixed> $entry
     */
    public static function unverifiableNote(array $entry, int $days): string
    {
        $why      = (string)($entry['why'] ?? '');
        $package  = (string)($entry['package'] ?? '');
        $dirs     = self::entryDirs($entry);
        $what     = $package !== '' ? "`{$package}`" : 'This dependency';
        $sentence = match ($why) {
            CloseState::TRANSITIVE_WHY => $what . ' is transitive, and ' . $dirs . ' hold no lockfile to verify against'
                . ': commit a lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml or composer.lock) there, or fix it manually.',
            'no fix known'           => 'no fixed version is known upstream for ' . $what . '; watch the advisory, or replace the package.',
            'manifest missing'       => 'the manifest this issue names is gone from the branch, so there is nothing to verify against; close it manually once the removal is confirmed.',
            'not declared or locked' => $what . ' is neither declared nor locked where the issue expects it; the issue text may name the wrong manifest.',
            default                  => ($entry['detail'] ?? '') !== '' ? (string)$entry['detail'] : 'the current manifests cannot confirm or deny it.',
        };
        return "### Not auto-verifiable\n\n"
            . "dep-sec-patcher `--close-fixed` has not been able to verify this issue for {$days} days: {$sentence}\n\n"
            . 'Checked by [dep-sec-patcher](https://github.com/detain/dep-sec-patcher), which closes nothing it cannot verify. '
            . "Once the missing piece exists, a run with `--close-fixed` will decide again.\n\n"
            . '<!-- security-update:unverifiable-note -->';
    }

    /**
     * The directories a remembered verdict was about, for the note.
     *
     * @param array<string, mixed> $entry
     */
    private static function entryDirs(array $entry): string
    {
        $dirs = [];
        foreach ((array)($entry['paths'] ?? []) as $path) {
            if (!is_string($path) || $path === '') {
                continue;
            }
            $dir = dirname($path);
            $dirs[$dir === '.' ? '/' : '/' . ltrim($dir, '/')] = true;
        }
        if ($dirs === []) {
            return 'the project';
        }
        $out = array_keys($dirs);
        sort($out);
        return '`' . implode('`, `', $out) . '`';
    }

    /**
     * The run's diagnostic: everything still open, and the reason it waits.
     * Dependabot alerts by what the bot is or is not doing about them,
     * database records by the note auto-fix left on them.
     *
     * @param array<string, mixed> $db
     */
    private function notFixedSection(array $db): void
    {
        $report = NotFixedReport::build($this->alertBuckets(), $this->databaseBuckets($db));
        if ($report['dependabot_alerts']['total'] === 0 && $report['vuln_db_records']['total'] === 0) {
            return;
        }
        $this->notFixed = $report;
        foreach (NotFixedReport::consoleLines($report) as $line) {
            $this->console->line($line);
        }
    }

    /**
     * Open Dependabot alerts bucketed by why they are still open. Whether a
     * bot PR covers one is only claimed from a complete PR listing; an
     * unproven coverage just leaves the alert in the awaiting bucket.
     *
     * @return array<string, list<array{package: string, ecosystem: string, version: string}>>
     */
    private function alertBuckets(): array
    {
        $alerts = $this->openDependabotAlerts();
        if ($alerts === null) {
            return [];
        }
        $buckets = [];
        foreach ($alerts as $alert) {
            $fixed  = (string)($alert['fixed_version'] ?? '');
            $reason = match (true) {
                $fixed === ''                                                                  => 'no-fix-upstream',
                FixPlanner::alertNeedsMajor((string)($alert['vulnerable_range'] ?? ''), $fixed) => 'needs-major',
                $this->openBotPrs !== null && $this->botPrCovers($alert)                       => 'covered-by-open-PR',
                default                                                                       => 'fix-available-awaiting-bot-PR',
            };
            $buckets[$reason][] = [
                'package'   => (string)($alert['package'] ?? '?'),
                'ecosystem' => (string)($alert['ecosystem'] ?? ''),
                'version'   => $fixed,
            ];
        }
        return $buckets;
    }

    /**
     * Whether an open bot PR is already moving the package this alert is
     * about, in the directory the PR title names.
     *
     * @param array<string, mixed> $alert
     */
    private function botPrCovers(array $alert): bool
    {
        foreach ($this->openBotPrs ?? [] as $pr) {
            $packages = self::prPackages($pr['title'], $pr['body']);
            // the loose cover: a PR anywhere on this package keeps the report
            // from claiming nobody is moving it (the strict one only gates closes)
            if ($packages !== [] && self::alertsCoverPr($packages, self::prDirectory($pr['title']), [$alert])['covered']) {
                return true;
            }
        }
        return false;
    }

    /**
     * Pending and skipped database records bucketed by the note that keeps
     * them there; a record with no fix version needs no note to say so.
     *
     * @param array<string, mixed> $db
     * @return array<string, list<array{package: string, ecosystem: string, version: string}>>
     */
    private function databaseBuckets(array $db): array
    {
        $buckets = [];
        foreach ($db['vulns'] as $v) {
            if (!in_array((string)($v['state'] ?? ''), ['pending', 'skipped'], true)) {
                continue;
            }
            $fixed  = (string)($v['fixed_version'] ?? '');
            $reason = $fixed === '' ? 'no-fix-yet' : NotFixedReport::noteReason((string)($v['note'] ?? ''));
            $buckets[$reason][] = [
                'package'   => (string)($v['package'] ?? '?'),
                'ecosystem' => (string)($v['ecosystem'] ?? ''),
                'version'   => $fixed,
            ];
        }
        return $buckets;
    }

    /**
     * The close memory of this run's repository, read on first use.
     */
    private function closeState(): CloseState
    {
        if ($this->closeState === null) {
            $corrupt = false;
            $this->closeState = CloseState::load($this->closeStateFile, $this->now, $this->repo(), $corrupt);
            if ($corrupt) {
                $this->console->warn("the close state was unreadable and starts fresh: {$this->closeStateFile}");
            }
        }
        return $this->closeState;
    }

    private function saveCloseState(): void
    {
        if ($this->closeState === null) {
            return;
        }
        try {
            $this->closeState->save();
        } catch (RuntimeException $e) {
            if (!$this->closeStateWarned) {
                $this->closeStateWarned = true;
                $this->console->warn("close state cannot be saved ({$e->getMessage()}); this run's verdicts are not remembered");
            }
        }
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
        ] + ($this->postureAttempted ? ['posture_enabled' => $this->postureEnabled] : [])
          + ($this->notFixed === null ? [] : ['not_fixed' => $this->notFixed]);
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
