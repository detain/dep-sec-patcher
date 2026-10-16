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
 * One run of update-samples-security: ecosystem audits, scanners, GitHub
 * collection, PR triage, auto-fix, close-fixed, summary.
 */
final class SecurityRun
{
    private const STATUS_RANK = ['SKIP' => 0, 'PASS' => 1, 'WARN' => 2, 'FAIL' => 3];

    /** @var array<string, array{status: string, vulns: int, outdated: int}> */
    private array $summary = [];
    private string $now;
    private ?GitHub $gh = null;
    private Context $ctx;

    /**
     * @param array<string, string>|null $profile resolved parent-project profile
     */
    public function __construct(
        private Options $opt,
        private Console $console,
        private ?array $profile,
        private string $root,
        private string $vulnDb,
        private string $reportDir,
        private string $defaultRepo,
    ) {
        $this->now = gmdate('Y-m-d\TH:i:s\Z');
    }

    public function run(): int
    {
        $c = $this->console;
        if ($this->profile !== null) {
            $c->line('project: ' . $this->profile['profile'] . ' (' . $this->profile['label'] . ')');
        }
        $c->line("root: {$this->root}");
        $c->line("mode: {$this->opt->mode}");
        $c->line("vuln db: {$this->vulnDb}");
        $c->line("reports: {$this->reportDir}");
        $c->line('threads: ' . $this->opt->threads . ', command timeout: '
            . ($this->opt->timeout > 0 ? CommandResult::duration($this->opt->timeout) : 'none'));
        $c->line();

        $runner = new ProcessRunner($c, $this->opt->timeout, $this->opt->verbose, $this->opt->debug);
        $index  = $this->opt->applyStored ? ManifestIndex::fromList($this->root, []) : new ManifestIndex($this->root);
        $this->ctx = new Context($this->opt, $c, $runner, $this->root, $this->reportDir, $index);
        $nvd = $this->opt->nvdApiKey !== '' ? $this->opt->nvdApiKey : TokenHarvester::find('NVD_API_KEY');
        $this->ctx->state['nvd_api_key'] = (string)$nvd;

        if ($this->opt->applyStored) {
            $c->info('Ecosystem updaters: skipped (--apply-stored)');
        } else {
            $this->runEcosystems();
        }

        // Authenticate gh once up front so every GitHub step shares the result
        if ($this->opt->githubEnabled()) {
            $this->gh = new GitHub($runner, $c, $this->root);
            $this->gh->ensureAuth();
        }

        $this->runScanners();
        $this->collectGitHub();
        $this->checkRepoSettings();
        $this->triagePullRequests();
        $this->applyFixes();
        $this->closeFixedIssues();

        $this->printSummary();
        $this->writeReport();
        return 0;
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
            }
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
                if ($result->status === TargetResult::SKIP && $dir === '') {
                    // Optional tool pair; absent on most hosts, not worth a SKIP line
                    continue;
                }
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
        $found = NetworkScanner::scan($this->ctx->files->files(), NetworkScanner::fileReader($this->root));
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

    private function repo(): string
    {
        return $this->gh?->resolveRepo($this->opt->ghRepo, $this->root, $this->defaultRepo) ?? '';
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
        if (!$this->githubReady()) {
            $c->skip('github (gh unavailable or unauthenticated)');
            $this->record('dependabot', 'SKIP');
            return;
        }
        $repo = $this->repo();
        $c->info("GitHub repository: {$repo}");

        $alerts = $this->gh->paginate("repos/{$repo}/dependabot/alerts?state=open&per_page=100");
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
        $advisories = $this->gh->paginate("repos/{$repo}/security-advisories?per_page=100", $status);
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
        $issues = $this->gh->openIssues($repo, $limit, 'number,title,body,author,url');
        $issueRecords = [];
        if ($issues === null) {
            $c->warn("Could not list issues for {$repo}");
            $this->record('sec-issues', 'SKIP');
        } else {
            $issueRecords = IssueParser::parse($issues);
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
        if ($merged === []) {
            $c->info('No vulnerability records collected');
            return;
        }
        $db = $this->loadDb();
        $db = VulnDb::upsert($db, $merged, $this->now, $this->gh->slug);
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
        if (!$this->githubReady()) {
            $c->skip('gh (unavailable or unauthenticated - cannot check secret scanning)');
            $this->record('secret-scanning', 'SKIP');
            return;
        }
        $c->info('Checking repository security settings...');
        $info = $this->gh->json(['api', 'repos/' . $this->repo()], 60);
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
        if (!$this->githubReady()) {
            $c->skip('PR triage (gh unavailable or unauthenticated)');
            return;
        }
        $repo = $this->repo();
        $c->info("Triaging dependency-bot PRs on {$repo}...");

        $prs = $this->gh->json(['pr', 'list', '--repo', $repo, '--state', 'open', '--limit', '100',
            '--json', 'number,title,author,isDraft,headRefName']);
        if (!is_array($prs)) {
            $c->warn('PR triage: could not list pull requests');
            return;
        }
        // Only touch PRs raised by dependency bots, never a human contributor's work
        $bots = array_values(array_filter($prs, static fn ($pr) => empty($pr['isDraft'])
            && preg_match('/dependabot|renovate|mend|snyk/i', (string)($pr['author']['login'] ?? '')) === 1));
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
            if ($this->opt->mode !== 'update') {
                continue;
            }
            $rebaseCmd = self::rebaseCommand($author);
            if ($mergeable === 'MERGEABLE') {
                if ($status === 'BLOCKED') {
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
                } elseif ($this->gh->run(['pr', 'merge', $num, '--repo', $repo, '--squash', '--delete-branch'])->ok()) {
                    $c->ok("  Merged PR #{$num}");
                    $merged++;
                } elseif ($this->gh->run(['pr', 'merge', $num, '--repo', $repo, '--squash', '--auto', '--delete-branch'])->ok()) {
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
                        $info          = $this->gh->json(['repo', 'view', $repo, '--json', 'defaultBranchRef'], 60);
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
            $data = $this->gh->json(['pr', 'view', $num, '--repo', $repo, '--json', 'mergeable,mergeStateStatus'], 60);
            $m    = (string)($data['mergeable'] ?? '');
            if ($m !== '' && $m !== 'UNKNOWN') {
                return [$m, (string)($data['mergeStateStatus'] ?? 'UNKNOWN')];
            }
            sleep(2);
        }
        return $state;
    }

    /**
     * @return array{comments: list<array<string, mixed>>, commits: list<array<string, mixed>>}
     */
    private function prComments(string $repo, string $num): array
    {
        $data = $this->gh->json(['pr', 'view', $num, '--repo', $repo, '--json', 'comments,commits'], 60);
        return [
            'comments' => is_array($data['comments'] ?? null) ? $data['comments'] : [],
            'commits'  => is_array($data['commits'] ?? null) ? $data['commits'] : [],
        ];
    }

    /**
     * Whether our last rebase request is still outstanding: nothing has been
     * pushed to the branch since we asked. (Comparing against the newest
     * comment would not do: the bot's own reply displaces ours.)
     *
     * @param array{comments: list<array<string, mixed>>, commits: list<array<string, mixed>>}|null $data
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
        return $this->gh->run(['pr', 'comment', $num, '--repo', $repo, '--body', $body . "\n\n<!-- security-update:rebase -->"])->ok();
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
        if ($this->opt->mode !== 'update') {
            $c->info("auto-fix: {$pending} pending fixes (MODE=check, not applying). Use --update to apply.");
            return;
        }
        $c->info("auto-fix: applying {$pending} pending fix(es) from {$this->vulnDb}");

        $lister  = $this->dirLister();
        $updates = [];
        $applied = $missing = $notDeclared = $satisfied = 0;
        foreach (FixPlanner::plan($db) as $row) {
            $target = ManifestPaths::sourceManifestFor($row['manifest'], $lister);
            $via    = $target !== $row['manifest'] ? ' (via ' . basename($row['manifest']) . ')' : '';
            $abs    = $this->root . '/' . $target;

            if (!is_file($abs)) {
                $missing++;
                [$state, $note] = ['skipped', "manifest not found: {$target}"];
            } else {
                $content  = (string)file_get_contents($abs);
                $declared = ManifestEditor::declared($row['ecosystem'], $target, $content, $row['package']);
                $ver      = Version::chooseTarget($declared, $row['spec'], $row['pkg_max']);
                if ($ver === '') {
                    // Every advisory for this package is already cleared
                    $satisfied++;
                    [$state, $note] = ['applied', "already satisfied: {$target} declares {$declared}"];
                } else {
                    $res = ManifestEditor::apply(
                        $row['ecosystem'],
                        $target,
                        $content,
                        $row['package'],
                        $ver,
                        $row['pkg_max'] !== '' ? $row['pkg_max'] : $ver,
                        is_file(dirname($abs) . '/yarn.lock')
                    );
                    if ($res['status'] === ManifestEditor::REFUSED) {
                        $notDeclared++;
                        [$state, $note] = ['skipped', "refused: {$ver} would downgrade the version declared in {$target}"];
                    } elseif ($res['content'] !== $content && file_put_contents($abs, $res['content']) !== false) {
                        $applied++;
                        [$state, $note] = ['applied', "set to {$ver} in {$target}"];
                        $c->ok("  {$row['ecosystem']} {$row['package']} -> {$ver} in {$target}{$via}");
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
        $this->saveDb(VulnDb::applyStates($db, $updates, $this->now));

        $c->info("auto-fix: applied={$applied} already-ok={$satisfied} not-declared={$notDeclared} missing-manifest={$missing}");
        if ($applied > 0) {
            $this->record('auto-fix', 'PASS', 0, $applied);
            $c->warn("Manifests were modified in {$this->root} — review 'git diff' before committing");
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

        // The repo's existing "security fix" label means a Mend-generated fix
        // PR, so a dedicated marker label is used
        $labelOk = false;
        $label   = $this->opt->closeLabel;
        if ($label !== '') {
            $labels = $this->gh->json(['label', 'list', '--repo', $repo, '--limit', '200', '--json', 'name'], 60);
            if (is_array($labels) && in_array($label, array_column($labels, 'name'), true)) {
                $labelOk = true;
            } elseif ($update && $this->gh->run(['label', 'create', $label, '--repo', $repo, '--color', '0E8A16',
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
        $open = $this->gh->json(['issue', 'list', '--repo', $repo, '--state', 'open', '--limit', '100000', '--json', 'number'], 900);
        if (is_array($open) && $open !== []) {
            $openSet = array_flip(array_map('intval', array_column($open, 'number')));
            $c->info('close-fixed: ' . count($openSet) . ' issues open, ' . count($byIssue) . ' in the database');
            $byIssue = array_intersect_key($byIssue, $openSet);
        } else {
            $c->warn('could not list open issues; falling back to every known ref');
        }
        $c->info('close-fixed: checking ' . count($byIssue) . ' issue(s) against the current manifests');

        $branch = 'master';
        $r = $this->ctx->runner->run(['git', '-C', $this->root, 'rev-parse', '--abbrev-ref', 'HEAD'], $this->root, ['timeout' => 30, 'label' => 'git']);
        if ($r->ok() && trim($r->stdout) !== '') {
            $branch = trim($r->stdout);
        }

        $lister   = $this->dirLister();
        $contents = [];
        $closed = $unresolved = $unverifiable = $rateLimited = 0;
        foreach ($byIssue as $ref => $needs) {
            $ok       = true;
            $reason   = '';
            $detail   = '';
            $evidence = '';
            foreach ($needs as $need) {
                if ($need['package'] === '') {
                    continue;
                }
                $target = ManifestPaths::sourceManifestFor($need['manifest'], $lister);
                $abs    = $this->root . '/' . $target;
                if (!is_file($abs)) {
                    [$ok, $reason, $detail] = [false, 'unverifiable', "manifest missing: {$target}"];
                    break;
                }
                $contents[$abs] ??= (string)file_get_contents($abs);
                $cur = ManifestEditor::declared($need['ecosystem'], $target, $contents[$abs], $need['package']);
                if ($cur === '') {
                    [$ok, $reason, $detail] = [false, 'unverifiable', "{$need['package']} not declared in {$target}"];
                    break;
                }
                if (!FixPlanner::requirementMet($cur, $need)) {
                    [$ok, $reason, $detail] = [false, 'unresolved', "{$need['package']} is " . Version::floor($cur) . ", needs >= {$need['fixed_version']}"];
                    break;
                }
                // Record the evidence so the closing comment shows its working
                $evidence .= "| `{$need['package']}` | {$need['fixed_version']} | **{$cur}** | `{$target}` |\n";
            }

            if (!$ok) {
                $reason === 'unresolved' ? $unresolved++ : $unverifiable++;
                if ($this->opt->debug) {
                    $c->info("  #{$ref} " . ($reason === 'unresolved' ? 'still open' : 'unverifiable') . ": {$detail}");
                }
                continue;
            }
            if (!$update) {
                $c->info("  would close #{$ref} (all fixes verified)");
                $closed++;
                continue;
            }
            // Label first, so the marker survives even if the close fails
            if ($labelOk) {
                $this->gh->run(['issue', 'edit', (string)$ref, '--repo', $repo, '--add-label', $label], 60);
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
                . 'Checked by `scripts/api/update-samples-security.sh --close-fixed`, which reads the version each manifest'
                . " declares rather than assuming an earlier fix succeeded. Reopen if this is wrong.\n\n"
                . '<!-- security-update:closed-verified -->';
            for ($attempt = 1; ; $attempt++) {
                $res = $this->gh->run(['issue', 'close', (string)$ref, '--repo', $repo, '--reason', 'completed', '--comment', $body], 120);
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
        $c->info("close-fixed: closed={$closed} still-vulnerable={$unresolved} unverifiable={$unverifiable} rate-limited={$rateLimited}");
        $this->record('close-fixed', 'PASS', 0, $closed);
    }

    // ── summary & report ─────────────────────────────────────────────────────

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
            'scan_timestamp' => $this->now,
            'root_dir'       => $this->root,
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

    private function dirLister(): callable
    {
        $root = $this->root;
        return static function (string $dir) use ($root): array {
            $entries = @scandir($dir === '' ? $root : $root . '/' . $dir);
            return $entries === false ? [] : array_values(array_diff($entries, ['.', '..']));
        };
    }
}
