<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\CloseState;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\FixPlanner;
use Detain\DepSecPatcher\IssueVerifier;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\PrTriageState;
use Detain\DepSecPatcher\SecurityRun;
use Detain\DepSecPatcher\Target;
use Detain\DepSecPatcher\VulnDb;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;

/**
 * What a close-fixed verdict is allowed to rest on: the watched paths it
 * names (manifests and the lockfiles read through them), and the commit it
 * was drawn against. A lockfile-only regression or a late-landing
 * old-dated commit must both re-verify, never close on remembered evidence.
 *
 * @phpstan-type Need array{ecosystem: string, package: string, fixed_version: string, fix_versions: list<string>, manifest: string}
 */
class CloseEvidenceTest extends TestCase
{
    use Fixtures;

    private string $root = '';

    protected function setUp(): void
    {
        $this->hermeticGit();
    }

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    // ── the watched paths (needsPaths) ───────────────────────────────────────

    public function testNeedsPathsWatchesTheLockfilesTheVerifierMayRead(): void
    {
        $run   = $this->secRun($this->plainRoot());
        $needs = [
            ['ecosystem' => 'npm', 'package' => 'qs', 'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'], 'manifest' => 'a/package.json'],
            ['ecosystem' => 'composer', 'package' => 'x/y', 'fixed_version' => '2.0.0', 'fix_versions' => ['2.0.0'], 'manifest' => 'composer.json'],
            ['ecosystem' => 'pip', 'package' => 'urllib3', 'fixed_version' => '2.0.0', 'fix_versions' => ['2.0.0'], 'manifest' => 'requirements.txt'],
            ['ecosystem' => 'npm', 'package' => '', 'fixed_version' => '', 'fix_versions' => [], 'manifest' => ''],
        ];
        $paths = $this->call($run, 'needsPaths', [$needs, $this->call($run, 'dirLister')]);
        foreach (['a/package.json', 'a/yarn.lock', 'a/package-lock.json', 'a/npm-shrinkwrap.json', 'a/pnpm-lock.yaml',
            'composer.json', 'composer.lock', 'requirements.txt'] as $expected) {
            $this->assertContains($expected, $paths);
        }
        $this->assertNotContains('./package-lock.json', $paths, 'a root manifest names no ./ prefix');
        $this->assertNotContains('requirements.txt.lock', $paths, 'an ecosystem without lockfiles to read watches none');
        $this->assertNotContains('', $paths, 'an empty manifest names nothing');
        $this->assertSame($paths, $this->call($run, 'needsPaths', [$needs, $this->call($run, 'dirLister')]), 'deterministic: sorted and deduplicated');
    }

    // ── the change scan (changedSinceChecks) ─────────────────────────────────

    public function testALockfileOnlyRegressionInvalidatesTheVerdictItWasDrawnFrom(): void
    {
        $root = $this->gitRoot();
        file_put_contents($root . '/a/package.json', "{\"dependencies\":{\"qs\":\"^6.15.2\"}}\n");
        file_put_contents($root . '/a/package-lock.json', $this->npmLock('6.15.2'));
        $this->git($root, ['add', '--all']);
        $this->git($root, ['commit', '--quiet', '-m', 'qs fixed and locked']);
        $headA = trim($this->git($root, ['rev-parse', 'HEAD']));

        $run   = $this->secRun($root);
        $needs = $this->qsNeeds();
        $paths = $this->call($run, 'needsPaths', [$needs, $this->call($run, 'dirLister')]);
        $this->assertContains('a/package-lock.json', $paths, 'a verdict read through the lock must watch it');

        $state = $this->state($root, $headA, $needs, $paths);
        // the lockfile alone regresses, committed cleanly
        file_put_contents($root . '/a/package-lock.json', $this->npmLock('6.11.0'));
        $this->git($root, ['commit', '--quiet', '-am', 'lock regressed']);

        $changed = $this->call($run, 'changedSinceChecks', [$state]);
        $this->assertIsArray($changed);
        $this->assertArrayHasKey('a/package-lock.json', $changed);
        $this->assertTrue($this->call($run, 'entryPathsTouched', [$state->get('5'), $changed]),
            'the remembered verdict notices its lockfile changed');

        // and the full chain: reuse is refused, the fresh check sees the
        // vulnerable lock, and nothing closes
        $verdicts = $this->resolveWithMemory($root, $state->get('5'), $needs, $changed);
        $this->assertSame('verified', $verdicts['origin'], 'the cached verdict was not trusted');
        $this->assertFalse($verdicts['verdict']['ok'], 'the re-verification reports the lock behind the fix');
        $this->assertSame('unresolved', $verdicts['verdict']['reason']);
    }

    public function testALateLandingOldDatedCommitIsSeenByTheShaScan(): void
    {
        $root = $this->gitRoot();
        file_put_contents($root . '/a/package.json', "{\"dependencies\":{\"qs\":\"6.15.2\"}}\n");
        $this->git($root, ['add', '--all']);
        $this->git($root, ['commit', '--quiet', '-m', 'initial']);
        $headA = trim($this->git($root, ['rev-parse', 'HEAD']));

        $run   = $this->secRun($root);
        $needs = $this->qsNeeds();
        $paths = $this->call($run, 'needsPaths', [$needs, $this->call($run, 'dirLister')]);
        $state = $this->state($root, $headA, $needs, $paths);

        // a pull lands an old-dated commit: its committer date predates even
        // the day of slack a --since window scans, but its content moved
        $this->setEnv('GIT_AUTHOR_DATE', '2001-01-01T00:00:00 +0000');
        $this->setEnv('GIT_COMMITTER_DATE', '2001-01-01T00:00:00 +0000');
        file_put_contents($root . '/a/package.json', "{\"dependencies\":{\"qs\":\"6.11.0\"}}\n");
        $this->git($root, ['commit', '--quiet', '-am', 'late-arriving old-dated downgrade']);
        $this->setEnv('GIT_AUTHOR_DATE', null);
        $this->setEnv('GIT_COMMITTER_DATE', null);

        $changed = $this->call($run, 'changedSinceChecks', [$state]);
        $this->assertIsArray($changed, 'diffing from the recorded sha answers what dating cannot');
        $this->assertArrayHasKey('a/package.json', $changed);
        $this->assertTrue($this->call($run, 'entryPathsTouched', [$state->get('5'), $changed]));
    }

    public function testAnUnreachableRememberedShaFailsClosedForTheRun(): void
    {
        $root  = $this->gitRoot();
        $run   = $this->secRun($root);
        $needs = $this->qsNeeds();
        $paths = $this->call($run, 'needsPaths', [$needs, $this->call($run, 'dirLister')]);
        // a rewritten or collected history: the object this clone no longer holds
        $state = $this->state($root, str_repeat('01', 20), $needs, $paths);
        $this->assertNull($this->call($run, 'changedSinceChecks', [$state]),
            'no reuse and no new memory: the verdict re-earns itself blindly');
    }

    public function testAnEntryFromBeforeShasWereStoredStillScansByDate(): void
    {
        $root = $this->gitRoot();
        file_put_contents($root . '/a/package.json', "{\"dependencies\":{\"qs\":\"6.15.2\"}}\n");
        $this->git($root, ['add', '--all']);
        $this->git($root, ['commit', '--quiet', '-m', 'initial']);

        $run   = $this->secRun($root);
        $needs = $this->qsNeeds();
        $paths = $this->call($run, 'needsPaths', [$needs, $this->call($run, 'dirLister')]);
        $state = $this->state($root, '', $needs, $paths); // head '' — the pre-upgrade shape

        file_put_contents($root . '/a/package.json', "{\"dependencies\":{\"qs\":\"6.11.0\"}}\n");
        $this->git($root, ['commit', '--quiet', '-am', 'a commit dated today']);

        $changed = $this->call($run, 'changedSinceChecks', [$state]);
        $this->assertIsArray($changed, 'the transitional date scan covers entries that name no sha');
        $this->assertArrayHasKey('a/package.json', $changed);
    }

    public function testANewWorkingTreeScansNothing(): void
    {
        $root = $this->gitRoot();
        $this->git($root, ['commit', '--quiet', '--allow-empty', '-m', 'empty']);
        $run   = $this->secRun($root);
        $state = CloseState::load($root . '/state/close.json', gmdate('Y-m-d\TH:i:s\Z'), 'o/r');
        $this->assertSame([], $this->call($run, 'changedSinceChecks', [$state]),
            'git answers, and there is simply nothing changed and nothing remembered');
    }

    // ── the unreadable lockfile (verifyOverrides) ────────────────────────────

    public function testAnUnreadableLockIsNotAnEvictedPackage(): void
    {
        $root = $this->plainRoot();
        $log  = $this->shim('npm', "#!/bin/sh\necho npm \"\$*\" >> '__LOG__'\n");
        file_put_contents($root . '/a/package.json', "{\"dependencies\":{}}\n");
        file_put_contents($root . '/a/package-lock.json', "{ not json, truncated by an interrupted write");
        mkdir($root . '/b', 0775, true);
        file_put_contents($root . '/b/package.json', "{\"dependencies\":{}}\n");
        mkdir($root . '/c', 0775, true);
        file_put_contents($root . '/c/package.json', "{\"dependencies\":{}}\n");
        file_put_contents($root . '/c/package-lock.json', $this->npmLock('6.11.0'));

        $rows = $this->call($this->secRun($root), 'verifyOverrides', [[
            $this->verification('a'),
            $this->verification('b'),
            $this->verification('c'),
        ]]);
        $this->callsContain($log, 'npm install --package-lock-only');
        $byDir = [];
        foreach ($rows as $row) {
            $byDir[$row['target']] = $row;
        }
        $this->assertTrue($byDir['a/package.json']['unreadable'], 'a lock that cannot decode says nothing, least of all "evicted"');
        $this->assertSame([], $byDir['a/package.json']['still'], 'and is never reported as versions that survived');
        $this->assertTrue($byDir['b/package.json']['unreadable'], 'a lock deleted under the edit says nothing either');
        $this->assertFalse($byDir['c/package.json']['unreadable']);
        $this->assertSame(['6.11.0'], $byDir['c/package.json']['still'], 'a readable lock keeps answering as before');
    }

    // ── needs-major tally (applyFixes) ───────────────────────────────────────

    public function testAutoFixAddsToTheNeedsMajorTheTriageAlreadyCounted(): void
    {
        $root = $this->gitRoot();
        file_put_contents($root . '/a/package.json', "{\"dependencies\":{\"qs\":\"6.11.0\"}}\n");
        $dbFile = $root . '/vulns.json';
        VulnDb::save($dbFile, VulnDb::upsert(VulnDb::empty(), [[
            'key' => 'a/package.json|qs|CVE-1', 'source' => 'issue', 'id' => 'CVE-1', 'ref' => 5, 'refs' => [5],
            'ecosystem' => 'npm', 'package' => 'qs', 'manifest' => 'a/package.json',
            'fixed_version' => '7.0.0', 'fix_versions' => ['7.0.0'],
        ]], '2026-01-01T00:00:00Z', 'o/r'));

        $run = $this->secRun($root, $dbFile);
        (new ReflectionProperty(SecurityRun::class, 'needsMajor'))->setValue($run, 2); // two majors counted from PR titles pre-run
        $this->call($run, 'applyFixes');
        $this->assertSame(3, (new ReflectionProperty(SecurityRun::class, 'needsMajor'))->getValue($run),
            'the auto-fix tally joins the run, it does not replace it');
    }

    // ── the rebase throttle against a skewed clock ───────────────────────────

    public function testAHeadDatedAheadOfOurClockCannotResetTheRebaseCount(): void
    {
        $root    = $this->plainRoot();
        $stateAt = $root . '/state/triage.json';
        $state   = PrTriageState::load($stateAt, gmdate('Y-m-d\TH:i:s\Z'), 'o/r');
        $state->record('9', ['outcome' => 'rebase-requested', 'rebase_requests' => 2]);
        $state->save();
        $run = $this->secRun($root, '', '', $stateAt);

        $future = ['comments' => [], 'commits' => [['committedDate' => gmdate('Y-m-d\TH:i:s\Z', time() + 7200)]]];
        $fields = $this->call($run, 'firstRebaseRequest', ['9', $future]);
        $this->assertSame(2, $fields['rebase_requests'], 'a hot committer clock keeps counting, it does not re-start the throttle');

        $past = ['comments' => [], 'commits' => [['committedDate' => gmdate('Y-m-d\TH:i:s\Z', time() - 7200)]]];
        $this->assertSame(1, $this->call($run, 'firstRebaseRequest', ['9', $past])['rebase_requests'],
            'a commit from before now is a real push: the answer starts a fresh cycle');
        $this->assertSame(1, $this->call($run, 'firstRebaseRequest', ['404', $future])['rebase_requests'],
            'a PR never asked before counts its first request as one');
    }

    public function testTheSupersedeClaimStatesTheAlertListNotItsCause(): void
    {
        $this->assertSame('no open Dependabot alert covers these packages anymore', SecurityRun::supersedeClaim());
    }

    // ── harness ──────────────────────────────────────────────────────────────

    /**
     * @param list<Need> $needs
     * @param list<string> $paths
     */
    private function state(string $root, string $head, array $needs, array $paths): CloseState
    {
        $state = CloseState::load($root . '/state/close.json', gmdate('Y-m-d\TH:i:s\Z'), 'o/r');
        $state->remember('5', 'fixed', [
            'key'   => CloseState::key($needs),
            'head'  => $head,
            'paths' => $paths,
        ]);
        return $state;
    }

    /**
     * The loop close-fixed runs: reuse only when the memory and the change
     * scan both allow it.
     *
     * @param array<string, mixed> $entry
     * @param list<Need>           $needs
     * @param array<string, true>  $changed
     * @return array{verdict: array<string, mixed>, origin: string}
     */
    private function resolveWithMemory(string $root, array $entry, array $needs, array $changed): array
    {
        $verifier = new IssueVerifier($root, $this->lister($root), static fn (string $m): bool => true);
        $batch    = [];
        [$verdict, $origin] = CloseState::resolve(
            $needs,
            $entry,
            0,
            $this->call($this->secRun($root), 'entryPathsTouched', [$entry, $changed]),
            false,
            static fn (array $n): array => $verifier->verify($n),
            $batch
        );
        return ['verdict' => $verdict, 'origin' => $origin];
    }

    /**
     * @return list<Need>
     */
    private function qsNeeds(): array
    {
        return FixPlanner::issueRequirements(['vulns' => [[
            'key' => 'a/package.json|qs|CVE-1', 'source' => 'issue', 'id' => 'CVE-1', 'ref' => 5,
            'ecosystem' => 'npm', 'package' => 'qs', 'manifest' => 'a/package.json',
            'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'], 'state' => 'open',
        ]]])['5'];
    }

    private function npmLock(string $qsVersion): string
    {
        return json_encode([
            'name' => 'a', 'lockfileVersion' => 3,
            'packages' => ['' => ['dependencies' => ['qs' => '^6.15.2']], 'node_modules/qs' => ['version' => $qsVersion]],
        ], JSON_PRETTY_PRINT) . "\n";
    }

    /**
     * One queued override edit: package qs, dir under the test root.
     *
     * @return array{keys: list<string>, n: int, dir: string, pkg: string, spec: array<string, list<string>>, ver: string, target: string, via: string}
     */
    private function verification(string $dir): array
    {
        $root = $this->root;
        return [
            'keys' => [$dir . '/package.json|qs|CVE-1'], 'n' => 1, 'dir' => $root . '/' . $dir,
            'pkg' => 'qs', 'spec' => ['CVE-1' => ['6.15.2']], 'ver' => '6.15.2',
            'target' => $dir . '/package.json', 'via' => '',
        ];
    }

    /**
     * A directory that is not a git repository: for the tests that need only
     * the tree and the harness. The a/ subdirectory exists because most
     * fixtures here need a manifest directory below the root.
     */
    private function plainRoot(): string
    {
        $this->root = $this->scratchDir('evidence');
        mkdir($this->root . '/a', 0775, true);
        return $this->root;
    }

    private function gitRoot(): string
    {
        $this->root = $this->scratchDir('evidence');
        mkdir($this->root . '/a', 0775, true);
        $this->git($this->root, ['init', '--quiet', '--initial-branch=main']);
        return $this->root;
    }

    private function lister(string $root): callable
    {
        return static function (string $dir) use ($root): array {
            $entries = @scandir($dir === '' ? $root : $root . '/' . $dir);
            return $entries === false ? [] : array_values(array_diff($entries, ['.', '..']));
        };
    }

    private function secRun(string $root, string $vulnDb = '', string $closeStateFile = '', string $triageStateFile = ''): SecurityRun
    {
        [$console, $runner] = $this->quietRunner(60);
        $opt     = Options::parse(['--close-fixed'], []);
        $reports = $root . '/reports';
        $run     = new SecurityRun($opt, $console, new Target($root), $vulnDb, $reports, '', [], '', $triageStateFile, $closeStateFile);
        (new ReflectionProperty(SecurityRun::class, 'ctx'))
            ->setValue($run, new Context($opt, $console, $runner, $root, $reports, ManifestIndex::fromList($root, [])));
        return $run;
    }

    /**
     * @param list<mixed> $args
     */
    private function call(object $subject, string $method, array $args = []): mixed
    {
        $m = new ReflectionMethod($subject, $method);
        return $m->invoke($subject, ...$args);
    }

    private function shim(string $tool, string $body): string
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/' . $tool, str_replace('__LOG__', escapeshellarg($log), $body) . "\n");
        chmod($bin . '/' . $tool, 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        touch($log);
        return $log;
    }

    private function callsContain(string $log, string $needle): void
    {
        $this->assertStringContainsString($needle, implode("\n", file($log, FILE_IGNORE_NEW_LINES) ?: []));
    }
}
