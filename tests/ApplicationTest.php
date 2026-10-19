<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\GitUrl;
use Detain\DepSecPatcher\StatePaths;
use Detain\DepSecPatcher\VulnDb;
use PHPUnit\Framework\TestCase;

/**
 * The command end to end, run as a subprocess. Only checks that need no
 * network are enabled (netsec, or --apply-stored), and a local bare
 * repository stands in for a remote.
 */
class ApplicationTest extends TestCase
{
    use Fixtures;

    private string $xdg;

    protected function setUp(): void
    {
        $this->hermeticGit();
        $this->xdg = $this->scratchDir('xdg');
    }

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    /**
     * @param list<string>          $args
     * @param array<string, string> $env
     * @return array{0: int, 1: string} exit code, combined output
     */
    private function cli(array $args, string $cwd, array $env = []): array
    {
        $env  = array_merge(getenv(), ['XDG_STATE_HOME' => $this->xdg, 'NVD_API_KEY' => '', 'GH_TOKEN' => ''], $env);
        // sh merges stderr into stdout, so errors and output arrive in order
        $cmd  = array_merge(['sh', '-c', 'exec "$0" "$@" 2>&1', PHP_BINARY, dirname(__DIR__) . '/bin/dep-sec-patcher'], $args);
        $proc = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w']], $pipes, $cwd, $env);
        $this->assertIsResource($proc);
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        return [proc_close($proc), $out];
    }

    private function project(): string
    {
        $dir = $this->scratchDir('project');
        mkdir($dir . '/conf');
        file_put_contents($dir . '/conf/app.yaml', "url: http://api.vendor.test/v1\n");
        return $dir;
    }

    public function testPlainDirectorySkipsGithubAndKeepsStateOutside(): void
    {
        $dir = $this->project();
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec'], $dir);
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('github repo: none (the target is not a git checkout)', $out);
        $this->assertStringContainsString('[SKIP] github (no GitHub repository: the target is not a git checkout; pass --repo OWNER/NAME)', $out);
        $this->assertStringContainsString('[WARN] netsec: 1 config files reference plain-HTTP endpoints: conf/app.yaml', $out);

        $state = $this->xdg . '/dep-sec-patcher/' . StatePaths::slug('', $dir);
        $this->assertFileExists($state . '/reports/security-scan-report.json');
        $this->assertFileDoesNotExist($state . '/run.lock', 'the lock is deleted when the run ends');
        $report = json_decode((string)file_get_contents($state . '/reports/security-scan-report.json'), true);
        $this->assertIsArray($report);
        $this->assertSame('WARN', $report['ecosystems']['network-security']['status']);
        $this->assertSame('', $report['github_repo']);
        $this->assertSame(['conf'], array_values(array_diff(scandir($dir) ?: [], ['.', '..'])), 'nothing written into the tree');
    }

    public function testStrictExitCodeAndAllowHttp(): void
    {
        $dir = $this->project();
        [$rc] = $this->cli(['--check', '--only', 'netsec', '--strict', '--allow-http', 'api.vendor.test/'], $dir);
        $this->assertSame(0, $rc, 'allowed host: nothing fails');

        file_put_contents($dir . '/settings.py', "password = 'hunter2-real'\n");
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--strict', $dir], '/');
        $this->assertSame(3, $rc, $out);
        $this->assertStringContainsString('[FAIL] netsec: possible hardcoded credentials', $out);
        [$rc] = $this->cli(['--check', '--only', 'netsec', $dir], '/');
        $this->assertSame(0, $rc, 'without --strict a completed run exits 0');
    }

    public function testConfigFileIsAppliedAndValidated(): void
    {
        $dir = $this->project();
        file_put_contents($dir . '/.dep-sec-patcher.json', json_encode(['only' => ['netsec'], 'allow-http' => ['api.vendor.test/']]));
        [$rc, $out] = $this->cli(['--check'], $dir);
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('config: ' . $dir . '/.dep-sec-patcher.json', $out);
        $this->assertStringContainsString('[OK]   netsec: no plain-HTTP endpoints', $out);

        file_put_contents($dir . '/.dep-sec-patcher.json', '{"threds": 4}');
        [$rc, $out] = $this->cli(['--check'], $dir);
        $this->assertSame(1, $rc);
        $this->assertStringContainsString($dir . '/.dep-sec-patcher.json: unknown key "threds"', $out);

        $alt = $this->scratchDir('cfg') . '/alt.json';
        file_put_contents($alt, '{"only": ["netsec"], "scanners": {"netsec": false}}');
        [$rc, $out] = $this->cli(['--check', '--config', $alt, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringNotContainsString('netsec:', $out, '--config wins over the file in the target');
    }

    public function testStateInsideTheTreeIsRefused(): void
    {
        $dir = $this->project();
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--state-dir', $dir . '/.state'], $dir);
        $this->assertSame(1, $rc);
        $this->assertStringContainsString('must be outside the scanned tree', $out);
        $this->assertDirectoryDoesNotExist($dir . '/.state', 'refused before anything was created');

        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--report-dir', 'conf/reports'], $dir);
        $this->assertSame(1, $rc);
        $this->assertStringContainsString('report directory', $out);
    }

    public function testUsageErrors(): void
    {
        $dir = $this->project();
        foreach ([
            [['--profile', 'my'], 'unknown option: --profile'],
            [['no/such/thing/here'], 'target not found'],
            [['--subdir', 'missing'], '--subdir not found'],
            [['--repo', 'not a repo'], '--repo must be OWNER/NAME'],
        ] as [$args, $message]) {
            [$rc, $out] = $this->cli($args, $dir);
            $this->assertSame(1, $rc, implode(' ', $args));
            $this->assertStringContainsString($message, $out);
        }
        [$rc, $out] = $this->cli(['--help'], $dir);
        $this->assertSame(0, $rc);
        $this->assertStringContainsString('Usage: dep-sec-patcher [OPTIONS] [TARGET]', $out);
    }

    public function testRunLock(): void
    {
        $dir   = $this->project();
        $state = $this->scratchDir('state');
        $lock  = fopen($state . '/run.lock', 'c+');
        $this->assertIsResource($lock);
        $this->assertTrue(flock($lock, LOCK_EX | LOCK_NB));
        fwrite($lock, '424242');
        fflush($lock);
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--state-dir', $state], $dir);
        $this->assertFileExists($state . '/run.lock', "the other run's lock is left alone");
        flock($lock, LOCK_UN);
        fclose($lock);
        $this->assertSame(1, $rc);
        $this->assertStringContainsString('another run is already in progress (pid 424242)', $out);
    }

    public function testNothingIsLeftPerTargetWhenTheReportsGoElsewhere(): void
    {
        $dir     = $this->project();
        $reports = $this->scratchDir('reports');
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--report-dir', $reports], $dir);
        $this->assertSame(0, $rc, $out);
        $this->assertFileExists($reports . '/security-scan-report.json');
        $this->assertSame([], array_values(array_diff(scandir($this->xdg . '/dep-sec-patcher') ?: [], ['.', '..'])));
    }

    public function testADatabaseInTheOldLocationIsMovedOut(): void
    {
        $dir = $this->scratchDir('legacy');
        file_put_contents($dir . '/package.json', "{\"dependencies\": {\"qs\": \"^6.11.0\"}}\n");
        $base = $this->xdg . '/dep-sec-patcher';
        $slug = StatePaths::slug('', $dir);
        $old  = $base . '/' . $slug . '/vulns.json';
        $new  = $base . '/vulns/' . $slug . '.json';
        VulnDb::save($old, VulnDb::upsert(VulnDb::empty(), [[
            'key' => 'package.json|qs|CVE-1', 'source' => 'dependabot', 'id' => 'CVE-1', 'ecosystem' => 'npm',
            'package' => 'qs', 'manifest' => 'package.json', 'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'],
        ]], '2026-01-01T00:00:00Z', ''));

        [$rc, $out] = $this->cli(['--check', '--apply-stored', $dir], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString("moved the vulnerability database from {$old} to {$new}", $out);
        $this->assertStringContainsString("vuln db: {$new}", $out);
        $this->assertStringContainsString('would set npm qs -> 6.15.2 in package.json', $out, 'its records are used');
        $this->assertFileDoesNotExist($old);
        $this->assertArrayHasKey('package.json|qs|CVE-1', VulnDb::load($new)['vulns']);
    }

    public function testOriginRepoSubdirAndSlug(): void
    {
        $remote = $this->makeRemote(['api/conf/a.yaml' => "u: http://api.vendor.test/\n", 'other/b.yaml' => "u: http://x.vendor.test/\n"]);
        $this->git($remote['work'], ['remote', 'set-url', 'origin', 'git@github.com:Acme/Widgets.git']);
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--no-github', '--subdir', 'api', $remote['work']], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('github repo: Acme/Widgets (from the origin remote)', $out);
        $this->assertStringContainsString('subdir: api', $out);
        $this->assertStringContainsString('plain-HTTP endpoints: api/conf/a.yaml', $out, 'paths stay relative to the target root');
        $this->assertStringNotContainsString('other/b.yaml', $out);
        $this->assertDirectoryExists($this->xdg . '/dep-sec-patcher/acme__widgets');
    }

    /**
     * The per-target state directory of a remote target.
     *
     * @param array{bare: string, work: string, url: string} $remote
     */
    private function remoteState(array $remote): string
    {
        return $this->xdg . '/dep-sec-patcher/' . StatePaths::slug('', GitUrl::normalize($remote['url']), GitUrl::basename($remote['url']));
    }

    public function testRemoteTargetCloneIsDeletedWhenTheRunEnds(): void
    {
        $remote = $this->makeRemote([
            'conf/app.yaml'         => "url: http://api.vendor.test/v1\n",
            '.dep-sec-patcher.json' => '{"only": ["netsec"]}',
        ]);
        [$rc, $out] = $this->cli(['--check', $remote['url']], '/');
        $this->assertSame(0, $rc, $out);
        $state = $this->remoteState($remote);
        $clone = $state . '/checkout';
        $this->assertStringContainsString("cloning {$remote['url']} into {$clone}", $out);
        $this->assertStringContainsString('github repo: none (the target URL is not on github.com)', $out);
        $this->assertStringContainsString('config: ' . $clone . '/.dep-sec-patcher.json', $out, 'config read from the clone');
        $this->assertStringContainsString('conf/app.yaml', $out);
        $this->assertStringContainsString("deleted the clone {$clone}", $out);
        $this->assertSame(['reports'], array_values(array_diff(scandir($state) ?: [], ['.', '..'])), 'only the reports are left');
    }

    public function testKeepCloneLeavesAPristineCloneForTheNextRun(): void
    {
        $remote = $this->makeRemote([
            'conf/app.yaml'         => "url: http://api.vendor.test/v1\n",
            '.dep-sec-patcher.json' => '{"only": ["netsec"]}',
        ]);
        [$rc, $out] = $this->cli(['--check', '--keep-clone', $remote['url']], '/');
        $this->assertSame(0, $rc, $out);
        $clone = $this->remoteState($remote) . '/checkout';
        $this->assertStringNotContainsString('deleted the clone', $out);
        $this->assertSame('', $this->git($clone, ['status', '--porcelain', '--ignored']), 'check mode leaves it pristine');

        // The next run refreshes and reuses it, and without --keep-clone deletes it
        [$rc, $out] = $this->cli(['--check', $remote['url']], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('updating the clone of', $out);
        $this->assertStringContainsString("deleted the clone {$clone}", $out);
        $this->assertDirectoryDoesNotExist($clone);
    }

    public function testARunThatFailsAfterCloningStillDeletesTheClone(): void
    {
        $remote = $this->makeRemote();
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--subdir', 'missing', $remote['url']], '/');
        $this->assertSame(1, $rc, $out);
        $this->assertStringContainsString('--subdir not found', $out);
        $this->assertStringContainsString('deleted the clone', $out);
        $this->assertDirectoryDoesNotExist($this->remoteState($remote), 'the lock went too, leaving the directory empty');
    }

    public function testAWorkdirTheToolDidNotCreateIsNeverDeleted(): void
    {
        $remote  = $this->makeRemote();
        $workdir = $this->scratchDir('mine');
        file_put_contents($workdir . '/notes.txt', 'mine');
        [$rc, $out] = $this->cli(['--check', '--only', 'netsec', '--workdir', $workdir, $remote['url']], '/');
        $this->assertSame(1, $rc, $out);
        $this->assertStringContainsString('is not a clone made by dep-sec-patcher', $out);
        $this->assertStringNotContainsString('deleted the clone', $out);
        $this->assertFileExists($workdir . '/notes.txt');
    }

    public function testAnInterruptedRunStillDeletesTheClone(): void
    {
        if (!function_exists('posix_kill') || !function_exists('pcntl_signal')) {
            $this->markTestSkipped('needs the pcntl and posix extensions');
        }
        $remote = $this->makeRemote(['package.json' => "{}\n"]);
        $bin    = $this->scratchDir('bin');
        $marker = $bin . '/started';
        // An npm that hangs, so the run can be stopped in the middle of an audit
        file_put_contents($bin . '/npm', "#!/bin/sh\ntouch " . escapeshellarg($marker) . "\nexec sleep 60\n");
        chmod($bin . '/npm', 0755);
        $env  = array_merge(getenv(), ['XDG_STATE_HOME' => $this->xdg, 'NVD_API_KEY' => '', 'GH_TOKEN' => '',
            'PATH' => $bin . ':' . getenv('PATH')]);
        // exec: the pid signalled below is the tool's, not the shell's
        $cmd  = ['sh', '-c', 'exec "$0" "$@" 2>&1', PHP_BINARY, dirname(__DIR__) . '/bin/dep-sec-patcher', '--check', '--only', 'node', $remote['url']];
        $proc = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w']], $pipes, '/', $env);
        $this->assertIsResource($proc);
        for ($i = 0; $i < 300 && !is_file($marker); $i++) {
            usleep(100000);
        }
        $this->assertFileExists($marker, 'the audit started');
        posix_kill(proc_get_status($proc)['pid'], SIGINT);
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $this->assertSame(130, proc_close($proc), $out);

        $state = $this->remoteState($remote);
        $this->assertStringContainsString("deleted the clone {$state}/checkout", $out);
        $this->assertDirectoryDoesNotExist($state . '/checkout');
        $this->assertFileDoesNotExist($state . '/run.lock');
    }

    public function testUpdateModeAppliesStoredFixesAndPushesABranch(): void
    {
        $remote = $this->makeRemote(['web/package.json' => "{\n  \"dependencies\": {\n    \"qs\": \"^6.11.0\"\n  }\n}\n"]);
        $db     = $this->scratchDir('db') . '/vulns.json';
        VulnDb::save($db, VulnDb::upsert(VulnDb::empty(), [[
            'key' => 'web/package.json|qs|CVE-1', 'source' => 'dependabot', 'id' => 'CVE-1', 'ref' => 1, 'refs' => [1],
            'ecosystem' => 'npm', 'package' => 'qs', 'manifest' => 'web/package.json',
            'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'],
        ]], '2026-01-01T00:00:00Z', ''));

        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--push', '--branch', 'sec/qs', '--vuln-db', $db, $remote['url']], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('npm qs -> 6.15.2 in web/package.json', $out);
        $this->assertStringContainsString('push: pushed branch sec/qs to origin', $out);
        $this->assertStringContainsString('"qs": "^6.15.2"', $this->git($remote['bare'], ['show', 'sec/qs:web/package.json']));
        $this->assertStringContainsString('"qs": "^6.11.0"', $this->git($remote['bare'], ['show', 'main:web/package.json']), 'the default branch is untouched');
        $this->assertSame('applied', VulnDb::load($db)['vulns']['web/package.json|qs|CVE-1']['state']);
    }

    public function testPushRefusesATreeThatWasDirty(): void
    {
        $remote = $this->makeRemote(['web/package.json' => "{\"dependencies\": {\"qs\": \"^6.11.0\"}}\n"]);
        file_put_contents($remote['work'] . '/notes.txt', 'uncommitted work');
        $db = $this->scratchDir('db') . '/vulns.json';
        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--push', '--vuln-db', $db, $remote['work']], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('push: the working tree had uncommitted changes before the run', $out);
        $this->assertSame('', $this->git($remote['bare'], ['branch', '--list', 'dep-sec-patcher/*']));
    }

    public function testPushDirectCommitsOntoTheDefaultBranch(): void
    {
        $remote = $this->makeRemote(['web/package.json' => "{\n  \"dependencies\": {\n    \"qs\": \"^6.11.0\"\n  }\n}\n"]);
        $db     = $this->scratchDir('db') . '/vulns.json';
        VulnDb::save($db, VulnDb::upsert(VulnDb::empty(), [[
            'key' => 'web/package.json|qs|CVE-1', 'source' => 'dependabot', 'id' => 'CVE-1', 'ref' => 1, 'refs' => [1],
            'ecosystem' => 'npm', 'package' => 'qs', 'manifest' => 'web/package.json',
            'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'],
        ]], '2026-01-01T00:00:00Z', ''));

        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--push-direct', '--vuln-db', $db, $remote['url']], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('push: pushed the changes straight to main on origin', $out);
        $this->assertStringContainsString('"qs": "^6.15.2"', $this->git($remote['bare'], ['show', 'main:web/package.json']));
        $msg = $this->git($remote['bare'], ['log', '-1', '--format=%B', 'main']);
        $this->assertStringContainsString('npm qs -> 6.15.2 in web/package.json', $msg);
        $this->assertStringContainsString('- web/package.json', $msg);
        $this->assertSame('', $this->git($remote['bare'], ['branch', '--list', 'dep-sec-patcher/*']), 'no side branch');
    }

    public function testPrWithoutGithubKeepsThePushedBranch(): void
    {
        $remote = $this->makeRemote(['web/package.json' => "{\"dependencies\": {\"qs\": \"^6.11.0\"}}\n"]);
        $db     = $this->scratchDir('db') . '/vulns.json';
        VulnDb::save($db, VulnDb::upsert(VulnDb::empty(), [[
            'key' => 'web/package.json|qs|CVE-1', 'source' => 'dependabot', 'id' => 'CVE-1', 'ref' => 1, 'refs' => [1],
            'ecosystem' => 'npm', 'package' => 'qs', 'manifest' => 'web/package.json',
            'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'],
        ]], '2026-01-01T00:00:00Z', ''));

        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--pr', '--branch', 'sec/qs', '--vuln-db', $db, $remote['url']], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('push: pushed branch sec/qs to origin', $out);
        $this->assertStringContainsString('push: --pr needs gh and a GitHub repository; open a pull request for sec/qs by hand', $out);
        $this->assertStringContainsString('"qs": "^6.15.2"', $this->git($remote['bare'], ['show', 'sec/qs:web/package.json']));
    }

    /**
     * @param list<array<string, mixed>> $records
     */
    private function storedDb(array $records): string
    {
        $db = $this->scratchDir('db') . '/vulns.json';
        VulnDb::save($db, VulnDb::upsert(VulnDb::empty(), $records, '2026-01-01T00:00:00Z', ''));
        return $db;
    }

    public function testMajorUpgradesWaitForAllowMajor(): void
    {
        $dir = $this->scratchDir('major');
        file_put_contents($dir . '/package.json', "{\n  \"dependencies\": {\n    \"bootstrap\": \"^3\"\n  }\n}\n");
        $db = $this->storedDb([[
            'key' => 'package.json|bootstrap|CVE-1', 'source' => 'issue', 'id' => 'CVE-1', 'ecosystem' => 'npm',
            'package' => 'bootstrap', 'manifest' => 'package.json', 'fixed_version' => '4.0.0', 'fix_versions' => ['4.0.0'],
        ]]);
        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--vuln-db', $db, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('npm bootstrap needs a major upgrade (^3 -> 4.0.0) in package.json', $out);
        $this->assertStringContainsString('"bootstrap": "^3"', (string)file_get_contents($dir . '/package.json'));
        $this->assertSame('pending', VulnDb::load($db)['vulns']['package.json|bootstrap|CVE-1']['state'], 'retried on a later run');

        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--allow-major', '--vuln-db', $db, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('"bootstrap": "^4.0.0"', (string)file_get_contents($dir . '/package.json'));
    }

    public function testTransitiveFixesFollowTheLockfile(): void
    {
        $dir = $this->scratchDir('transitive');
        file_put_contents($dir . '/package.json', "{\n  \"dependencies\": {\n    \"minimatch\": \"^3.0.0\"\n  }\n}\n");
        file_put_contents($dir . '/yarn.lock', "brace-expansion@^1.1.7:\n  version \"1.1.14\"\n\nqs@^6.0.0:\n  version \"6.15.2\"\n\n"
            . "nanoid@^3.3.1:\n  version \"3.3.4\"\n\nnanoid@^5.0.0:\n  version \"5.0.1\"\n");
        $record = static fn (string $pkg, array $fixes): array => [
            'key' => "yarn.lock|{$pkg}|GHSA-{$pkg}", 'source' => 'dependabot', 'id' => "GHSA-{$pkg}", 'ecosystem' => 'npm',
            'package' => $pkg, 'manifest' => 'yarn.lock', 'fixed_version' => $fixes[0], 'fix_versions' => $fixes,
        ];
        $db = $this->storedDb([
            $record('brace-expansion', ['1.1.21', '2.0.2']),
            $record('qs', ['6.14.1']),
            $record('nanoid', ['3.3.8', '5.0.9']),
            $record('babel', ['7.29.6', '8.0.0-rc.6']),
        ]);
        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--vuln-db', $db, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $doc = json_decode((string)file_get_contents($dir . '/package.json'), true);
        $this->assertSame(['brace-expansion' => '^1.1.21'], $doc['resolutions'], 'pinned on the release line the lockfile holds');
        $this->assertArrayNotHasKey('overrides', $doc, 'a yarn project gets no npm overrides');

        $vulns = VulnDb::load($db)['vulns'];
        $this->assertSame('applied', $vulns['yarn.lock|qs|GHSA-qs']['state']);
        $this->assertStringContainsString('the lockfile resolves qs to 6.15.2', $vulns['yarn.lock|qs|GHSA-qs']['note']);
        $this->assertSame('pending', $vulns['yarn.lock|nanoid|GHSA-nanoid']['state']);
        $this->assertStringContainsString('several major versions', $vulns['yarn.lock|nanoid|GHSA-nanoid']['note']);
        $this->assertSame('skipped', $vulns['yarn.lock|babel|GHSA-babel']['state'], 'nothing installs it, so no pin');
        $this->assertStringContainsString('neither declared in package.json nor in its lockfile', $vulns['yarn.lock|babel|GHSA-babel']['note']);
    }

    public function testWithoutALockfileATransitivePinFollowsTheVersionTheIssueFoundInUse(): void
    {
        $dir = $this->scratchDir('inuse');
        file_put_contents($dir . '/pom.xml', "<project>\n  <dependencies>\n  </dependencies>\n</project>\n");
        $record = static fn (string $pkg, array $fixes, array $installed): array => [
            'key' => "pom.xml|{$pkg}|CVE-1", 'source' => 'issue', 'id' => 'CVE-1', 'ecosystem' => 'maven', 'package' => $pkg,
            'manifest' => 'pom.xml', 'fixed_version' => $fixes[0], 'fix_versions' => $fixes, 'installed' => $installed,
        ];
        $db = $this->storedDb([
            $record('org.springframework:spring-webmvc', ['6.2.19', '7.0.8'], ['5.1.17.RELEASE']),
            $record('io.netty:netty-codec-http2', ['4.1.135.Final', '4.2.15.Final'], ['4.1.67.Final', '4.1.76.Final']),
            $record('ch.qos.logback:logback-core', ['1.5.34'], ['1.2.3', '2.0.1']),
        ]);
        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--vuln-db', $db, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $pom = (string)file_get_contents($dir . '/pom.xml');
        $this->assertStringContainsString('<artifactId>netty-codec-http2</artifactId>', $pom);
        $this->assertStringContainsString('<version>4.1.135.Final</version>', $pom, 'the fix on the line in use, not the newest');
        $this->assertStringNotContainsString('spring-webmvc', $pom);
        $this->assertStringContainsString('spring-webmvc needs a major upgrade (5.1.17.RELEASE -> 6.2.19)', $out);
        $vulns = VulnDb::load($db)['vulns'];
        $this->assertStringContainsString('found in use at 1.2.3, 2.0.1 in several major versions', $vulns['pom.xml|ch.qos.logback:logback-core|CVE-1']['note']);

        [$rc, $out] = $this->cli(['--update', '--apply-stored', '--allow-major', '--vuln-db', $db, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('<version>6.2.19</version>', (string)file_get_contents($dir . '/pom.xml'), 'the lowest major that fixes it');
    }

    public function testCheckModeSuggestsTheCommandThatAppliesTheFixes(): void
    {
        $dir = $this->scratchDir('suggest');
        file_put_contents($dir . '/package.json', "{\"dependencies\": {\"qs\": \"^6.11.0\"}}\n");
        $db = $this->storedDb([[
            'key' => 'package.json|qs|CVE-1', 'source' => 'dependabot', 'id' => 'CVE-1', 'ecosystem' => 'npm',
            'package' => 'qs', 'manifest' => 'package.json', 'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'],
        ]]);
        [$rc, $out] = $this->cli(['--check', '--apply-stored', '--vuln-db', $db, $dir], '/');
        $this->assertSame(0, $rc, $out);
        $this->assertStringContainsString('Next steps', $out);
        $this->assertStringContainsString('would set npm qs -> 6.15.2 in package.json', $out);
        $this->assertStringContainsString('1 fix(es) from GitHub\'s alerts and issues would be written', $out);
        $this->assertMatchesRegularExpression('#Apply the fixes:\n\S+ +\S*dep-sec-patcher --update --apply-stored --vuln-db \S+ ' . preg_quote($dir, '#') . '\n#', $out);
        $this->assertStringContainsString('"qs": "^6.11.0"', (string)file_get_contents($dir . '/package.json'), 'check mode changed nothing');
    }
}
