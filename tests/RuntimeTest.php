<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Console;
use Detain\DepSecPatcher\ForkPool;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\WorkspaceGuard;
use PHPUnit\Framework\TestCase;

/**
 * The process, concurrency and workspace machinery. These spawn short-lived
 * processes and use a scratch directory; nothing touches the network.
 */
class RuntimeTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/dep-sec-patcher-test-' . getmypid() . '-' . mt_rand();
        mkdir($this->dir, 0775, true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private function runner(int $timeout = 30): ProcessRunner
    {
        $out = fopen('php://memory', 'w+');
        $this->assertIsResource($out);
        $console = new Console(false, '[test]', $out);
        return new ProcessRunner($console, $timeout);
    }

    public function testCapturesOutputAndExitCode(): void
    {
        $r = $this->runner()->run(['sh', '-c', 'echo out; echo err >&2; exit 3'], $this->dir);
        $this->assertSame(3, $r->exitCode);
        $this->assertSame("out\n", $r->stdout);
        $this->assertStringContainsString('err', $r->output);
        $this->assertFalse($r->ok());
    }

    public function testStdinIsClosedSoPromptsCannotHang(): void
    {
        $r = $this->runner(10)->run(['sh', '-c', 'read answer; echo "got:$answer"'], $this->dir);
        $this->assertFalse($r->timedOut);
        $this->assertSame("got:\n", $r->stdout);
    }

    public function testTimeoutKillsTheWholeProcessTree(): void
    {
        if (!function_exists('posix_kill')) {
            $this->markTestSkipped('posix extension required');
        }
        $marker = $this->dir . '/child.pid';
        $start  = microtime(true);
        ob_start();
        $r = $this->runner(1)->run(['sh', '-c', "sleep 30 & echo \$! > {$marker}; sleep 30"], $this->dir);
        ob_end_clean();
        $this->assertTrue($r->timedOut);
        $this->assertLessThan(15, microtime(true) - $start);
        $child = (int)trim((string)file_get_contents($marker));
        usleep(200000);
        $this->assertFalse(posix_kill($child, 0), 'the backgrounded grandchild was killed too');
    }

    public function testDaemonsLeftBehindAreReaped(): void
    {
        if (!function_exists('posix_kill')) {
            $this->markTestSkipped('posix extension required');
        }
        // A helper that detaches from our pipes and outlives the command, the
        // way MSBuild node reuse does; it must not survive the run
        $marker = $this->dir . '/daemon.pid';
        $r = $this->runner(10)->run(['sh', '-c', "sleep 30 </dev/null >/dev/null 2>&1 & echo \$! > {$marker}"], $this->dir);
        $this->assertTrue($r->ok());
        $daemon = (int)trim((string)file_get_contents($marker));
        usleep(200000);
        $this->assertFalse(posix_kill($daemon, 0), 'the detached helper was reaped');
    }

    public function testMissingProgram(): void
    {
        $r = $this->runner()->run(['definitely-not-a-real-program-xyz'], $this->dir);
        $this->assertFalse($r->ok());
    }

    public function testForkPoolRespectsGroupLimits(): void
    {
        if (!function_exists('pcntl_fork') || !function_exists('posix_getpid')) {
            $this->markTestSkipped('pcntl and posix extensions required');
        }
        $log  = $this->dir . '/log';
        $jobs = [['serial', 1], ['serial', 2], ['serial', 3], ['free', 4], ['free', 5], ['free', 6]];
        $done = [];
        ForkPool::run(
            $jobs,
            4,
            static fn (array $j): string => $j[0],
            ['serial' => 1],
            static function (array $j) use ($log): array {
                $start = microtime(true);
                usleep(300000);
                file_put_contents($log, "{$j[0]} {$start} " . microtime(true) . "\n", FILE_APPEND | LOCK_EX);
                return ["id" => $j[1], "pid" => posix_getpid()];
            },
            static function (array $j, $result) use (&$done): void {
                $done[] = $result['id'];
            }
        );
        sort($done);
        $this->assertSame([1, 2, 3, 4, 5, 6], $done, 'every result reaches the parent');

        $spans = ['serial' => [], 'free' => []];
        foreach (file($log) ?: [] as $line) {
            [$group, $s, $e] = explode(' ', trim($line));
            $spans[$group][] = [(float)$s, (float)$e];
        }
        ['serial' => $serial, 'free' => $free] = $spans;
        usort($serial, static fn ($a, $b) => $a[0] <=> $b[0]);
        for ($i = 1; $i < count($serial); $i++) {
            $this->assertGreaterThanOrEqual($serial[$i - 1][1], $serial[$i][0], 'serial jobs never overlap');
        }
        usort($free, static fn ($a, $b) => $a[0] <=> $b[0]);
        $this->assertLessThan($free[0][1], $free[1][0], 'unlimited jobs do overlap');
    }

    public function testForkPoolSequentialFallback(): void
    {
        $pids = [];
        ForkPool::run([1, 2], 1, static fn ($j) => 'g', [], static fn ($j) => getmypid(), static function ($j, $r) use (&$pids): void {
            $pids[] = $r;
        });
        $this->assertSame([getmypid(), getmypid()], $pids, 'one thread runs in-process');
    }

    public function testWorkspaceGuardUpdateModeRemovesOnlyNewBuildDirs(): void
    {
        mkdir($this->dir . '/bin');                       // pre-existing: must survive
        file_put_contents($this->dir . '/package.json', '{}');
        $guard = new WorkspaceGuard($this->dir, false);
        mkdir($this->dir . '/node_modules/x', 0775, true);
        mkdir($this->dir . '/obj');
        file_put_contents($this->dir . '/package-lock.json', '{}');
        file_put_contents($this->dir . '/package.json', '{"changed":true}');
        $guard->restore();

        $this->assertDirectoryDoesNotExist($this->dir . '/node_modules');
        $this->assertDirectoryDoesNotExist($this->dir . '/obj');
        $this->assertDirectoryExists($this->dir . '/bin');
        $this->assertFileExists($this->dir . '/package-lock.json', 'update mode keeps new lockfiles');
        $this->assertSame('{"changed":true}', file_get_contents($this->dir . '/package.json'));
    }

    public function testWorkspaceGuardCheckModeUndoesEverything(): void
    {
        file_put_contents($this->dir . '/composer.json', '{"a":1}');
        $guard = new WorkspaceGuard($this->dir, true);
        file_put_contents($this->dir . '/composer.json', '{"a":2}');
        file_put_contents($this->dir . '/composer.lock', '{}');
        mkdir($this->dir . '/vendor/ro', 0775, true);
        file_put_contents($this->dir . '/vendor/ro/f', 'x');
        chmod($this->dir . '/vendor/ro', 0555);           // go/cargo leave read-only dirs
        $undone = $guard->restore();

        $this->assertSame('{"a":1}', file_get_contents($this->dir . '/composer.json'));
        $this->assertFileDoesNotExist($this->dir . '/composer.lock');
        $this->assertDirectoryDoesNotExist($this->dir . '/vendor');
        $this->assertContains('restored composer.json', $undone);
        $this->assertContains('removed composer.lock', $undone);
    }

    public function testManifestIndexPrunesDependencyDirs(): void
    {
        foreach (['a/package.json', 'a/node_modules/dep/package.json', 'b/vendor/x/composer.json', 'b/composer.json', '.git/config'] as $f) {
            @mkdir(dirname($this->dir . '/' . $f), 0775, true);
            file_put_contents($this->dir . '/' . $f, '{}');
        }
        $index = new ManifestIndex($this->dir);
        $this->assertSame(['a/package.json', 'b/composer.json'], $index->files());
        $this->assertSame(['a'], $index->dirsWith(['package.json']));
    }
}
