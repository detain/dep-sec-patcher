<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Runs jobs in forked workers, honouring per-group concurrency limits.
 *
 * Some package managers corrupt a shared cache when two copies run at once
 * (Maven 3.8's local repository, yarn v1, NuGet's global packages folder), so
 * every job names a group and each group has a limit; the scheduler only
 * starts a job whose group has room, otherwise it moves on to the next one.
 * Jobs from different groups therefore still overlap: a serialised mvn can run
 * alongside npm audits.
 *
 * Results travel back through a temp file per job, so counters and summaries
 * are aggregated in the parent. (The original shell script ran its parallel mode
 * through xargs subshells that discarded every result, and passed them an
 * unexported $script, so -t N silently did nothing at all.)
 */
final class ForkPool
{
    /** @var array<int, true> */
    private static array $children = [];

    /**
     * @param list<mixed>        $jobs
     * @param callable           $groupOf (job): group name
     * @param array<string, int> $limits  group => max concurrent (missing = unlimited)
     * @param callable           $work    (job): result; runs in the worker, result must be serialisable
     * @param callable           $done    (job, result): void; runs in the parent, in completion order
     */
    public static function run(array $jobs, int $threads, callable $groupOf, array $limits, callable $work, callable $done): void
    {
        if ($threads <= 1 || count($jobs) <= 1 || !function_exists('pcntl_fork')) {
            foreach ($jobs as $job) {
                $done($job, $work($job));
            }
            return;
        }

        $queue   = $jobs;
        $running = [];   // pid => [job, tmpfile, group]
        $inGroup = [];   // group => running count

        while ($queue !== [] || $running !== []) {
            // Start whatever fits, in queue order, skipping jobs whose group is full
            foreach ($queue as $i => $job) {
                if (count($running) >= $threads) {
                    break;
                }
                $group = $groupOf($job);
                $limit = $limits[$group] ?? PHP_INT_MAX;
                if (($inGroup[$group] ?? 0) >= $limit) {
                    continue;
                }
                unset($queue[$i]);

                $tmp = tempnam(sys_get_temp_dir(), 'dep-sec-patcher.');
                $pid = $tmp === false ? -1 : pcntl_fork();
                if ($pid === -1) {
                    // Could not fork: run it here rather than drop it
                    if ($tmp !== false) {
                        @unlink($tmp);
                    }
                    $done($job, $work($job));
                    continue;
                }
                if ($pid === 0) {
                    self::$children = [];
                    try {
                        $result = $work($job);
                    } catch (\Throwable $e) {
                        $result = $e;
                    }
                    file_put_contents($tmp, serialize($result instanceof \Throwable
                        ? ['__worker_error' => get_class($result) . ': ' . $result->getMessage()]
                        : $result));
                    // End without running the shutdown functions and destructors
                    // inherited from the parent; the result is already on disk
                    if (function_exists('posix_kill')) {
                        posix_kill(posix_getpid(), ProcessRunner::SIGKILL);
                    }
                    exit(0);
                }
                self::$children[$pid] = true;
                $running[$pid]        = [$job, $tmp, $group];
                $inGroup[$group]      = ($inGroup[$group] ?? 0) + 1;
            }

            if ($running === []) {
                continue;
            }
            $pid = pcntl_wait($status);
            if ($pid <= 0 || !isset($running[$pid])) {
                continue;   // interrupted by a signal, or not one of ours
            }
            [$job, $tmp, $group] = $running[$pid];
            unset($running[$pid], self::$children[$pid]);
            $inGroup[$group]--;

            $raw    = @file_get_contents($tmp);
            $result = is_string($raw) && $raw !== '' ? @unserialize($raw) : false;
            @unlink($tmp);
            if ($result === false) {
                $why    = pcntl_wifsignaled($status) ? 'killed by signal ' . pcntl_wtermsig($status) : 'exit ' . pcntl_wexitstatus($status);
                $result = ['__worker_error' => "worker died ({$why})"];
            }
            $done($job, $result);
        }
    }

    /**
     * Forward a termination signal to every live worker.
     */
    public static function signalChildren(int $signal): void
    {
        foreach (array_keys(self::$children) as $pid) {
            @posix_kill($pid, $signal);
        }
    }
}
