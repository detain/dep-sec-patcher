<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Runs external tools with a timeout, live progress and no way to block on a
 * prompt.
 *
 * - stdin is /dev/null, so a tool that wants input fails instead of waiting
 *   forever on a terminal nobody is watching;
 * - each command gets its own session (setsid), so a timeout or Ctrl-C kills
 *   the whole tree it spawned, not just the top process;
 * - when a command has been quiet for HEARTBEAT seconds a "still running" line
 *   is printed, so a long NVD download no longer looks like a hang;
 * - with $verbose every output line is streamed as it arrives.
 */
final class ProcessRunner
{
    /** Signal numbers, so the no-pcntl fallback never touches the pcntl-only SIG* constants. */
    public const SIGTERM = 15;
    public const SIGKILL = 9;

    private const HEARTBEAT   = 60;
    private const KILL_GRACE  = 10;
    private const STDOUT_CAP  = 64 * 1024 * 1024;
    private const OUTPUT_CAP  = 256 * 1024;

    /** @var array<int, true> process-group ids of commands currently running */
    private static array $active = [];

    private ?string $setsid;

    public function __construct(
        private Console $console,
        private int $defaultTimeout,
        private bool $verbose = false,
        private bool $debug = false
    ) {
        $setsid       = trim((string)@shell_exec('command -v setsid 2>/dev/null'));
        $this->setsid = $setsid !== '' && function_exists('posix_kill') ? $setsid : null;
    }

    /**
     * @param list<string> $argv
     * @param array{timeout?: int, env?: array<string, string>, label?: string} $opt
     *        timeout: seconds, 0 = none (default: the runner's default)
     */
    public function run(array $argv, string $cwd, array $opt = []): CommandResult
    {
        $timeout = $opt['timeout'] ?? $this->defaultTimeout;
        $label   = $opt['label'] ?? $argv[0];
        $display = self::display($argv);
        $env     = null;
        if (!empty($opt['env'])) {
            $env = array_merge(getenv(), $opt['env']);
        }

        if ($this->debug || $this->verbose) {
            $this->console->detail("[{$label}] \$ {$display}" . ($timeout > 0 ? '  (timeout ' . CommandResult::duration($timeout) . ')' : ''));
        }

        $cmd  = $this->setsid !== null ? array_merge([$this->setsid], $argv) : $argv;
        $spec = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];

        $start = microtime(true);
        $proc  = @proc_open($cmd, $spec, $pipes, $cwd, $env);
        if (!is_resource($proc)) {
            return new CommandResult($display, 127, false, '', "failed to start: {$display}", 0.0);
        }
        $pid = (int)proc_get_status($proc)['pid'];
        if ($this->setsid !== null) {
            self::$active[$pid] = true;
        }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout   = '';
        $output   = '';
        $partial  = [1 => '', 2 => ''];
        $open     = [1 => true, 2 => true];
        $exit     = null;
        $exitedAt = 0.0;
        $timedOut = false;
        $killedAt = 0.0;
        $lastSeen = $start;

        while (true) {
            $read = [];
            foreach ([1, 2] as $fd) {
                if ($open[$fd]) {
                    $read[$fd] = $pipes[$fd];
                }
            }
            if ($read !== []) {
                $w = $e = null;
                $ready = @stream_select($read, $w, $e, 1, 0);
                if ($ready !== false && $ready > 0) {
                    foreach ($read as $stream) {
                        $fd    = $stream === $pipes[1] ? 1 : 2;
                        $chunk = fread($stream, 65536);
                        if ($chunk === false || $chunk === '') {
                            if (feof($stream)) {
                                $open[$fd] = false;
                            }
                            continue;
                        }
                        $lastSeen = microtime(true);
                        if ($fd === 1 && strlen($stdout) < self::STDOUT_CAP) {
                            $stdout .= $chunk;
                        }
                        $output .= $chunk;
                        if (strlen($output) > self::OUTPUT_CAP * 2) {
                            $output = substr($output, -self::OUTPUT_CAP);
                        }
                        if ($this->verbose) {
                            $partial[$fd] .= $chunk;
                            while (($nl = strpos($partial[$fd], "\n")) !== false) {
                                $this->console->detail("[{$label}] " . rtrim(CommandResult::plain(substr($partial[$fd], 0, $nl)), "\r"));
                                $partial[$fd] = substr($partial[$fd], $nl + 1);
                            }
                        }
                    }
                }
            } else {
                usleep(100000);
            }

            $now = microtime(true);
            if ($exit === null) {
                $st = proc_get_status($proc);
                if (!$st['running']) {
                    $exit     = $st['signaled'] ? 128 + (int)$st['termsig'] : (int)$st['exitcode'];
                    $exitedAt = $now;
                }
            }
            if ($exit !== null && !$open[1] && !$open[2]) {
                break;
            }
            // The command exited but something it spawned still holds the
            // pipes (a build daemon, a backgrounded helper): reap the group
            if ($exit !== null && $now - $exitedAt > 5) {
                $this->killGroup($pid, self::SIGKILL);
                break;
            }

            if ($timeout > 0 && $exit === null && !$timedOut && $now - $start > $timeout) {
                $timedOut = true;
                $killedAt = $now;
                $this->console->detail("[{$label}] timed out after " . CommandResult::duration($timeout) . ", stopping: {$display}");
                $this->killGroup($pid, self::SIGTERM);
            }
            if ($timedOut && $exit === null && $now - $killedAt > self::KILL_GRACE) {
                $this->killGroup($pid, self::SIGKILL);
                $killedAt = $now;
            }

            if (!$timedOut && $now - $lastSeen >= self::HEARTBEAT) {
                $this->console->detail("[{$label}] still running after " . CommandResult::duration($now - $start) . ": {$display}");
                $lastSeen = $now;
            }
        }

        if ($this->verbose) {
            foreach ([1, 2] as $fd) {
                if (trim($partial[$fd]) !== '') {
                    $this->console->detail("[{$label}] " . rtrim($partial[$fd]));
                }
            }
        }
        foreach ([1, 2] as $fd) {
            if (is_resource($pipes[$fd])) {
                fclose($pipes[$fd]);
            }
        }
        proc_close($proc);
        // Reap anything the command left running in its session (MSBuild
        // nodes, compiler servers): they would outlive the run and pile up
        $this->killGroup($pid, self::SIGKILL);
        unset(self::$active[$pid]);

        return new CommandResult($display, $exit, $timedOut, $stdout, $output, microtime(true) - $start);
    }

    /**
     * Whether a program is on PATH.
     */
    public static function has(string $tool): bool
    {
        static $cache = [];
        if (!isset($cache[$tool])) {
            $cache[$tool] = trim((string)@shell_exec('command -v ' . escapeshellarg($tool) . ' 2>/dev/null')) !== '';
        }
        return $cache[$tool];
    }

    /**
     * Terminate every running command's process group. Called from the
     * SIGINT/SIGTERM handler: commands run in their own session, so Ctrl-C at
     * the terminal does not reach them on its own.
     */
    public static function killAll(int $signal = self::SIGTERM): void
    {
        if (!function_exists('posix_kill')) {
            return;
        }
        foreach (array_keys(self::$active) as $pgid) {
            @posix_kill(-$pgid, $signal);
        }
    }

    private function killGroup(int $pid, int $signal): void
    {
        if ($this->setsid !== null) {
            @posix_kill(-$pid, $signal);
        } elseif (function_exists('posix_kill') && $signal !== self::SIGKILL) {
            // Without a session of its own the pid may be reused once reaped;
            // only signal it while it may still be ours
            @posix_kill($pid, $signal);
        }
    }

    /**
     * @param list<string> $argv
     */
    private static function display(array $argv): string
    {
        return implode(' ', array_map(static function (string $a): string {
            // Never echo a secret passed as -Dkey=value
            if (preg_match('/^-D[^=]*(?:key|token|password|secret)[^=]*=/i', $a) === 1) {
                return preg_replace('/=.*/', '=***', $a) ?? $a;
            }
            // Nor credentials embedded in a URL (https://user:token@host/...)
            $a = GitUrl::redact($a);
            return preg_match('/^[A-Za-z0-9_.,:\/=@%+-]+$/', $a) === 1 ? $a : escapeshellarg($a);
        }, $argv));
    }
}
