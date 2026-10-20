<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use InvalidArgumentException;
use RuntimeException;

/**
 * The command-line entry point: options, TARGET and state resolution, the
 * config file, the run lock and signal handling, then one SecurityRun.
 */
final class Application
{
    public const VERSION = '0.1.0';
    public const PREFIX  = '[dep-sec-patcher]';

    /** @var resource|null held for the whole run; closing it releases the lock */
    private $lock = null;
    private string $lockFile = '';
    /** The default per-target directory, removed at the end once empty; '' with --state-dir */
    private string $stateDir = '';
    /** The remote target's clone, deleted when the run ends; '' when there is none to delete */
    private string $clone = '';

    /**
     * @param list<string>          $argv including the program name
     * @param array<string, string> $env
     */
    public function run(array $argv, array $env): int
    {
        $program = basename($argv[0] ?? 'dep-sec-patcher');
        $args    = array_slice($argv, 1);
        try {
            $opt = Options::parse($args, $env);
        } catch (InvalidArgumentException $e) {
            fwrite(STDERR, self::PREFIX . ' ERROR: ' . $e->getMessage() . "\nUse '{$program} --help' for usage information\n");
            return 1;
        }
        if ($opt->help) {
            fwrite(STDOUT, Options::help($program));
            return 0;
        }
        if ($opt->version) {
            fwrite(STDOUT, 'dep-sec-patcher ' . self::VERSION . "\n");
            return 0;
        }

        ini_set('pcre.backtrack_limit', '10000000');
        ini_set('memory_limit', '2G');
        set_time_limit(0);

        // Tool locations a cron or systemd environment usually lacks
        $path = Environment::toolPath($env);
        putenv('PATH=' . $path);
        $env['PATH'] = $path;

        $console = new Console(function_exists('stream_isatty') && stream_isatty(STDOUT), self::PREFIX);
        $runner  = new ProcessRunner($console, $opt->timeout, $opt->verbose, $opt->debug);
        $cwd     = (string)getcwd();

        // Before prepare(): Ctrl-C during the first clone must stop git too
        $this->installSignalHandlers($console);

        try {
            [$opt, $target, $state, $configFile] = $this->prepare($opt, $args, $env, $cwd, $console, $runner);
        } catch (InvalidArgumentException | RuntimeException $e) {
            $this->cleanup($console);
            fwrite(STDERR, self::PREFIX . ' ERROR: ' . $e->getMessage() . "\n");
            return 1;
        }

        try {
            $run  = new SecurityRun($opt, $console, $target, $state->vulnDb, $state->reportDir, $configFile, $argv,
                $state->stateDir . '/osv-cache.json', $state->stateDir . '/triage-state.json', $state->stateDir . '/close-state.json');
            $code = $run->run();
        } finally {
            $this->cleanup($console);
        }
        return $code;
    }

    /**
     * The end of a run, however it ends: delete the clone, then the lock,
     * then the per-target directory if nothing (the reports) is left in it.
     */
    private function cleanup(Console $console): void
    {
        if ($this->clone !== '') {
            $clone       = $this->clone;
            $this->clone = '';
            if (is_dir($clone)) {
                // Moved aside first, so a removal cut short (a worker still
                // restoring files as Ctrl-C lands) cannot leave a half-deleted
                // tree in the way of the next run's clone
                $trash = $clone . '.deleting-' . getmypid();
                $path  = @rename($clone, $trash) ? $trash : $clone;
                Filesystem::remove($path);
                clearstatcache();
                if (file_exists($path)) {
                    $console->warn("could not delete the clone {$path}");
                } else {
                    $console->info("deleted the clone {$clone}");
                }
            }
        }
        if (is_resource($this->lock)) {
            // Deleted while still held, so a run starting now either fails to
            // take this lock or creates a new file (see acquireLock())
            @unlink($this->lockFile);
            flock($this->lock, LOCK_UN);
            fclose($this->lock);
            if ($this->stateDir !== '') {
                @rmdir($this->stateDir);
            }
        }
        $this->lock = null;
    }

    /**
     * One run per target: two would race on the manifests, the clone and
     * the database.
     */
    private function acquireLock(StatePaths $state, bool $defaultStateDir): void
    {
        for ($attempt = 1; ; $attempt++) {
            if (!is_dir($state->stateDir) && !@mkdir($state->stateDir, 0700, true) && !is_dir($state->stateDir)) {
                throw new RuntimeException("cannot create state directory {$state->stateDir}");
            }
            // 'e' = close-on-exec: without it every tool inherits the
            // descriptor, and a daemon one leaves behind (an MSBuild node)
            // holds the lock after we exit
            $lock = @fopen($state->lockFile, 'c+e');
            if ($lock === false) {
                if ($attempt < 5) {
                    continue;   // a finishing run removed the empty directory in between
                }
                throw new RuntimeException("cannot open the run lock {$state->lockFile}");
            }
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                $holder = trim((string)stream_get_contents($lock));
                fclose($lock);
                throw new RuntimeException('another run is already in progress' . ($holder !== '' ? " (pid {$holder})" : '')
                    . " for this target (lock: {$state->lockFile})");
            }
            // A finishing run deletes the lock file while holding it: if this
            // is that deleted file, a run starting now would lock a new one
            // alongside, so take the lock again from the path
            clearstatcache(true, $state->lockFile);
            $held = fstat($lock);
            $path = @stat($state->lockFile);
            if ($held !== false && $path !== false && $held['dev'] === $path['dev'] && $held['ino'] === $path['ino']) {
                break;
            }
            fclose($lock);
            if ($attempt >= 5) {
                throw new RuntimeException("could not take the run lock {$state->lockFile}");
            }
        }
        ftruncate($lock, 0);
        fwrite($lock, (string)getmypid());
        fflush($lock);
        $this->lock     = $lock;
        $this->lockFile = $state->lockFile;
        $this->stateDir = $defaultStateDir ? $state->stateDir : '';
    }

    /**
     * The database used to live in the per-target directory by default: move
     * one left there to where it lives now.
     */
    private static function moveLegacyDb(StatePaths $state, Console $console): void
    {
        $old = $state->legacyVulnDb;
        if ($old === '' || !is_file($old) || file_exists($state->vulnDb)) {
            return;
        }
        $dir = dirname($state->vulnDb);
        if ((!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) || !@rename($old, $state->vulnDb)) {
            throw new RuntimeException("cannot move the vulnerability database {$old} to {$state->vulnDb}");
        }
        $console->info("moved the vulnerability database from {$old} to {$state->vulnDb}");
    }

    /**
     * Everything between parsing the options and starting the run.
     *
     * @param list<string>          $args
     * @param array<string, string> $env
     * @return array{0: Options, 1: Target, 2: StatePaths, 3: string}
     */
    private function prepare(Options $opt, array $args, array $env, string $cwd, Console $console, ProcessRunner $runner): array
    {
        $resolver = new TargetResolver($runner, $console, $opt->timeout > 0 ? $opt->timeout : 3600);
        $spec     = TargetResolver::classify($opt->target, $cwd);

        $repo = '';
        $note = '';
        if ($opt->ghRepo !== '') {
            if (preg_match('#^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]+$#', $opt->ghRepo) !== 1) {
                throw new InvalidArgumentException("--repo must be OWNER/NAME, got: {$opt->ghRepo}");
            }
            [$repo, $note] = [$opt->ghRepo, 'from --repo'];
        }

        $root = '';
        if ($spec['kind'] === 'local') {
            $root = TargetResolver::localRoot($spec['path']);
            if ($repo === '') {
                $origin = file_exists($root . '/.git') ? $resolver->originUrl($root) : '';
                $repo   = $origin === '' ? '' : (string)GitUrl::githubRepo($origin);
                $note   = match (true) {
                    $repo !== ''                    => 'from the origin remote',
                    $origin !== ''                  => 'origin is not on github.com',
                    file_exists($root . '/.git')    => 'the checkout has no origin remote',
                    default                         => 'the target is not a git checkout',
                };
            }
            $identity = $root;
            $name     = basename($root);
        } else {
            if ($repo === '') {
                $repo = (string)GitUrl::githubRepo($spec['url']);
                $note = $repo !== '' ? 'from the target URL' : 'the target URL is not on github.com';
            }
            $identity = GitUrl::normalize($spec['url']);
            $name     = GitUrl::basename($spec['url']);
        }

        $state = StatePaths::resolve($opt, StatePaths::slug($repo, $identity, $name), $env, $cwd);
        if ($root !== '') {
            self::assertOutside($state, $root);
        }
        $this->acquireLock($state, $opt->stateDir === '');
        self::moveLegacyDb($state, $console);

        if ($spec['kind'] === 'remote') {
            // Registered before cloning, so a clone that fails or is
            // interrupted part way is deleted too
            if (!$opt->keepClone && TargetResolver::ownsWorkdir($state->workdir)) {
                $this->clone = StatePaths::canonical($state->workdir);
            }
            $resolver->checkout($spec['url'], $state->workdir);
            $root = (string)realpath($state->workdir);
            self::assertOutside($state, $root);
        }

        $subdir = TargetResolver::checkSubdir($root, $opt->subdir);

        // The config file is part of the target, so it is read after cloning
        $configFile = $opt->configFile !== '' ? StatePaths::absolute($opt->configFile, $cwd) : '';
        if ($configFile === '' && is_file($root . '/' . Config::FILE)) {
            $configFile = $root . '/' . Config::FILE;
        }
        if ($configFile !== '') {
            $opt = Options::parse($args, $env, Config::fromFile($configFile));
        }

        if (!is_dir($state->reportDir) && !@mkdir($state->reportDir, 0775, true) && !is_dir($state->reportDir)) {
            throw new RuntimeException("cannot create report directory {$state->reportDir}");
        }

        if ($repo !== '' && $spec['kind'] === 'local' && !file_exists($root . '/.git')) {
            $top = $resolver->gitTopLevel($root);
            if ($top !== '' && $top !== $root) {
                $console->warn("{$root} is inside the git work tree {$top}: GitHub reports manifest paths relative to the"
                    . ' repository root, so pass that as TARGET and narrow the scan with --subdir '
                    . substr($root, strlen($top) + 1));
            }
        }

        $target = new Target($root, $subdir, $repo, $note, $spec['kind'] === 'remote', $spec['url'], $opt->target);
        return [$opt, $target, $state, $configFile];
    }

    /**
     * State never lands inside the scanned tree: it would be audited, undone
     * by check mode, deleted with the clone, or committed.
     */
    private static function assertOutside(StatePaths $state, string $root): void
    {
        $paths = ['state directory' => $state->stateDir, 'vulnerability database' => $state->vulnDb, 'report directory' => $state->reportDir];
        foreach ($paths as $what => $path) {
            if (StatePaths::inside($path, $root)) {
                throw new InvalidArgumentException("the {$what} ({$path}) must be outside the scanned tree {$root}");
            }
        }
    }

    /**
     * Tools run in their own sessions so a timeout can kill a whole process
     * tree; that also means Ctrl-C never reaches them, so pass it on.
     */
    private function installSignalHandlers(Console $console): void
    {
        if (!function_exists('pcntl_async_signals') || !function_exists('pcntl_signal')) {
            return;
        }
        pcntl_async_signals(true);
        $parent = function_exists('posix_getpid') ? posix_getpid() : getmypid();
        foreach ([SIGINT => 130, SIGTERM => 143, SIGHUP => 129] as $sig => $code) {
            pcntl_signal($sig, function () use ($code, $parent, $console): void {
                ProcessRunner::killAll(ProcessRunner::SIGTERM);
                ForkPool::signalChildren(ProcessRunner::SIGTERM);
                // exit() skips the finally blocks that undo a running
                // audit's changes; give the stopped tools a moment, then undo
                usleep(300000);
                WorkspaceGuard::restoreAll();
                // The clone and the lock belong to the parent; a forked worker
                // inherits this handler and must leave them alone
                if ((function_exists('posix_getpid') ? posix_getpid() : getmypid()) === $parent) {
                    $console->line('interrupted, stopping running tools');
                    $this->cleanup($console);
                }
                exit($code);
            });
        }
    }
}
