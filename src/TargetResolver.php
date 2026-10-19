<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use InvalidArgumentException;
use RuntimeException;

/**
 * Turns the positional TARGET into a directory to scan.
 *
 * A local directory is used in place. A git URL, or the GitHub OWNER/NAME
 * shorthand, is cloned into a workdir that dep-sec-patcher owns and deletes
 * when the run ends. A clone kept with --keep-clone (or left by a run that
 * was killed) is reset to the remote's default branch, with untracked and
 * ignored files removed, and reused.
 *
 * Every git command runs through ProcessRunner (timeout, stdin closed) with
 * terminal prompts disabled, so a missing credential fails instead of hanging.
 */
final class TargetResolver
{
    /** Marker inside .git/ identifying a clone this tool created and may reset. */
    public const CLONE_MARKER = 'dep-sec-patcher-clone';

    public function __construct(
        private ProcessRunner $runner,
        private Console $console,
        private int $timeout = 1800,
    ) {
    }

    /**
     * Classify a TARGET without touching the network. An existing local path
     * always wins, so a directory named like "owner/name" is still local.
     *
     * @return array{kind: 'local'|'remote', path: string, url: string}
     */
    public static function classify(string $target, string $cwd): array
    {
        if ($target === '') {
            return ['kind' => 'local', 'path' => $cwd, 'url' => ''];
        }
        $path = str_starts_with($target, '/') ? $target : rtrim($cwd, '/') . '/' . $target;
        if (file_exists($path) || is_link($path)) {
            return ['kind' => 'local', 'path' => $path, 'url' => ''];
        }
        if (GitUrl::isUrl($target)) {
            return ['kind' => 'remote', 'path' => '', 'url' => $target];
        }
        if (GitUrl::isGithubShorthand($target)) {
            return ['kind' => 'remote', 'path' => '', 'url' => GitUrl::fromShorthand($target)];
        }
        throw new InvalidArgumentException("target not found: {$target} (not a directory, git URL or OWNER/NAME)");
    }

    /**
     * Validated absolute root for a local target. The target itself must not
     * be a symlink, so the scan cannot be redirected outside it.
     */
    public static function localRoot(string $path): string
    {
        if (is_link(rtrim($path, '/'))) {
            throw new InvalidArgumentException("target must not be a symlink: {$path}");
        }
        $root = realpath($path);
        if ($root === false || !is_dir($root)) {
            throw new InvalidArgumentException("target is not a directory: {$path}");
        }
        return $root;
    }

    /**
     * Validate --subdir against the root: it must exist, be a directory, and
     * (after resolving symlinks) stay inside the root.
     */
    public static function checkSubdir(string $root, string $subdir): string
    {
        if ($subdir === '') {
            return '';
        }
        $abs  = $root . '/' . $subdir;
        $real = realpath($abs);
        if ($real === false || !is_dir($real)) {
            throw new InvalidArgumentException("--subdir not found in the target: {$subdir}");
        }
        if (!str_starts_with($real . '/', rtrim($root, '/') . '/') || $real === $root) {
            throw new InvalidArgumentException("--subdir must stay inside the target: {$subdir}");
        }
        return substr($real, strlen(rtrim($root, '/')) + 1);
    }

    /**
     * OWNER/NAME from a local checkout's origin remote, when the checkout's
     * own root is the target and origin is on github.com; '' otherwise.
     */
    public function originRepo(string $root): string
    {
        if (!file_exists($root . '/.git')) {
            return '';
        }
        $url = $this->originUrl($root);
        return $url === '' ? '' : (string)GitUrl::githubRepo($url);
    }

    public function originUrl(string $root): string
    {
        $r = $this->git($root, ['remote', 'get-url', 'origin'], 30);
        return $r->ok() ? trim($r->stdout) : '';
    }

    /**
     * Top level of the git work tree containing $dir, or '' when none.
     */
    public function gitTopLevel(string $dir): string
    {
        $r = $this->git($dir, ['rev-parse', '--show-toplevel'], 30);
        if (!$r->ok()) {
            return '';
        }
        $top = realpath(trim($r->stdout));
        return $top === false ? '' : $top;
    }

    /**
     * Whether a run may delete $workdir when it ends: nothing is there yet,
     * or it is an empty directory or a clone this tool made. Anything else
     * checkout() refuses to touch.
     */
    public static function ownsWorkdir(string $workdir): bool
    {
        if (!is_dir($workdir)) {
            return !file_exists($workdir) && !is_link($workdir);
        }
        return (scandir($workdir) ?: []) === ['.', '..'] || is_file($workdir . '/.git/' . self::CLONE_MARKER);
    }

    /**
     * Clone $url into $workdir, or refresh an earlier clone there, leaving it
     * clean at the tip of the remote's default branch.
     *
     * @return string the default branch name
     */
    public function checkout(string $url, string $workdir): string
    {
        $shown = GitUrl::redact($url);
        $fresh = !is_dir($workdir) || (scandir($workdir) ?: []) === ['.', '..'];

        if ($fresh) {
            $parent = dirname($workdir);
            if (!is_dir($parent) && !@mkdir($parent, 0700, true) && !is_dir($parent)) {
                throw new RuntimeException("cannot create {$parent}");
            }
            $this->console->info("cloning {$shown} into {$workdir}...");
            $r = $this->git($parent, ['clone', '--quiet', '--', $url, $workdir], $this->timeout);
            if (!$r->ok()) {
                throw new RuntimeException("git clone {$shown} failed (" . $r->failureReason() . '): ' . implode(' | ', $r->tail(4)));
            }
            @file_put_contents($workdir . '/.git/' . self::CLONE_MARKER, GitUrl::normalize($url) . "\n");
        } else {
            if (!is_file($workdir . '/.git/' . self::CLONE_MARKER)) {
                throw new RuntimeException("refusing to use {$workdir}: it exists and is not a clone made by dep-sec-patcher"
                    . ' (remove it or choose another --workdir)');
            }
            $this->console->info("updating the clone of {$shown} in {$workdir}...");
            $this->must($workdir, ['remote', 'set-url', 'origin', $url], 30);
            $dirty = $this->git($workdir, ['status', '--porcelain'], 120);
            if ($dirty->ok() && trim($dirty->stdout) !== '') {
                $n = count(array_filter(explode("\n", trim($dirty->stdout))));
                $this->console->warn("discarding {$n} local change(s) left in the clone {$workdir}");
            }
            $this->must($workdir, ['fetch', '--prune', '--quiet', 'origin'], $this->timeout);
        }

        // Follow the remote's current default branch, even if it was renamed
        $this->git($workdir, ['remote', 'set-head', 'origin', '--auto'], 120);
        $head = $this->git($workdir, ['symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD'], 30);
        $branch = (string)preg_replace('#^origin/#', '', trim($head->stdout));
        if (!$head->ok() || $branch === '') {
            throw new RuntimeException("{$shown} has no default branch (is the repository empty?)");
        }
        $this->must($workdir, ['checkout', '--quiet', '--force', '-B', $branch, 'origin/' . $branch], 300);
        $this->must($workdir, ['reset', '--quiet', '--hard', 'origin/' . $branch], 300);
        $this->must($workdir, ['clean', '-ffdxq'], 300);
        return $branch;
    }

    /**
     * Environment for git: never prompt for anything.
     *
     * @return array<string, string>
     */
    public static function gitEnv(): array
    {
        $env = ['GIT_TERMINAL_PROMPT' => '0'];
        if ((string)getenv('GIT_SSH_COMMAND') === '' && (string)getenv('GIT_SSH') === '') {
            $env['GIT_SSH_COMMAND'] = 'ssh -o BatchMode=yes';
        }
        return $env;
    }

    /**
     * Options for every git command. With a GitHub token in the environment
     * (possibly harvested from an rc file) git authenticates to github.com
     * over HTTPS as the same account the gh steps use, through gh, ahead of
     * any stored credential that may belong to someone else. (On the command
     * line because proc_open drops the empty value that resets the helpers.)
     *
     * @return list<string>
     */
    public static function gitOptions(): array
    {
        if (((string)getenv('GH_TOKEN') === '' && (string)getenv('GITHUB_TOKEN') === '') || !ProcessRunner::has('gh')) {
            return [];
        }
        // An empty helper resets the list collected from the config files
        return ['-c', 'credential.https://github.com.helper=', '-c', 'credential.https://github.com.helper=!gh auth git-credential'];
    }

    /**
     * @param list<string> $args
     */
    private function git(string $cwd, array $args, int $timeout): CommandResult
    {
        return $this->runner->run(array_merge(['git'], self::gitOptions(), $args), $cwd, [
            'timeout' => $timeout,
            'label'   => 'git',
            'env'     => self::gitEnv(),
        ]);
    }

    /**
     * @param list<string> $args
     */
    private function must(string $cwd, array $args, int $timeout): CommandResult
    {
        $r = $this->git($cwd, $args, $timeout);
        if (!$r->ok()) {
            throw new RuntimeException('git ' . implode(' ', array_map([GitUrl::class, 'redact'], $args)) . ' failed (' . $r->failureReason() . '): '
                . implode(' | ', array_map([GitUrl::class, 'redact'], $r->tail(4))));
        }
        return $r;
    }
}
