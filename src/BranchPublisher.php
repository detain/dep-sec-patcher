<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * --push, --pr and --push-direct: commit what an update-mode run changed and
 * push it to origin, either on a new branch (put back on the branch the tree
 * started on afterwards) or straight onto the checked-out branch.
 *
 * Only this run's changes are published: snapshot() records what was
 * already uncommitted before the run (path => content hash), and the commit
 * takes just the paths the run changed that were clean then. A path that
 * was dirty before and that the run changed as well is left out, since the
 * two cannot be told apart. A remote target's clone is always clean at the
 * start.
 */
final class BranchPublisher
{
    /** @var array<string, string>|null what was uncommitted before the run: path => content hash; null before snapshot() */
    private ?array $before = null;
    /** Whether the paths left out of the commit have been reported */
    private bool $announced = false;

    public function __construct(
        private ProcessRunner $runner,
        private Console $console,
        private string $root,
        private int $timeout = 600,
    ) {
    }

    /**
     * True/false for a git work tree, null when $root is not the top of one.
     */
    public function isClean(): ?bool
    {
        if (!file_exists($this->root . '/.git')) {
            return null;
        }
        $r = $this->git(['status', '--porcelain'], 120);
        return $r->ok() ? trim($r->stdout) === '' : null;
    }

    /**
     * Record what is uncommitted before the run touches the tree, so that
     * publishing takes only the run's own changes.
     *
     * @return array<string, string>|null path => content hash, null when $root is not the top of a work tree
     */
    public function snapshot(): ?array
    {
        if (!file_exists($this->root . '/.git')) {
            return null;
        }
        $paths = $this->statusPaths(true);
        if ($paths === null) {
            return null;
        }
        $this->before = [];
        foreach ($paths as $path) {
            $this->before[$path] = $this->contentHash($path);
        }
        return $this->before;
    }

    /**
     * Sort the uncommitted paths into those this run changed (and are
     * committed), those that were already dirty before the run and that the
     * run changed too (left out), and those dirty before that the run left
     * as they were (left alone). Without a snapshot every change is the run's.
     *
     * @return array{commit: list<string>, conflicted: list<string>, untouched: list<string>}|null null when git status fails
     */
    public function plan(): ?array
    {
        $paths = $this->statusPaths(true);
        if ($paths === null) {
            return null;
        }
        $plan = ['commit' => [], 'conflicted' => [], 'untouched' => []];
        foreach ($paths as $path) {
            if ($this->before === null || !array_key_exists($path, $this->before)) {
                $plan['commit'][] = $path;
            } elseif ($this->contentHash($path) === $this->before[$path]) {
                $plan['untouched'][] = $path;
            } else {
                $plan['conflicted'][] = $path;
            }
        }
        return $plan;
    }

    public static function defaultBranch(string $now): string
    {
        return 'dep-sec-patcher/' . gmdate('Ymd-His', (int)strtotime($now));
    }

    /**
     * The checked-out branch, '' for a detached HEAD.
     */
    public function currentBranch(): string
    {
        $r = $this->git(['symbolic-ref', '--quiet', '--short', 'HEAD'], 30);
        return $r->ok() ? trim($r->stdout) : '';
    }

    /**
     * Paths the run changed, created or deleted, relative to the root.
     *
     * @return list<string>
     */
    public function changedFiles(): array
    {
        return $this->statusPaths(false) ?? [];
    }

    /**
     * Every uncommitted path from git status, untracked files included.
     *
     * @param bool $origins also list the original path of a staged rename or copy
     * @return list<string>|null null when git status fails
     */
    private function statusPaths(bool $origins): ?array
    {
        $r = $this->git(['status', '--porcelain', '-z', '--untracked-files=all'], 120);
        if (!$r->ok()) {
            return null;
        }
        $files   = [];
        $entries = explode("\0", rtrim($r->stdout, "\0"));
        for ($i = 0; $i < count($entries); $i++) {
            if (strlen($entries[$i]) < 4) {
                continue;
            }
            $files[] = substr($entries[$i], 3);
            // A rename or copy is followed by its original path
            if (in_array($entries[$i][0], ['R', 'C'], true)) {
                $i++;
                if ($origins && isset($entries[$i]) && $entries[$i] !== '') {
                    $files[] = $entries[$i];
                }
            }
        }
        return array_values(array_unique($files));
    }

    /**
     * What a path holds in the work tree right now, to tell whether the run
     * changed a path that was already dirty.
     */
    private function contentHash(string $path): string
    {
        $full = $this->root . '/' . $path;
        if (is_link($full)) {
            return 'link:' . (string)readlink($full);
        }
        if (is_file($full)) {
            $hash = @sha1_file($full);
            return $hash === false ? 'unreadable' : 'file:' . $hash . ':' . (is_executable($full) ? 'x' : '-');
        }
        return is_dir($full) ? 'dir' : 'missing';
    }

    /**
     * Fast-forward the checked-out $branch to origin's copy, so the run's
     * changes are made on top of whatever was merged since the tree was last
     * pulled (dependency-bot PRs this very run merged, for instance). A
     * branch that has diverged from origin's is left alone.
     */
    public function syncWithOrigin(string $branch): bool
    {
        if (!$this->git(['fetch', '--quiet', 'origin', $branch], $this->timeout)->ok()) {
            $this->console->info("push: could not fetch {$branch} from origin; continuing from the local copy");
            return false;
        }
        if ($this->git(['merge-base', '--is-ancestor', 'FETCH_HEAD', 'HEAD'], 30)->ok()) {
            return true;
        }
        if (!$this->git(['merge', '--quiet', '--ff-only', 'FETCH_HEAD'], 120)->ok()) {
            $this->console->warn("push: {$branch} has diverged from origin's {$branch}, or uncommitted changes are in the way; not fast-forwarding it");
            return false;
        }
        $this->console->info("push: fast-forwarded {$branch} to origin's {$branch}");
        return true;
    }

    /**
     * Commit the run's changes to a new branch, rebased onto origin's $base
     * when that has moved on during the run, push it, and check the starting
     * branch back out. A commit that conflicts with origin's $base is pushed
     * as it is, so the conflict shows up for review. Changes that were
     * uncommitted before the run stay in the work tree, on no branch.
     *
     * @return bool whether the branch was pushed
     */
    public function publish(string $branch, string $message, string $base = ''): bool
    {
        $paths = $this->pathsToCommit();
        if ($paths === null || $paths === []) {
            return false;
        }
        $back = $this->currentBranch();
        if ($back === '') {
            $back = trim($this->git(['rev-parse', 'HEAD'], 30)->stdout);
        }

        if (!$this->step(['checkout', '--quiet', '-b', $branch], "create branch {$branch}")) {
            return false;
        }
        $committed = $this->commit($message, $paths);
        $head      = $committed ? trim($this->git(['rev-parse', 'HEAD'], 30)->stdout) : '';
        // Leave the working tree where it started; the changes live on the
        // branch, and anything uncommitted is carried back untouched
        if ($back !== '') {
            $this->git(['checkout', '--quiet', $back], 120);
        }
        if (!$committed || $head === '') {
            return false;
        }
        if ($base !== '') {
            $rebased = $this->rebased($head, $base);
            if ($rebased !== false && $rebased !== $head
                && !$this->step(['branch', '--force', $branch, $rebased], "move {$branch} onto origin's {$base}")) {
                return false;
            }
        }
        $pushed = $this->step(['push', '--quiet', '--set-upstream', 'origin', $branch], "push {$branch}", $this->timeout);
        if ($pushed) {
            $this->console->ok("push: pushed branch {$branch} to origin");
        }
        return $pushed;
    }

    /**
     * Commit the run's changes straight onto the checked-out branch and push
     * it to origin's branch of the same name, rebasing onto origin's copy
     * first when that has moved on. When the commit cannot land there
     * (conflicts, a protected branch), it is moved to $fallback and pushed
     * there instead, and the checked-out branch is put back where it started.
     *
     * @return string 'pushed', 'fallback' (pushed to $fallback instead) or '' (nothing pushed)
     */
    public function publishDirect(string $message, string $fallback): string
    {
        $branch = $this->currentBranch();
        if ($branch === '') {
            $this->console->fail('push: --push-direct needs a checked-out branch, but HEAD is detached');
            return '';
        }
        $paths = $this->pathsToCommit();
        if ($paths === null || $paths === []) {
            return '';
        }
        $start = trim($this->git(['rev-parse', 'HEAD'], 30)->stdout);
        if (!$this->commit($message, $paths)) {
            return '';
        }
        // Origin can move between the fetch and the push: allow one retry
        for ($attempt = 1; ; $attempt++) {
            $head    = trim($this->git(['rev-parse', 'HEAD'], 30)->stdout);
            $rebased = $this->rebased($head, $branch);
            if ($rebased === false) {
                break;
            }
            $r = $this->git(['push', '--quiet', 'origin', "{$rebased}:refs/heads/{$branch}"], $this->timeout);
            if ($r->ok()) {
                $this->console->ok("push: pushed the changes straight to {$branch} on origin");
                if ($rebased !== $head && !$this->git(['reset', '--quiet', '--keep', $rebased], 120)->ok()) {
                    $this->console->warn("push: could not move the local {$branch} onto what was pushed, as uncommitted changes are in the way;"
                        . " run `git reset --keep origin/{$branch}` once they are committed or moved aside");
                }
                return 'pushed';
            }
            if ($attempt === 1 && preg_match('/non-fast-forward|fetch first|\(stale info\)/i', $r->output) === 1) {
                continue;
            }
            $this->console->fail("push: push to {$branch} failed (" . $r->failureReason() . ')');
            foreach ($r->tail(6) as $line) {
                $this->console->detail('| ' . GitUrl::redact($line));
            }
            break;
        }

        // The commit could not land: keep it on a side branch, put $branch back
        if (!$this->step(['branch', '--force', $fallback, 'HEAD'], "create branch {$fallback}")) {
            return '';
        }
        if ($start !== '') {
            $this->step(['reset', '--quiet', '--keep', $start], "reset {$branch} to where it started");
        }
        if (!$this->step(['push', '--quiet', '--set-upstream', 'origin', $fallback], "push {$fallback}", $this->timeout)) {
            $this->console->warn("push: the commit is kept on the local branch {$fallback}");
            return '';
        }
        $this->console->warn("push: could not push to {$branch}; pushed branch {$fallback} instead, merge it by hand");
        return 'fallback';
    }

    /**
     * Delete a local branch (after its pull request was merged).
     */
    public function deleteLocalBranch(string $branch): void
    {
        if ($this->currentBranch() !== $branch) {
            $this->git(['branch', '--quiet', '-D', $branch], 60);
        }
    }

    /**
     * Whether the run changed anything that can be committed.
     */
    public function hasChanges(): bool
    {
        $paths = $this->pathsToCommit();
        return $paths !== null && $paths !== [];
    }

    /**
     * The paths to commit, saying (once) which uncommitted changes are left
     * out and why.
     *
     * @return list<string>|null null when git status fails
     */
    private function pathsToCommit(): ?array
    {
        $plan = $this->plan();
        if ($plan === null) {
            $this->console->fail('push: git status failed');
            return null;
        }
        if (!$this->announced) {
            $this->announced = true;
            if ($plan['untouched'] !== []) {
                $this->console->info('push: leaving ' . count($plan['untouched']) . ' path(s) that were already uncommitted before the run'
                    . ' alone, uncommitted: ' . self::names($plan['untouched']));
            }
            if ($plan['conflicted'] !== []) {
                $this->console->warn('push: not committing ' . count($plan['conflicted']) . ' path(s) that had uncommitted changes before the run'
                    . ' and that the run changed too, so the two are not mixed: ' . self::names($plan['conflicted']));
            }
        }
        if ($plan['commit'] === []) {
            $this->console->info($plan['conflicted'] === [] ? 'push: nothing changed, nothing to push' : 'push: nothing else changed, nothing to push');
        }
        return $plan['commit'];
    }

    /**
     * @param list<string> $paths
     */
    private static function names(array $paths): string
    {
        $shown = array_slice($paths, 0, 10);
        return implode(', ', $shown) . (count($paths) > 10 ? ' and ' . (count($paths) - 10) . ' more' : '');
    }

    /**
     * Stage and commit exactly $paths, leaving anything else (other
     * uncommitted changes, whatever was already staged) as it was.
     *
     * @param list<string> $paths
     */
    private function commit(string $message, array $paths): bool
    {
        $list = tempnam(sys_get_temp_dir(), 'dep-sec-patcher-paths-');
        if ($list === false || file_put_contents($list, implode("\0", $paths) . "\0") === false) {
            $this->console->fail('push: could not write the list of paths to commit');
            return false;
        }
        try {
            $from = ['--pathspec-from-file=' . $list, '--pathspec-file-nul'];
            if (!$this->step(array_merge(['--literal-pathspecs', 'add', '--all'], $from), 'stage changes')) {
                return false;
            }
            return $this->step(array_merge($this->identity(), ['--literal-pathspecs', 'commit', '--quiet', '--no-verify', '--only', '-m', $message], $from), 'commit');
        } finally {
            @unlink($list);
        }
    }

    /**
     * $commit replayed onto origin's current $base, when $base has moved on
     * since the tree was checked out. The rebase runs in a temporary work
     * tree of its own, so uncommitted changes in $root are never touched.
     *
     * @return string|false the commit to push ($commit itself when no rebase is needed), false when it conflicts with origin's $base
     */
    private function rebased(string $commit, string $base): string|false
    {
        if (!$this->git(['fetch', '--quiet', 'origin', $base], $this->timeout)->ok()) {
            // Cannot tell; the push will say if it matters
            return $commit;
        }
        $upstream = trim($this->git(['rev-parse', '--verify', '--quiet', 'FETCH_HEAD^{commit}'], 30)->stdout);
        if ($upstream === '' || $this->git(['merge-base', '--is-ancestor', $upstream, $commit], 30)->ok()) {
            return $commit;
        }
        $this->console->info("push: origin's {$base} moved on during the run; rebasing the commit onto it");
        $tmp = sys_get_temp_dir() . '/dep-sec-patcher-rebase-' . bin2hex(random_bytes(6));
        if (!$this->step(['worktree', 'add', '--quiet', '--detach', $tmp, $commit], 'prepare the rebase')) {
            return false;
        }
        try {
            if ($this->git(array_merge($this->identity(), ['rebase', '--quiet', $upstream]), 300, $tmp)->ok()) {
                $rebased = trim($this->git(['rev-parse', 'HEAD'], 30, $tmp)->stdout);
                if ($rebased !== '') {
                    return $rebased;
                }
            }
            $this->git(['rebase', '--abort'], 60, $tmp);
            $this->console->fail("push: the changes conflict with what was merged into origin's {$base} during the run");
            return false;
        } finally {
            $this->git(['worktree', 'remove', '--force', $tmp], 120);
            $this->git(['worktree', 'prune'], 60);
        }
    }

    /**
     * A bot identity, only where git has none configured.
     *
     * @return list<string>
     */
    private function identity(): array
    {
        return trim($this->git(['config', 'user.email'], 30)->stdout) === ''
            ? ['-c', 'user.name=dep-sec-patcher', '-c', 'user.email=dep-sec-patcher@users.noreply.github.com']
            : [];
    }

    /**
     * @param list<string> $args
     */
    private function step(array $args, string $what, int $timeout = 300): bool
    {
        $r = $this->git($args, $timeout);
        if (!$r->ok()) {
            $this->console->fail("push: {$what} failed (" . $r->failureReason() . ')');
            foreach ($r->tail(6) as $line) {
                $this->console->detail('| ' . GitUrl::redact($line));
            }
        }
        return $r->ok();
    }

    /**
     * @param list<string> $args
     */
    private function git(array $args, int $timeout, string $cwd = ''): CommandResult
    {
        return $this->runner->run(array_merge(['git'], TargetResolver::gitOptions(), $args), $cwd !== '' ? $cwd : $this->root, [
            'timeout' => $timeout,
            'label'   => 'git',
            'env'     => TargetResolver::gitEnv(),
        ]);
    }
}
