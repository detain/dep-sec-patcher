<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * --push, --pr and --push-direct: commit what an update-mode run changed and
 * push it to origin, either on a new branch (put back on the branch the tree
 * started on afterwards) or straight onto the checked-out branch.
 *
 * Only a tree that was clean before the run is published, so nothing but
 * this run's changes can end up in the commit. A remote target's cache clone
 * is always clean at the start.
 */
final class BranchPublisher
{
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
        $r = $this->git(['status', '--porcelain', '-z', '--untracked-files=all'], 120);
        if (!$r->ok()) {
            return [];
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
            }
        }
        return $files;
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
            $this->console->warn("push: {$branch} has diverged from origin's {$branch}; not fast-forwarding it");
            return false;
        }
        $this->console->info("push: fast-forwarded {$branch} to origin's {$branch}");
        return true;
    }

    /**
     * Commit the changes to a new branch, rebased onto origin's $base when
     * that has moved on during the run, push it, and check the starting
     * branch back out. A commit that conflicts with origin's $base is pushed
     * as it is, so the conflict shows up for review.
     *
     * @return bool whether the branch was pushed
     */
    public function publish(string $branch, string $message, string $base = ''): bool
    {
        if (!$this->hasChanges()) {
            return false;
        }
        $back = $this->currentBranch();
        if ($back === '') {
            $back = trim($this->git(['rev-parse', 'HEAD'], 30)->stdout);
        }

        if (!$this->step(['checkout', '--quiet', '-b', $branch], "create branch {$branch}")) {
            return false;
        }
        try {
            if (!$this->commit($message)) {
                return false;
            }
            if ($base !== '') {
                $this->rebaseOnto($base);
            }
            $pushed = $this->step(['push', '--quiet', '--set-upstream', 'origin', $branch], "push {$branch}", $this->timeout);
            if ($pushed) {
                $this->console->ok("push: pushed branch {$branch} to origin");
            }
            return $pushed;
        } finally {
            // Leave the working tree where it started; the changes live on the branch
            if ($back !== '') {
                $this->git(['checkout', '--quiet', $back], 120);
            }
        }
    }

    /**
     * Commit the changes straight onto the checked-out branch and push it to
     * origin's branch of the same name, rebasing onto origin's copy first
     * when that has moved on. When the commit cannot land there (conflicts,
     * a protected branch), it is moved to $fallback and pushed there instead,
     * and the checked-out branch is put back where it started.
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
        if (!$this->hasChanges()) {
            return '';
        }
        $start = trim($this->git(['rev-parse', 'HEAD'], 30)->stdout);
        if (!$this->commit($message)) {
            return '';
        }
        // Origin can move between the fetch and the push: allow one retry
        for ($attempt = 1; ; $attempt++) {
            if (!$this->rebaseOnto($branch)) {
                break;
            }
            $r = $this->git(['push', '--quiet', 'origin', "HEAD:refs/heads/{$branch}"], $this->timeout);
            if ($r->ok()) {
                $this->console->ok("push: pushed the changes straight to {$branch} on origin");
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

    public function hasChanges(): bool
    {
        $status = $this->git(['status', '--porcelain'], 120);
        if (!$status->ok()) {
            $this->console->fail('push: git status failed (' . $status->failureReason() . ')');
            return false;
        }
        if (trim($status->stdout) === '') {
            $this->console->info('push: nothing changed, nothing to push');
            return false;
        }
        return true;
    }

    private function commit(string $message): bool
    {
        if (!$this->step(['add', '--all'], 'stage changes')) {
            return false;
        }
        return $this->step(array_merge($this->identity(), ['commit', '--quiet', '--no-verify', '-m', $message]), 'commit');
    }

    /**
     * Replay HEAD's commit onto origin's current $base, when $base has moved
     * on since the tree was checked out. On a conflict the rebase is
     * abandoned and HEAD is left as it was.
     *
     * @return bool false when the commit conflicts with origin's $base
     */
    private function rebaseOnto(string $base): bool
    {
        if (!$this->git(['fetch', '--quiet', 'origin', $base], $this->timeout)->ok()) {
            // Cannot tell; the push will say if it matters
            return true;
        }
        if ($this->git(['merge-base', '--is-ancestor', 'FETCH_HEAD', 'HEAD'], 30)->ok()) {
            return true;
        }
        $this->console->info("push: origin's {$base} moved on during the run; rebasing the commit onto it");
        if ($this->git(array_merge($this->identity(), ['rebase', '--quiet', 'FETCH_HEAD']), 300)->ok()) {
            return true;
        }
        $this->git(['rebase', '--abort'], 60);
        $this->console->fail("push: the changes conflict with what was merged into origin's {$base} during the run");
        return false;
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
    private function git(array $args, int $timeout): CommandResult
    {
        return $this->runner->run(array_merge(['git'], TargetResolver::gitOptions(), $args), $this->root, [
            'timeout' => $timeout,
            'label'   => 'git',
            'env'     => TargetResolver::gitEnv(),
        ]);
    }
}
