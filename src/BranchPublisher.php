<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * --push: commit what an update-mode run changed to a new branch and push it
 * to origin, then put the working tree back on the branch it started on.
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
     * @return bool whether a branch was pushed
     */
    public function publish(string $branch, string $message, string $githubRepo = ''): bool
    {
        $c      = $this->console;
        $status = $this->git(['status', '--porcelain'], 120);
        if (!$status->ok()) {
            $c->fail('push: git status failed (' . $status->failureReason() . ')');
            return false;
        }
        if (trim($status->stdout) === '') {
            $c->info('push: nothing changed, no branch created');
            return false;
        }

        $start = $this->git(['rev-parse', '--abbrev-ref', 'HEAD'], 30);
        $back  = trim($start->stdout);
        if ($back === 'HEAD' || $back === '') {
            $back = trim($this->git(['rev-parse', 'HEAD'], 30)->stdout);
        }

        if (!$this->step(['checkout', '--quiet', '-b', $branch], "create branch {$branch}")) {
            return false;
        }
        try {
            if (!$this->step(['add', '--all'], 'stage changes')) {
                return false;
            }
            // Fall back to a bot identity only where git has none configured
            $identity = trim($this->git(['config', 'user.email'], 30)->stdout) === ''
                ? ['-c', 'user.name=dep-sec-patcher', '-c', 'user.email=dep-sec-patcher@users.noreply.github.com']
                : [];
            if (!$this->step(array_merge($identity, ['commit', '--quiet', '--no-verify', '-m', $message]), 'commit')) {
                return false;
            }
            $pushed = $this->step(['push', '--quiet', '--set-upstream', 'origin', $branch], "push {$branch}", $this->timeout);
            if ($pushed) {
                $c->ok("push: pushed branch {$branch} to origin");
                if ($githubRepo !== '') {
                    $c->info("open a pull request: gh pr create --repo {$githubRepo} --head {$branch} --fill");
                }
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
        return $this->runner->run(array_merge(['git'], $args), $this->root, [
            'timeout' => $timeout,
            'label'   => 'git',
            'env'     => TargetResolver::gitEnv(),
        ]);
    }
}
