<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Thin wrapper over the gh CLI. Every call has a timeout and none can block
 * on a prompt; failures return null so callers can tell "the API failed" from
 * "there is nothing", which the original shell script's `2>/dev/null` could not.
 */
final class GitHub
{
    public bool $ready = false;
    public string $slug = '';

    public function __construct(
        private ProcessRunner $runner,
        private Console $console,
        private string $cwd
    ) {
    }

    /**
     * Cron and systemd runs do not source ~/.bashrc, so gh would silently have
     * no token; harvest GH_TOKEN/GITHUB_TOKEN from the usual rc files instead
     * of skipping every GitHub check.
     */
    public function ensureAuth(): bool
    {
        if (!ProcessRunner::has('gh')) {
            $this->console->skip('gh (not installed - GitHub checks unavailable)');
            return false;
        }
        if ($this->authOk()) {
            return $this->ready = true;
        }
        foreach (TokenHarvester::rcFiles() as $rc) {
            $token = TokenHarvester::fromContent((string)@file_get_contents($rc), ['GH_TOKEN', 'GITHUB_TOKEN']);
            if ($token === null) {
                continue;
            }
            putenv('GH_TOKEN=' . $token);
            if ($this->authOk()) {
                $this->console->info("gh: authenticated with token harvested from {$rc}");
                return $this->ready = true;
            }
        }
        $this->console->warn('gh is installed but not authenticated (no usable GH_TOKEN found)');
        $this->console->info("Tip: add 'export GH_TOKEN=...' to ~/.bashrc or run 'gh auth login'");
        return false;
    }

    /**
     * Canonical OWNER/NAME for a repository (from --repo or the target's
     * origin remote), run through the API so a renamed or differently-cased
     * repo resolves to its current name. Falls back to the input when the
     * lookup fails.
     */
    public function resolveRepo(string $repo): string
    {
        if ($this->slug !== '') {
            return $this->slug;
        }
        $slug = $repo;
        $info = $this->json(['api', "repos/{$slug}"], 60);
        if (is_array($info) && !empty($info['full_name'])) {
            $slug = (string)$info['full_name'];
        }
        return $this->slug = $slug;
    }

    /**
     * Run gh and decode its JSON stdout; null on failure.
     *
     * @param list<string> $args
     */
    public function json(array $args, int $timeout = 300): mixed
    {
        $r = $this->run($args, $timeout);
        if (!$r->ok()) {
            return null;
        }
        return json_decode($r->stdout, true);
    }

    /**
     * All pages of a list endpoint, flattened; null when the API call failed.
     *
     * @return list<array<string, mixed>>|null
     */
    public function paginate(string $path, ?int &$httpStatus = null): ?array
    {
        $r = $this->run(['api', '--paginate', '--slurp', $path], 600);
        $httpStatus = preg_match('/HTTP (\d{3})/', $r->output, $m) === 1 ? (int)$m[1] : null;
        if (!$r->ok()) {
            return null;
        }
        $pages = json_decode($r->stdout, true);
        if (!is_array($pages)) {
            return null;
        }
        $items = [];
        foreach ($pages as $page) {
            foreach ((array)$page as $item) {
                $items[] = $item;
            }
        }
        return $items;
    }

    /**
     * Open issues with bodies. Retried: one transient failure here would
     * otherwise drop the entire issue set for the run.
     *
     * @return list<array<string, mixed>>|null
     */
    public function openIssues(string $repo, int $limit, string $fields): ?array
    {
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $data = $this->json(['issue', 'list', '--repo', $repo, '--state', 'open', '--limit', (string)$limit, '--json', $fields], 900);
            if (is_array($data) && array_is_list($data)) {
                return $data;
            }
            $this->console->warn("issue list attempt {$attempt}/3 failed for {$repo}");
            sleep($attempt * 3);
        }
        return null;
    }

    /**
     * @param list<string> $args
     */
    public function run(array $args, int $timeout = 300): CommandResult
    {
        return $this->runner->run(array_merge(['gh'], $args), $this->cwd, ['timeout' => $timeout, 'label' => 'gh']);
    }

    /**
     * @phpstan-impure the answer changes once a token is exported
     */
    private function authOk(): bool
    {
        return $this->run(['auth', 'status'], 60)->ok();
    }
}
