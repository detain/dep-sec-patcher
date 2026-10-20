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
        if (!$r->ok() && str_contains($r->output, 'unknown flag')) {
            // gh before 2.48 has no --slurp: one compact JSON item per line instead
            $r = $this->run(['api', '--paginate', $path, '--jq', '.[] | tojson'], 600);
            $httpStatus = preg_match('/HTTP (\d{3})/', $r->output, $m) === 1 ? (int)$m[1] : null;
            if (!$r->ok()) {
                return null;
            }
            $items = [];
            foreach (preg_split('/\r?\n/', trim($r->stdout)) ?: [] as $line) {
                $item = json_decode($line, true);
                if ($line !== '' && !is_array($item)) {
                    return null;
                }
                if (is_array($item)) {
                    $items[] = $item;
                }
            }
            return $items;
        }
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

    /** Issues per GraphQL page; the API's maximum. */
    public const ISSUE_PAGE = 100;

    /** Pull requests per REST page; the API's maximum. */
    public const PULL_PAGE = 100;

    /**
     * Read a REST list endpoint a page at a time until a short page says it
     * is the end. `gh pr list` has no page flag, so this pages the API's own
     * `page=` parameter instead. $fetch takes the 1-based page number and
     * returns that page's decoded rows, or null when the call failed. A
     * failure after some rows already arrived yields what was read with
     * $complete still false: acting on a part of the listing is fine,
     * concluding that the missing rest is gone is not.
     *
     * @param callable(int): (list<array<string, mixed>>|null) $fetch
     * @param-out bool $complete
     * @return list<array<string, mixed>>
     */
    public static function collectPulls(callable $fetch, ?bool &$complete = null, int $maxPages = 100): array
    {
        $complete = false;
        $rows     = [];
        for ($page = 1; $page <= $maxPages; $page++) {
            $rowsOnPage = $fetch($page);
            if ($rowsOnPage === null) {
                return $rows;
            }
            foreach ($rowsOnPage as $row) {
                $rows[] = $row;
            }
            if (count($rowsOnPage) < self::PULL_PAGE) {
                $complete = true;
                return $rows;
            }
        }
        return $rows;
    }

    /**
     * Every open issue (up to $limit, 0 = all), newest first, in the shape
     * `gh issue list --json number,title,body,url,author` gives. Read a page
     * of 100 at a time through GraphQL with a cursor, so one failed page is
     * retried on its own instead of the whole listing, and the rate limit
     * each page reports is respected. $complete says whether every open
     * issue was read; null when the listing failed.
     *
     * @param-out bool $complete
     * @return list<array<string, mixed>>|null
     */
    public function openIssues(string $repo, int $limit = 0, bool $withBody = true, ?bool &$complete = null): ?array
    {
        $complete = false;
        [$owner, $name] = array_pad(explode('/', $repo, 2), 2, '');
        if ($owner === '' || $name === '') {
            return null;
        }
        $fields = $withBody ? 'number title body url author { login __typename }' : 'number';
        $query  = 'query($owner: String!, $name: String!, $first: Int!, $after: String) {'
            . ' repository(owner: $owner, name: $name) {'
            . ' issues(states: OPEN, first: $first, after: $after, orderBy: {field: CREATED_AT, direction: DESC}) {'
            . " totalCount pageInfo { hasNextPage endCursor } nodes { {$fields} } } }"
            . ' rateLimit { remaining resetAt } }';
        $fetch = function (?string $after, int $first) use ($query, $owner, $name): array|string {
            $args = ['api', 'graphql', '-f', "query={$query}", '-f', "owner={$owner}", '-f', "name={$name}", '-F', "first={$first}"];
            if ($after !== null) {
                $args[] = '-f';
                $args[] = "after={$after}";
            }
            $r = $this->run($args, 300);
            $data = json_decode($r->stdout, true);
            // gh exits non-zero on GraphQL errors but still prints the body
            if (is_array($data) && isset($data['data']['repository']['issues']) && empty($data['errors'])) {
                return $data;
            }
            $errors = is_array($data) && is_array($data['errors'] ?? null) ? json_encode($data['errors']) : '';
            return trim($r->output . ' ' . $errors) ?: 'gh api graphql failed';
        };
        return self::collectIssues($fetch, $limit, static function (int $s): void {
            sleep($s);
        }, $this->console, $complete);
    }

    /**
     * The paging behind openIssues(), apart from gh so it can be tested.
     *
     * $fetch(cursor, pageSize) returns the decoded GraphQL response, or the
     * error text. A rate-limit error waits for the reset (or backs off);
     * anything else - usually a 502 when a page of large bodies takes too
     * long to render - halves the page and tries again.
     *
     * @param callable(?string, int): (array<string, mixed>|string) $fetch
     * @param callable(int): void $sleep
     * @param-out bool $complete
     * @return list<array<string, mixed>>|null
     */
    public static function collectIssues(callable $fetch, int $limit, callable $sleep, ?Console $console = null, ?bool &$complete = null): ?array
    {
        $complete = false;
        $issues   = [];
        $after    = null;
        $size     = self::ISSUE_PAGE;
        $failures = 0;
        $resetAt  = null;
        while (true) {
            $first = $limit > 0 ? min($size, $limit - count($issues)) : $size;
            $page  = $fetch($after, $first);
            if (is_string($page)) {
                if (++$failures > 6) {
                    $console?->warn('issue listing failed after ' . count($issues) . ' issues: ' . substr(str_replace("\n", ' ', $page), 0, 200));
                    return null;
                }
                if (preg_match('/rate.?limit|abuse|secondary|HTTP 429|HTTP 403/i', $page) === 1) {
                    $wait = $resetAt !== null ? max(5, min(3600, $resetAt - time() + 5)) : 60 * $failures;
                    $console?->warn("issue listing rate limited; waiting {$wait}s");
                    $sleep($wait);
                } else {
                    $size = max(10, intdiv($size, 2));
                    $console?->warn("issue listing page failed ({$failures}/6); retrying with {$size} per page");
                    $sleep(min(30, 2 * $failures));
                }
                continue;
            }
            $failures = 0;
            $conn     = $page['data']['repository']['issues'];
            foreach ((array)($conn['nodes'] ?? []) as $node) {
                if (!is_array($node) || !isset($node['number'])) {
                    continue;
                }
                $author = is_array($node['author'] ?? null) ? $node['author'] : null;
                $issues[] = ['number' => (int)$node['number']]
                    + (array_key_exists('body', $node) ? [
                        'title'  => (string)($node['title'] ?? ''),
                        'body'   => (string)($node['body'] ?? ''),
                        'url'    => (string)($node['url'] ?? ''),
                        'author' => $author === null ? null : [
                            'login'  => (string)($author['login'] ?? ''),
                            'is_bot' => ($author['__typename'] ?? '') === 'Bot',
                        ],
                    ] : []);
            }
            $more  = ($conn['pageInfo']['hasNextPage'] ?? false) === true;
            $after = is_string($conn['pageInfo']['endCursor'] ?? null) ? $conn['pageInfo']['endCursor'] : null;
            if (!$more || $after === null) {
                $complete = !$more;
                return $issues;
            }
            if ($limit > 0 && count($issues) >= $limit) {
                return $issues;
            }
            // A page that went through after a failure lets the size grow back
            $size = min(self::ISSUE_PAGE, $size * 2);
            $rate = $page['data']['rateLimit'] ?? null;
            $resetAt = is_array($rate) && is_string($rate['resetAt'] ?? null) ? (strtotime($rate['resetAt']) ?: null) : null;
            if (is_array($rate) && is_int($rate['remaining'] ?? null) && $rate['remaining'] < 10 && $resetAt !== null) {
                $wait = max(5, min(3600, $resetAt - time() + 5));
                $console?->warn("GraphQL quota nearly spent ({$rate['remaining']} left); waiting {$wait}s for the reset");
                $sleep($wait);
            }
        }
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
        // Only the account gh will use matters: plain `auth status` fails
        // when any stored account's token is stale, even an inactive one
        $r = $this->run(['auth', 'status', '--active'], 60);
        if (!$r->ok() && str_contains($r->output, 'unknown flag')) {
            // gh before 2.40 has no --active
            $r = $this->run(['auth', 'status'], 60);
        }
        return $r->ok();
    }
}
