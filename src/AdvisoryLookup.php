<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Fixed versions of one vulnerability in one package, from OSV
 * (https://osv.dev), for issues whose own fix list is no use: empty, or only
 * a release on another major line (jackson-databind 3.x lives under
 * tools.jackson.core, so it fixes nothing for com.fasterxml's 2.x).
 *
 * Asks once per package, for every advisory OSV has against it, and keeps the
 * answer, reduced to advisory id (and every alias) => fixed versions, in a
 * cache file for a day: two hundred jackson issues cost one request.
 *
 * Any failure (no network, an HTTP error, a body that is not OSV's) answers
 * null, which callers treat as "no fix known", so the issue is handled as it
 * was before. After a few failures in a row it stops asking for the rest of
 * the run.
 */
final class AdvisoryLookup
{
    public const QUERY_URL = 'https://api.osv.dev/v1/query';
    private const TTL = 86400;
    private const MAX_FAILURES = 3;
    private const MAX_PAGES = 20;

    /** @var array<string, array{at: int, fixes: array<string, list<string>>}> "eco|package" => what OSV said */
    private array $cache = [];
    private bool $loaded = false;
    private int $failures = 0;
    /** @var array<string, true> packages that failed this run, not asked again */
    private array $failed = [];
    /** @var callable(string, string): ?string url, JSON request body => response body, null on failure */
    private $post;
    private int $requests = 0;

    /**
     * @param string $cacheFile '' keeps answers in memory only
     * @param (callable(string, string): ?string)|null $post the HTTP layer; null uses PHP's stream wrapper
     */
    public function __construct(
        private string $cacheFile = '',
        ?callable $post = null,
        private ?Console $console = null,
        private ?int $now = null,
    ) {
        $this->post = $post ?? [self::class, 'httpPost'];
    }

    /**
     * The OSV ecosystem of a manifest, '' when OSV has none for it.
     */
    public static function osvEcosystem(string $manifest): string
    {
        if (basename($manifest) === 'build.sbt') {
            return 'Maven';
        }
        return match (ManifestPaths::ecosystemFor($manifest)) {
            'maven', 'gradle' => 'Maven',
            'npm'             => 'npm',
            'pip'             => 'PyPI',
            'composer'        => 'Packagist',
            'go'              => 'Go',
            'nuget'           => 'NuGet',
            'rubygems'        => 'RubyGems',
            'cargo'           => 'crates.io',
            'hex'             => 'Hex',
            'pub'             => 'Pub',
            'swift'           => 'SwiftURL',
            default           => '',
        };
    }

    /**
     * Every version OSV names as fixing advisory $id (a CVE, GHSA or other id
     * OSV knows, directly or as an alias) in $package, lowest first. [] when
     * OSV knows of no fix; null when OSV could not be asked.
     *
     * @return list<string>|null
     */
    public function fixedVersions(string $ecosystem, string $package, string $id): ?array
    {
        if ($ecosystem === '' || $package === '' || $id === '') {
            return null;
        }
        $fixes = $this->package($ecosystem, $package);
        return $fixes === null ? null : ($fixes[strtoupper($id)] ?? []);
    }

    /**
     * As a callable for IssueParser::parse().
     *
     * @return callable(string, string, string): ?list<string>
     */
    public function asCallable(): callable
    {
        return fn (string $eco, string $pkg, string $id): ?array => $this->fixedVersions($eco, $pkg, $id);
    }

    /** HTTP requests made so far, for the run log. */
    public function requests(): int
    {
        return $this->requests;
    }

    /**
     * @return array<string, list<string>>|null
     */
    private function package(string $ecosystem, string $package): ?array
    {
        $key = $ecosystem . '|' . $package;
        $this->load();
        $now = $this->now ?? time();
        if (isset($this->cache[$key]) && $now - $this->cache[$key]['at'] < self::TTL) {
            return $this->cache[$key]['fixes'];
        }
        if (isset($this->failed[$key]) || $this->failures >= self::MAX_FAILURES) {
            return null;
        }
        $fixes = $this->fetch($ecosystem, $package);
        if ($fixes === null) {
            $this->failed[$key] = true;
            if (++$this->failures === self::MAX_FAILURES) {
                $this->console?->warn('OSV: ' . self::MAX_FAILURES . ' lookups failed; not asking again this run');
            }
            return null;
        }
        $this->failures    = 0;
        $this->cache[$key] = ['at' => $now, 'fixes' => $fixes];
        $this->save();
        return $fixes;
    }

    /**
     * @return array<string, list<string>>|null
     */
    private function fetch(string $ecosystem, string $package): ?array
    {
        $byId  = [];
        $token = '';
        for ($page = 0; $page < self::MAX_PAGES; $page++) {
            $query = ['package' => ['ecosystem' => $ecosystem, 'name' => $package]] + ($token !== '' ? ['page_token' => $token] : []);
            $this->requests++;
            $body = ($this->post)(self::QUERY_URL, (string)json_encode($query));
            $data = is_string($body) ? json_decode($body, true) : null;
            if (!is_array($data) || (isset($data['vulns']) && !is_array($data['vulns']))) {
                return null;
            }
            foreach (is_array($data['vulns'] ?? null) ? $data['vulns'] : [] as $vuln) {
                if (!is_array($vuln)) {
                    continue;
                }
                $fixed = self::fixedIn($vuln, $ecosystem, $package);
                $ids   = array_merge([$vuln['id'] ?? null], is_array($vuln['aliases'] ?? null) ? $vuln['aliases'] : []);
                foreach ($ids as $id) {
                    if (is_string($id) && $id !== '') {
                        $id        = strtoupper($id);
                        $byId[$id] = Version::sortAscending(array_values(array_unique(array_merge($byId[$id] ?? [], $fixed))));
                    }
                }
            }
            $token = is_string($data['next_page_token'] ?? null) ? $data['next_page_token'] : '';
            if ($token === '') {
                ksort($byId, SORT_STRING);
                return $byId;
            }
        }
        return null;
    }

    /**
     * The "fixed" events of one OSV record's ranges for $package.
     *
     * @param array<mixed> $vuln
     * @return list<string>
     */
    private static function fixedIn(array $vuln, string $ecosystem, string $package): array
    {
        $out = [];
        foreach (is_array($vuln['affected'] ?? null) ? $vuln['affected'] : [] as $affected) {
            $pkg = is_array($affected) && is_array($affected['package'] ?? null) ? $affected['package'] : [];
            if (strcasecmp((string)($pkg['ecosystem'] ?? ''), $ecosystem) !== 0 || !self::sameName((string)($pkg['name'] ?? ''), $package, $ecosystem)) {
                continue;
            }
            foreach (is_array($affected['ranges'] ?? null) ? $affected['ranges'] : [] as $range) {
                if (!is_array($range) || !in_array($range['type'] ?? '', ['ECOSYSTEM', 'SEMVER'], true)) {
                    continue;
                }
                foreach (is_array($range['events'] ?? null) ? $range['events'] : [] as $event) {
                    $fixed = is_array($event) ? ($event['fixed'] ?? null) : null;
                    // Ends up in a manifest, so only plain versions
                    if (is_string($fixed) && preg_match('/^v?[0-9][0-9A-Za-z.+_~-]*$/', $fixed) === 1) {
                        $out[] = (string)preg_replace('/^v(?=[0-9])/', '', $fixed);
                    }
                }
            }
        }
        return $out;
    }

    private static function sameName(string $a, string $b, string $ecosystem): bool
    {
        // PyPI treats case and - _ . as equivalent; NuGet ignores case
        return match ($ecosystem) {
            'PyPI'  => strtolower((string)preg_replace('/[-_.]+/', '-', $a)) === strtolower((string)preg_replace('/[-_.]+/', '-', $b)),
            'NuGet' => strcasecmp($a, $b) === 0,
            default => $a === $b,
        };
    }

    private function load(): void
    {
        if ($this->loaded) {
            return;
        }
        $this->loaded = true;
        if ($this->cacheFile === '' || !is_file($this->cacheFile)) {
            return;
        }
        $data = json_decode((string)@file_get_contents($this->cacheFile), true);
        foreach (is_array($data['packages'] ?? null) ? $data['packages'] : [] as $key => $entry) {
            if (!is_string($key) || !is_array($entry) || !is_int($entry['at'] ?? null) || !is_array($entry['fixes'] ?? null)) {
                continue;
            }
            $fixes = [];
            foreach ($entry['fixes'] as $id => $versions) {
                if (is_string($id) && is_array($versions)) {
                    $fixes[$id] = array_values(array_filter($versions, 'is_string'));
                }
            }
            $this->cache[$key] = ['at' => $entry['at'], 'fixes' => $fixes];
        }
    }

    private function save(): void
    {
        if ($this->cacheFile === '') {
            return;
        }
        $dir = dirname($this->cacheFile);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            return;
        }
        // Written aside and renamed, so a concurrent run never reads half a file
        $tmp = $this->cacheFile . '.' . getmypid() . '.tmp';
        if (@file_put_contents($tmp, (string)json_encode(['packages' => $this->cache], JSON_UNESCAPED_SLASHES)) !== false) {
            @rename($tmp, $this->cacheFile);
        }
    }

    /**
     * POST $body as JSON; the response body on HTTP 200, else null.
     */
    public static function httpPost(string $url, string $body): ?string
    {
        $context = stream_context_create(['http' => [
            'method'        => 'POST',
            'header'        => "Content-Type: application/json\r\nAccept: application/json\r\nUser-Agent: dep-sec-patcher\r\n",
            'content'       => $body,
            'timeout'       => 30,
            'ignore_errors' => true,
        ]]);
        $response = @file_get_contents($url, false, $context);
        $headers  = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : $http_response_header;
        $status   = is_string($headers[0] ?? null) && preg_match('#^HTTP/\S+\s+(\d{3})#', $headers[0], $m) === 1 ? (int)$m[1] : 0;
        return $response === false || $status !== 200 ? null : $response;
    }
}
