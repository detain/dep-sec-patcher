<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use Detain\DepSecPatcher\Auditor\MavenPom;

/**
 * Which versions a package registry publishes, asked once per package and
 * kept for the run, so a fix can be checked against reality before it is
 * written into a manifest: "io.netty:netty-codec-http2 7.0.12" and
 * "lodash 4.18.0" exist in no registry, and a pin to them breaks the build.
 *
 * Three answers, never a guess: the list of published versions, or null when
 * the registry could not be asked (offline, a private package public
 * registries have never heard of, DEP_SEC_PATCHER_OFFLINE set, or an
 * ecosystem not covered here). Callers treat null as "unknown" and let the
 * fix through - a check that cannot answer must not block one.
 *
 * The HTTP layer is injected, so tests answer from fixtures: the same seam
 * AdvisoryLookup uses for OSV, widened from POST-only to GET.
 */
final class RegistryProbe
{
    public const MAVEN_CENTRAL = 'https://repo1.maven.org/maven2';
    public const NPM_REGISTRY  = 'https://registry.npmjs.org';
    public const PYPI          = 'https://pypi.org/pypi';

    /** @var array<string, list<string>|null> ecosystem|package => versions or null */
    private array $cache = [];
    /** @var callable(string): ?string */
    private $http;

    /**
     * @param (callable(string): ?string)|null $http GETs a URL; the body, or
     *        null on any failure. Default: PHP's stream wrapper, unless the
     *        run is told to stay offline.
     */
    public function __construct(?callable $http = null)
    {
        $this->http = $http ?? static function (string $url): ?string {
            return self::offline() ? null : self::httpGet($url);
        };
    }

    /**
     * Every version the registry publishes for a package, or null when it
     * cannot be said: unknown ecosystems, Maven names without a groupId, and
     * any failed lookup answer null, never a partial list.
     *
     * @return list<string>|null
     */
    public function versions(string $ecosystem, string $package): ?array
    {
        $ecosystem = strtolower($ecosystem) === 'pypi' ? 'pip' : strtolower($ecosystem);
        $key       = $ecosystem . '|' . $package;
        if (array_key_exists($key, $this->cache)) {
            return $this->cache[$key];
        }
        return $this->cache[$key] = match ($ecosystem) {
            'maven' => $this->mavenVersions($package),
            'npm'   => $this->npmVersions($package),
            'pip'   => $this->pipVersions($package),
            default => null,
        };
    }

    /**
     * Whether $version is published: false only when the package's full
     * version list was read and does not hold it.
     */
    public function exists(string $ecosystem, string $package, string $version): ?bool
    {
        $versions = $this->versions($ecosystem, $package);
        return $versions === null ? null : in_array($version, $versions, true);
    }

    /**
     * @return list<string>|null
     */
    private function mavenVersions(string $package): ?array
    {
        if (!str_contains($package, ':')) {
            return null;  // without a groupId the Central path is unknown
        }
        [$group, $artifact] = explode(':', $package, 2);
        if (preg_match('/^[\w.-]+$/', $group . $artifact) !== 1) {
            return null;
        }
        $url = self::MAVEN_CENTRAL . '/' . str_replace('.', '/', $group) . '/' . $artifact . '/maven-metadata.xml';
        $xml = ($this->http)($url);
        if (!is_string($xml)) {
            return null;
        }
        $found = MavenPom::metadataVersions($xml);
        return $found === [] ? null : $found;
    }

    /**
     * @return list<string>|null
     */
    private function npmVersions(string $package): ?array
    {
        if (preg_match('#^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$#', $package) !== 1) {
            return null;
        }
        $doc  = $this->json(self::NPM_REGISTRY . '/' . str_replace('/', '%2F', $package));
        $list = is_array($doc) && is_array($doc['versions'] ?? null) ? array_keys($doc['versions']) : null;
        return $list === null ? null : array_map('strval', $list);
    }

    /**
     * @return list<string>|null
     */
    private function pipVersions(string $package): ?array
    {
        $name = strtolower((string)preg_replace('/[-_.]+/', '-', $package));
        if (preg_match('/^[a-z0-9][a-z0-9._-]*$/', $name) !== 1) {
            return null;
        }
        $doc      = $this->json(self::PYPI . '/' . $name . '/json');
        $releases = is_array($doc) && is_array($doc['releases'] ?? null) ? $doc['releases'] : null;
        if ($releases === null) {
            return null;
        }
        // A release with no files was yanked and removed; it cannot install
        $out = [];
        foreach ($releases as $version => $files) {
            if (is_array($files) && $files !== []) {
                $out[] = (string)$version;
            }
        }
        return $out;
    }

    /**
     * @return array<mixed>|null
     */
    private function json(string $url): ?array
    {
        $body = ($this->http)($url);
        if (!is_string($body)) {
            return null;
        }
        $doc = json_decode($body, true);
        return is_array($doc) ? $doc : null;
    }

    /**
     * Whether this run was told to ask no registry
     * (DEP_SEC_PATCHER_OFFLINE=1): for air-gapped hosts and for tests that
     * drive the whole binary without a network.
     */
    public static function offline(): bool
    {
        $flag = getenv('DEP_SEC_PATCHER_OFFLINE');
        return $flag !== false && $flag !== '' && $flag !== '0';
    }

    /**
     * GET $url; the body on HTTP 200, null on any other answer. 404 means the
     * package does not exist here at all, which is "cannot be said" rather
     * than "publishes nothing": a private proxy's package must not be
     * declared nonexistent because the public registry never heard of it.
     */
    public static function httpGet(string $url): ?string
    {
        $context  = stream_context_create(['http' => [
            'timeout'       => 15,
            'user_agent'    => 'dep-sec-patcher',
            'header'        => "Accept: application/xml, application/json;q=0.9\r\n",
            'ignore_errors' => true,
        ]]);
        $response = @file_get_contents($url, false, $context);
        $headers  = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : $http_response_header;
        $status   = is_string($headers[0] ?? null) && preg_match('#^HTTP/\S+\s+(\d{3})#', $headers[0], $m) === 1 ? (int)$m[1] : 0;
        return $response === false || $status !== 200 ? null : $response;
    }
}
