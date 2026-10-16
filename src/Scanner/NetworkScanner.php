<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Scanner;

/**
 * Heuristic content checks: plain-HTTP endpoints in config files, hardcoded
 * credentials, and old TLS versions.
 *
 * The original shell script used `rg` with a look-ahead, which ripgrep rejects without
 * -P, and ran each check in a subshell whose counts were discarded, so these
 * checks always reported "OK". This is a plain PHP scan over the indexed files.
 *
 * Pure: the file reader is injected.
 */
final class NetworkScanner
{
    private const CONFIG_EXT = ['yaml', 'yml', 'json', 'toml'];
    private const MAX_BYTES  = 2 * 1024 * 1024;

    /**
     * http:// URLs that are identifiers, not endpoints: XML/JSON-schema
     * namespaces, licence links, loopback, documentation hosts. Prefixes of the
     * URL after "http://"; extend them with --allow-http or the config file's
     * "allow-http" list.
     */
    public const DEFAULT_HTTP_ALLOWED = [
        'localhost', '127.0.0.1', '0.0.0.0', '[::1]', 'www.w3.org/', 'json-schema.org/', 'www.apache.org/licenses',
        'opensource.org/', 'maven.apache.org/', 'xmlns.', 'schemas.', 'purl.org/', 'example.com', 'example.org',
        'example.net', 'petstore.swagger.io',
    ];

    /**
     * Assignment patterns; group 1 is the value, checked against PLACEHOLDER.
     */
    private const CREDENTIALS = [
        'password'    => '/password\s*=\s*["\']([^"\']+)["\']/',
        'api key'     => '/api[_-]?key\s*=\s*["\']([^"\']{8,})["\']/',
        'secret'      => '/secret\s*=\s*["\']([^"\']+)["\']/',
        'token'       => '/token\s*=\s*["\']([^"\']{16,})["\']/',
        'aws key'     => '/\b(AKIA[0-9A-Z]{16})\b/',
        'private key' => '/private[_-]?key\s*=\s*["\'](-----BEGIN)/',
    ];

    /**
     * Values generators and docs use as stand-ins ("password_example",
     * "YOUR_API_KEY", "xxx"), and code fragments rather than literals.
     */
    private const PLACEHOLDER = '/example|^your\b|your[\s_-]|xxx|changeme|change_me|placeholder|dummy|sample|redacted|\$GLOBALS|^[<{$%]|^\*+$|^\.+$|^\s*$/i';

    /**
     * @param list<string> $files     relative paths
     * @param callable     $read      (relative path): ?string file content, null to skip
     * @param list<string> $allowHttp extra allowed plain-HTTP prefixes, added to DEFAULT_HTTP_ALLOWED
     * @return array{http: list<string>, credentials: array<string, list<string>>, tls: list<string>}
     */
    public static function scan(array $files, callable $read, array $allowHttp = []): array
    {
        $allowed = self::allowPattern($allowHttp);
        $found   = ['http' => [], 'credentials' => [], 'tls' => []];
        foreach ($files as $file) {
            $ext  = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            if (preg_match('/\.(lock|sum)$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/', $file) === 1) {
                continue;
            }
            $isConfig = in_array($ext, self::CONFIG_EXT, true);
            $isTlsCfg = $isConfig || $ext === 'properties';
            $content  = $read($file);
            if ($content === null || str_contains(substr($content, 0, 8192), "\0")) {
                continue;
            }

            if ($isConfig && preg_match('/example|test/', $file) !== 1) {
                if (preg_match_all('#http://[^\s"\'<>)]+#', $content, $m) > 0) {
                    foreach ($m[0] as $url) {
                        if (preg_match($allowed, $url) !== 1) {
                            $found['http'][] = $file;
                            break;
                        }
                    }
                }
            }
            foreach (self::CREDENTIALS as $kind => $rx) {
                if (preg_match_all($rx, $content, $m) > 0) {
                    foreach ($m[1] as $value) {
                        if (preg_match(self::PLACEHOLDER, $value) !== 1) {
                            $found['credentials'][$kind][] = $file;
                            break;
                        }
                    }
                }
            }
            if ($isTlsCfg && preg_match('/TLSv1\.0|TLSv1\.1|sslversi/', $content) === 1) {
                $found['tls'][] = $file;
            }
        }
        return $found;
    }

    /**
     * Reader bounded to MAX_BYTES, for the real run.
     */
    public static function fileReader(string $root): callable
    {
        return static function (string $rel) use ($root): ?string {
            $abs = $root . '/' . $rel;
            if (!is_file($abs) || filesize($abs) > self::MAX_BYTES) {
                return null;
            }
            $content = @file_get_contents($abs);
            return $content === false ? null : $content;
        };
    }

    /**
     * Regex matching an allowed plain-HTTP URL: the defaults plus $extra,
     * each a prefix of the URL after "http://" in which * matches anything.
     *
     * @param list<string> $extra
     */
    public static function allowPattern(array $extra = []): string
    {
        $alternatives = [];
        foreach (array_merge(self::DEFAULT_HTTP_ALLOWED, $extra) as $prefix) {
            $prefix = (string)preg_replace('#^http://#i', '', $prefix);
            if ($prefix === '') {
                continue;
            }
            $alternatives[] = implode('.*', array_map(static fn (string $part): string => preg_quote($part, '#'), explode('*', $prefix)));
        }
        return '#^http://(?:' . implode('|', $alternatives) . ')#i';
    }
}
