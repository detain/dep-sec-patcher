<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * The versions a lockfile resolved a package to. Where a lockfile exists it
 * is the truth about what gets installed: a manifest's "*" or "^1.2.0" says
 * nothing about whether the vulnerable 1.2.3 is still locked, and a
 * transitive dependency is not in the manifest at all.
 *
 * Reads yarn.lock (v1 and Berry), package-lock.json / npm-shrinkwrap.json
 * (v1 to v3), pnpm-lock.yaml and composer.lock.
 */
final class Lockfile
{
    private const NPM_LOCKS = ['yarn.lock', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml'];

    /**
     * The lockfile names one ecosystem (as ManifestPaths::ecosystemFor names
     * them) reads. The close-fixed memory watches for these appearing in a
     * directory that had none — the one event that can turn "no lockfile"
     * into a verifiable verdict.
     *
     * @return list<string>
     */
    public static function lockNamesFor(string $ecosystem): array
    {
        return match ($ecosystem) {
            'npm'      => self::NPM_LOCKS,
            'composer' => ['composer.lock'],
            default    => [],
        };
    }

    /**
     * Every version the lockfiles in $dir hold for $pkg, or null when $dir
     * has no lockfile for that ecosystem ("npm" or "composer", as
     * ManifestPaths::ecosystemFor names them). An empty list means the lockfile
     * does not contain the package.
     *
     * @return list<string>|null
     */
    public static function versions(string $dir, string $ecosystem, string $pkg): ?array
    {
        $files = self::lockNamesFor($ecosystem);
        $found    = false;
        $versions = [];
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            if (!is_file($path)) {
                continue;
            }
            $found    = true;
            $content  = (string)file_get_contents($path);
            $versions = array_merge($versions, self::parse($file, $content, $pkg));
        }
        if (!$found) {
            return null;
        }
        $versions = array_values(array_unique($versions));
        return Version::sortAscending($versions);
    }

    /**
     * Whether $dir holds a lockfile for the ecosystem that cannot be decoded
     * into a dependency tree. A corrupt lock parses to the same empty list
     * as a lock that genuinely lacks the package, and "not found" must never
     * be trusted as "evicted". Line-based formats (yarn, pnpm) have no
     * detectable decode failure here — their parse miss and their corrupt
     * read are the same shape — so only the JSON locks are judged.
     */
    public static function unreadable(string $dir, string $ecosystem): bool
    {
        foreach (self::lockNamesFor($ecosystem) as $file) {
            $path = $dir . '/' . $file;
            if (is_file($path) && !self::decodes($file, (string)file_get_contents($path))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the named lockfile's content parses at all: the JSON ones must
     * decode to an object or array; nothing else can fail in a way we see.
     */
    private static function decodes(string $file, string $content): bool
    {
        if (!in_array($file, ['package-lock.json', 'npm-shrinkwrap.json', 'composer.lock'], true)) {
            return true;
        }
        return is_array(json_decode($content, true));
    }

    /**
     * @return list<string>
     */
    public static function parse(string $file, string $content, string $pkg): array
    {
        return match ($file) {
            'yarn.lock'                                  => self::yarn($content, $pkg),
            'package-lock.json', 'npm-shrinkwrap.json'   => self::npm($content, $pkg),
            'pnpm-lock.yaml'                             => self::pnpm($content, $pkg),
            'composer.lock'                              => self::composer($content, $pkg),
            default                                      => [],
        };
    }

    /**
     * yarn v1:   "qs@^6.11.0", qs@~6.5.2:\n  version "6.11.2"
     * yarn Berry: "qs@npm:^6.11.0":\n  version: 6.11.2
     *
     * @return list<string>
     */
    private static function yarn(string $content, string $pkg): array
    {
        $out     = [];
        $current = false;
        foreach (preg_split('/\r?\n/', $content) ?: [] as $line) {
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if ($line[0] !== ' ') {
                $current = false;
                foreach (explode(',', rtrim($line, ':')) as $descriptor) {
                    $descriptor = trim($descriptor, " \t\"'");
                    // The name ends at the last "@" that is not the scope's
                    $at = strrpos($descriptor, '@');
                    if ($at !== false && $at > 0 && substr($descriptor, 0, $at) === $pkg) {
                        $current = true;
                    }
                }
                continue;
            }
            if ($current && preg_match('/^\s+version:?\s+"?([^"\s]+)"?\s*$/', $line, $m) === 1) {
                $out[]   = $m[1];
                $current = false;
            }
        }
        return $out;
    }

    /**
     * v2/v3 "packages": {"node_modules/a/node_modules/qs": {"version": ..}};
     * v1 nested "dependencies".
     *
     * @return list<string>
     */
    private static function npm(string $content, string $pkg): array
    {
        $doc = json_decode($content, true);
        if (!is_array($doc)) {
            return [];
        }
        $out = [];
        if (is_array($doc['packages'] ?? null)) {
            foreach ($doc['packages'] as $path => $meta) {
                $path = (string)$path;
                if ((str_ends_with($path, 'node_modules/' . $pkg)) && is_array($meta) && isset($meta['version'])
                    && !($meta['link'] ?? false)) {
                    $out[] = (string)$meta['version'];
                }
            }
            return $out;
        }
        $walk = static function (array $deps) use (&$walk, &$out, $pkg): void {
            foreach ($deps as $name => $meta) {
                if (!is_array($meta)) {
                    continue;
                }
                if ((string)$name === $pkg && isset($meta['version'])) {
                    $out[] = (string)$meta['version'];
                }
                if (is_array($meta['dependencies'] ?? null)) {
                    $walk($meta['dependencies']);
                }
            }
        };
        if (is_array($doc['dependencies'] ?? null)) {
            $walk($doc['dependencies']);
        }
        return $out;
    }

    /**
     * Package keys: v9 "qs@6.11.2:", v6 "/qs@6.11.2:", v5 "/qs/6.11.2:",
     * each optionally quoted and followed by a "(peer@x)" suffix.
     *
     * @return list<string>
     */
    private static function pnpm(string $content, string $pkg): array
    {
        $q   = preg_quote($pkg, '/');
        $out = [];
        preg_match_all('/^\s+[\'"]?\/?' . $q . '[@\/]([0-9][^:(\'"\s]*)/m', $content, $m);
        foreach ($m[1] as $v) {
            $out[] = $v;
        }
        return $out;
    }

    /**
     * @return list<string>
     */
    private static function composer(string $content, string $pkg): array
    {
        $doc = json_decode($content, true);
        if (!is_array($doc)) {
            return [];
        }
        $out = [];
        foreach (['packages', 'packages-dev'] as $section) {
            foreach (is_array($doc[$section] ?? null) ? $doc[$section] : [] as $p) {
                if (is_array($p) && strtolower((string)($p['name'] ?? '')) === strtolower($pkg) && isset($p['version'])) {
                    $out[] = (string)preg_replace('/^v(?=\d)/', '', (string)$p['version']);
                }
            }
        }
        return $out;
    }
}
