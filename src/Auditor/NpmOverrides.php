<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Version;

/**
 * npm "overrides" for what `npm audit fix` leaves behind: a vulnerable copy
 * that a parent pins exactly (zapier-platform-core's form-data 4.0.5, mocha
 * 8's minimatch 3.0.4), which audit fix can only "fix" by moving the parent
 * a major version, often downwards.
 *
 * Each vulnerable copy is pinned to the lowest published release that clears
 * every advisory npm reported for that package, on the release line the copy
 * is on. A package locked on several lines gets one override per line
 * ("minimatch@3"), so copies on a line that is not affected stay where they
 * are. Crossing a line needs --allow-major. A package every version of which
 * is affected ("braces  *") has no fix to pin.
 *
 * Pure: the lockfile and the registry arrive as callables.
 */
final class NpmOverrides
{
    /**
     * @param array<string, mixed>               $audit     `npm audit --json`
     * @param callable(string): list<string>     $copies    versions the lockfile holds for a package
     * @param callable(string): ?list<string>    $published versions on the registry, null when unknown
     * @param array<string, mixed>               $existing  the manifest's current "overrides"
     * @param array<string, true>                $direct    packages the manifest declares
     * @return array{overrides: array<string, string>, notes: list<string>}
     */
    public static function plan(array $audit, callable $copies, callable $published, array $existing, array $direct, bool $allowMajor): array
    {
        $overrides = [];
        $notes     = [];
        $vulns     = is_array($audit['vulnerabilities'] ?? null) ? $audit['vulnerabilities'] : [];
        ksort($vulns, SORT_STRING);
        foreach ($vulns as $name => $vuln) {
            $name   = (string)$name;
            $ranges = [];
            foreach (is_array($vuln['via'] ?? null) ? $vuln['via'] : [] as $via) {
                // A string names a dependency that is vulnerable, not an advisory
                if (is_array($via) && is_string($via['range'] ?? null)) {
                    $ranges[] = $via['range'];
                }
            }
            if ($ranges === [] || preg_match('#^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$#', $name) !== 1) {
                continue;
            }
            if (array_filter($ranges, [self::class, 'everything']) !== []) {
                continue;   // no release is unaffected
            }
            $locked     = $copies($name);
            $vulnerable = array_values(array_filter($locked, static fn (string $v): bool => self::affected($v, $ranges)));
            if ($vulnerable === []) {
                continue;
            }
            $available = $published($name);
            if ($available === null) {
                continue;
            }
            $releases = array_values(array_filter($available, static fn (string $v): bool => preg_match('/^\d+\.\d+\.\d+$/', $v) === 1
                && !self::affected($v, $ranges)));
            $lockedLines = array_values(array_unique(array_map([Version::class, 'majorLine'], $locked)));
            $byLine      = [];
            foreach ($vulnerable as $v) {
                $byLine[Version::majorLine($v)][] = $v;
            }
            foreach ($byLine as $line => $onLine) {
                $line   = (string)$line;
                $newest = Version::max($onLine);
                $above  = array_values(array_filter($releases, static fn (string $v): bool => Version::gte($v, $newest) && $v !== $newest));
                $same   = array_values(array_filter($above, static fn (string $v): bool => Version::majorLine($v) === $line));
                $target = $same !== [] ? Version::sortAscending($same)[0] : '';
                if ($target === '' && $above !== []) {
                    if (!$allowMajor) {
                        $notes[] = "{$name} {$newest} has no fixed release on its {$line}.x line; overriding it needs --allow-major";
                        continue;
                    }
                    $target  = Version::sortAscending($above)[0];
                    $notes[] = "{$name} {$newest} -> {$target} crosses a major version (--allow-major)";
                }
                if ($target === '') {
                    continue;
                }
                // A plain key would also move copies on other lines, and npm
                // refuses one that differs from a direct dependency's spec
                $key = !isset($direct[$name]) && $lockedLines === [$line] ? $name : "{$name}@{$line}";
                if (isset($existing[$key]) && !is_string($existing[$key])) {
                    continue;   // a nested override is somebody's deliberate choice
                }
                $overrides[$key] = '^' . $target;
            }
        }
        return ['overrides' => $overrides, 'notes' => $notes];
    }

    /**
     * Whether a version falls in any of npm's advisory ranges.
     *
     * @param list<string> $ranges
     */
    public static function affected(string $version, array $ranges): bool
    {
        foreach ($ranges as $range) {
            if (self::satisfies($version, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * node-semver's satisfies() for the ranges npm audit prints: "||"
     * alternatives of comparator sets ("<3.1.4", ">=2.0.0 <2.0.2"), hyphen
     * ranges ("5.0.0 - 5.2.1"), x-ranges, caret, tilde and "*".
     */
    public static function satisfies(string $version, string $range): bool
    {
        foreach (explode('||', $range) as $alt) {
            $alt = trim((string)preg_replace('/(<=|>=|<|>|=|\^|~)\s+/', '$1', trim($alt)));
            if (preg_match('/^(\S+)\s+-\s+(\S+)$/', $alt, $m) === 1) {
                $alt = '>=' . $m[1] . ' <=' . $m[2];
            }
            $ok = true;
            foreach ($alt === '' ? [] : (preg_split('/\s+/', $alt) ?: []) as $comp) {
                if (!self::comparator($version, $comp)) {
                    $ok = false;
                    break;
                }
            }
            if ($ok) {
                return true;
            }
        }
        return false;
    }

    private static function everything(string $range): bool
    {
        return in_array(trim($range), ['', '*', 'x', '>=0', '>=0.0.0'], true);
    }

    private static function comparator(string $version, string $comp): bool
    {
        if (preg_match('/^(<=|>=|<|>|=|\^|~)?v?(.*)$/', $comp, $m) !== 1) {
            return false;
        }
        [$op, $p] = [$m[1], self::parts($m[2])];
        if ($p === []) {
            return !in_array($op, ['<', '>'], true);   // "*", "x", ">=*"
        }
        $full = count($p) === 3;
        $base = implode('.', array_pad($p, 3, 0)) . ($full ? self::prerelease($m[2]) : '');
        if ($op === '^' || $op === '~' || ($op === '' || $op === '=') && !$full) {
            // A range with an exclusive upper bound
            return Version::gte($version, $base) && !Version::gte($version, self::ceiling($op, $p));
        }
        return match ($op) {
            '<'     => !Version::gte($version, $base),
            '>='    => Version::gte($version, $base),
            // A partial bound covers its whole line: "<=5.2" admits 5.2.9
            '<='    => $full ? !Version::gte($version, $base) || self::same($version, $base) : !Version::gte($version, self::ceiling('', $p)),
            '>'     => $full ? Version::gte($version, $base) && !self::same($version, $base) : Version::gte($version, self::ceiling('', $p)),
            default => self::same($version, $base),
        };
    }

    /**
     * The exclusive upper bound of a caret, tilde or partial range.
     *
     * @param list<int> $p
     */
    private static function ceiling(string $op, array $p): string
    {
        [$major, $minor, $patch] = array_pad($p, 3, 0);
        if ($op === '^') {
            return match (true) {
                $major > 0 || count($p) === 1  => ($major + 1) . '.0.0',
                $minor > 0 || count($p) === 2  => "0." . ($minor + 1) . '.0',
                default                        => "0.0." . ($patch + 1),
            };
        }
        return count($p) === 1 ? ($major + 1) . '.0.0' : "{$major}." . ($minor + 1) . '.0';
    }

    private static function same(string $a, string $b): bool
    {
        return Version::gte($a, $b) && Version::gte($b, $a);
    }

    /**
     * @return list<int> the numeric parts before any wildcard
     */
    private static function parts(string $v): array
    {
        $out = [];
        foreach (explode('.', (string)preg_replace('/[-+].*$/', '', $v)) as $part) {
            if (!ctype_digit($part)) {
                break;
            }
            $out[] = (int)$part;
        }
        return array_slice($out, 0, 3);
    }

    private static function prerelease(string $v): string
    {
        return preg_match('/^\d+\.\d+\.\d+(-[^+]+)/', $v, $m) === 1 ? $m[1] : '';
    }
}
