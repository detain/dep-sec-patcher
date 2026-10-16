<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Turns security-bot issues (Mend/WhiteSource, Snyk, Renovate) into
 * remediation records.
 *
 * Mend Bolt files one issue per CVE, and the body carries everything needed
 * to fix it:
 *   <p>Path to dependency file: /a/b/package.json</p>
 *   <p>Fix Resolution (form-data): 3.0.5</p>
 *   <p>Direct dependency fix Resolution (superagent): 7.0.0</p>
 * and, for some ecosystems, a bare comma-separated list:
 *   <p>Fix Resolution: golang.org/x/net - v0.55.0,https://github.com/... - v0.55.0</p>
 *   <p>Fix Resolution: io.netty:netty-all:4.1.42.Final,...</p>
 * All three shapes are normalised into (package, version) pairs, one record per
 * pair per manifest. This is a line-for-line port of the jq program the shell
 * version used, including its regexes, so stored records keep the same keys.
 *
 * Pure: no I/O.
 */
final class IssueParser
{
    /**
     * @param list<array<string, mixed>> $issues `gh issue list --json number,title,body,url` rows
     * @return list<array<string, mixed>> remediation records
     */
    public static function parse(array $issues): array
    {
        $records = [];
        foreach ($issues as $issue) {
            foreach (self::parseIssue($issue) as $record) {
                $records[] = $record;
            }
        }
        return $records;
    }

    /**
     * @param array<string, mixed> $issue
     * @return list<array<string, mixed>>
     */
    public static function parseIssue(array $issue): array
    {
        $title  = self::utf8((string)($issue['title'] ?? ''));
        $body   = self::utf8((string)($issue['body'] ?? ''));
        $number = $issue['number'] ?? 0;

        if (!str_contains($body, 'Fix Resolution')) {
            return [];
        }

        $cve  = preg_match('/^(?<c>(?:CVE|WS)-[0-9A-Za-z-]+)/u', $title, $m) === 1 ? $m['c'] : '';
        $sev  = preg_match('/\((?<s>Critical|High|Medium|Low)\)/u', $title, $m) === 1 ? $m['s'] : '';
        $cvss = preg_match('/CVSS 3 Score Details \(<b>(?<v>[0-9.]+)<\/b>\)/u', $body, $m) === 1 ? $m['v'] : '0';

        $manifests = [];
        preg_match_all("/Path to dependency file: ([^<\n]+)/u", $body, $mm);
        foreach ($mm[1] as $path) {
            $manifests[] = (string)preg_replace('#^/#', '', self::trim($path), 1);
        }
        $manifests = self::uniqueSorted($manifests);

        // Affected package names, from the title ("detected in js-yaml-3.14.2.tgz")
        // and from the <b>-wrapped filenames in the body, which is the only
        // source when the title just says "detected in multiple libraries".
        $libs = [];
        $detected = preg_match('/detected in (?<l>.+)$/u', $title, $m) === 1 ? $m['l'] : '';
        foreach (explode(',', $detected) as $part) {
            $name = self::libname($part);
            if ($name !== null) {
                $libs[] = $name;
            }
        }
        preg_match_all('/<b>([^<]*\.(?:tgz|jar|whl|gem|nupkg|zip))<\/b>/u', $body, $mm);
        foreach ($mm[1] as $file) {
            $name = self::libname($file);
            if ($name !== null) {
                $libs[] = $name;
            }
        }
        $libs = self::uniqueSorted(array_values(array_filter($libs, static fn ($l) => $l !== '')));

        $fixes = [];
        preg_match_all("/Direct dependency fix Resolution \\(([^)]+)\\): ([^<\n]+)/u", $body, $mm, PREG_SET_ORDER);
        foreach ($mm as $hit) {
            $fixes[] = ['package' => self::cleanPkg($hit[1]), 'version' => self::cleanVer($hit[2]), 'direct' => true];
        }
        preg_match_all("/(?:^|>|\\s)Fix Resolution \\(([^)]+)\\): ([^<\n]+)/u", $body, $mm, PREG_SET_ORDER);
        foreach ($mm as $hit) {
            $fixes[] = ['package' => self::cleanPkg($hit[1]), 'version' => self::cleanVer($hit[2]), 'direct' => false];
        }
        preg_match_all("/(?:^|>|\\s)Fix Resolution: ([^<\n]+)/u", $body, $mm);
        foreach ($mm[1] as $list) {
            foreach (explode(',', $list) as $entry) {
                $entry = self::trim($entry);
                if ($entry === '') {
                    continue;
                }
                foreach (self::bareEntry($entry, $libs) as $fix) {
                    $fixes[] = $fix + ['direct' => false];
                }
            }
        }

        if ($fixes === [] || $manifests === []) {
            return [];
        }

        $id      = $cve === '' ? 'ISSUE-' . $number : $cve;
        $records = [];
        foreach ($fixes as $fix) {
            if ($fix['package'] === '' || $fix['version'] === '') {
                continue;
            }
            foreach ($manifests as $manifest) {
                $records[] = [
                    // Keyed on identity, not issue number, so a refiled issue for
                    // the same CVE/package/manifest updates the existing record
                    'key'              => $manifest . '|' . $fix['package'] . '|' . $id,
                    'source'           => 'issue',
                    'id'               => $id,
                    'cve'              => $cve,
                    'ref'              => $number,
                    // Mend files the same CVE against the same manifest several
                    // times; carry every issue number so closing retires them all
                    'refs'             => [$number],
                    // Advisories list a fix per release branch; keep them all
                    'fix_versions'     => [$fix['version']],
                    'ecosystem'        => '',
                    'package'          => $fix['package'],
                    'manifest'         => $manifest,
                    'manifests'        => $manifests,
                    'scope'            => '',
                    'severity'         => strtolower($sev),
                    'cvss'             => is_numeric($cvss) ? $cvss + 0 : 0,
                    'vulnerable_range' => '',
                    'fixed_version'    => $fix['version'],
                    'direct'           => $fix['direct'],
                    'summary'          => $title,
                    'url'              => (string)($issue['url'] ?? ''),
                ];
            }
        }
        return $records;
    }

    /**
     * One entry of a bare "Fix Resolution: a, b, c" list.
     *
     * @param list<string> $libs
     * @return list<array{package: string, version: string}>
     */
    private static function bareEntry(string $entry, array $libs): array
    {
        $gav = self::gav($entry);
        if ($gav !== null) {
            return [$gav];
        }
        $dashed = self::dashed($entry);
        if ($dashed !== null) {
            return [$dashed];
        }
        // Bare "Fix Resolution: 3.15.0" names no package; pair the version with
        // each affected library instead of dropping it.
        if (preg_match('/^[0-9]/u', $entry) === 1) {
            $out = [];
            foreach ($libs as $lib) {
                $out[] = ['package' => $lib, 'version' => self::cleanVer($entry)];
            }
            return $out;
        }
        return [];
    }

    /**
     * "io.netty:netty-all:4.1.42.Final" -> io.netty:netty-all @ 4.1.42.Final
     *
     * @return array{package: string, version: string}|null
     */
    private static function gav(string $s): ?array
    {
        if (preg_match('/^(?<g>[A-Za-z0-9_.-]+):(?<a>[A-Za-z0-9_.-]+):(?<v>[^,\s]+)$/u', $s, $m) !== 1) {
            return null;
        }
        return ['package' => self::cleanPkg($m['g'] . ':' . $m['a']), 'version' => self::cleanVer($m['v'])];
    }

    /**
     * "golang.org/x/net - v0.55.0" and
     * "https://github.com/x/y.git - jackson-databind-2.18.8"; the artifact-name
     * prefix some git tags carry is stripped from the version.
     *
     * @return array{package: string, version: string}|null
     */
    private static function dashed(string $s): ?array
    {
        if (preg_match('/^(?<n>.+?)\s+-\s+(?<v>\S+)$/u', $s, $m) !== 1) {
            return null;
        }
        $name = $m['n'];
        if (preg_match('#^https?://|\.git$#u', $name) === 1) {
            $parts = explode('/', (string)preg_replace('/\.git$/u', '', $name, 1));
            $name  = (string)end($parts);
        }
        $version = $m['v'];
        if (str_starts_with($version, $name . '-')) {
            $version = substr($version, strlen($name) + 1);
        }
        return ['package' => self::cleanPkg($name), 'version' => self::cleanVer($version)];
    }

    /**
     * "js-yaml-3.14.2.tgz" -> "js-yaml", "urllib3-2.6.3-py3-none-any.whl" -> "urllib3".
     * Needed because some issues state only a bare "Fix Resolution: 3.15.0"
     * and name the package nowhere except the vulnerable-library filenames.
     */
    private static function libname(string $s): ?string
    {
        $s = self::trim(self::printable($s));
        $s = (string)preg_replace('/\.(tgz|jar|whl|gem|nupkg|zip|egg|tar\.gz|tar|min\.js)$/u', '', $s, 1);
        if (preg_match('/^(?<n>.*?)-(?<v>[0-9][0-9A-Za-z.]*)/u', $s, $m) !== 1) {
            return null;
        }
        return $m['n'];
    }

    /**
     * Bot-rendered HTML smuggles invisible characters (U+2060 word joiner and
     * friends) into package names; they must go or every lookup misses.
     */
    private static function cleanPkg(string $s): string
    {
        return self::trim(self::printable($s));
    }

    private static function cleanVer(string $s): string
    {
        $s = self::trim(self::printable($s));
        $s = (string)preg_replace('/^[vV]_/u', '', $s, 1);
        $s = (string)preg_replace('/^[vV](?=[0-9])/u', '', $s, 1);
        return self::trim($s);
    }

    private static function printable(string $s): string
    {
        return (string)preg_replace('/[^\x20-\x7E]/u', '', $s);
    }

    private static function trim(string $s): string
    {
        return (string)preg_replace('/^\s+|\s+$/u', '', $s);
    }

    /**
     * jq `unique`: sorted by codepoint, duplicates removed.
     *
     * @param list<string> $values
     * @return list<string>
     */
    private static function uniqueSorted(array $values): array
    {
        $values = array_values(array_unique($values));
        sort($values, SORT_STRING);
        return $values;
    }

    /**
     * The /u patterns reject invalid UTF-8 outright, which would silently drop
     * the issue; substitute the bad bytes instead.
     */
    private static function utf8(string $s): string
    {
        return mb_check_encoding($s, 'UTF-8') ? $s : mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }
}
