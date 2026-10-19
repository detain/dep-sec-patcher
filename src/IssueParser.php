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
 * pair per manifest. It began as a port of the jq program the shell version
 * used; it differs where that program named the wrong package.
 *
 * A bare list names packages loosely: a git URL stands for its repository
 * ("netty" for io.netty:netty-codec-http2), alternatives sit side by side
 * (bcprov-lts8on next to bcprov-jdk18on), and tarball names drop the npm
 * scope ("core-7.29.0.tgz" is @babel/core). The paths Mend found the
 * libraries at say exactly which packages the issue is about, so a bare list
 * is narrowed to those.
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
        $url    = (string)($issue['url'] ?? '');

        // "Path to dependency file:", or "Sample Path to Dependency File:" in
        // the grouped format
        $manifests = [];
        preg_match_all("/Path to dependency file: ([^<\n]+)/iu", $body, $mm);
        foreach ($mm[1] as $path) {
            $path = self::manifestPath($path);
            if ($path !== '') {
                $manifests[] = $path;
            }
        }
        $manifests = self::uniqueSorted($manifests);
        if ($manifests === []) {
            return [];
        }

        $cve = preg_match('/^(?<c>(?:CVE|WS)-[0-9A-Za-z-]+)/u', $title, $m) === 1 ? $m['c'] : '';
        if ($cve === '' && preg_match('/^## Vulnerabilities/mu', $body) === 1) {
            return self::grouped($title, $body, $number, $url, $manifests);
        }
        if (!str_contains($body, 'Fix Resolution')) {
            return [];
        }
        $sev  = preg_match('/\((?<s>Critical|High|Medium|Low)\)/u', $title, $m) === 1 ? $m['s'] : '';
        $cvss = preg_match('/CVSS 3 Score Details \(<b>(?<v>[0-9.]+)<\/b>\)/u', $body, $m) === 1 ? $m['v'] : '0';
        $id   = $cve === '' ? 'ISSUE-' . $number : $cve;
        $installed = self::installed($body);
        return self::records(self::fixes($title, $body, self::affected($body), $installed), $id, $cve, $sev, $cvss, $number, $title, $url, $manifests, $installed);
    }

    /**
     * Mend's grouped format: one issue per vulnerable library, a summary
     * table with a row per CVE, then a <details> section per CVE carrying its
     * own "Fix Resolution". GitHub's size limit truncates the sections
     * ("Partial details (22 vulnerabilities)"), so a CVE with no section is
     * taken from its table row, whose "Fixed in (axios version)" column names
     * the library the issue is about.
     *
     * A CVE with no known fix becomes a record without a fixed version, so
     * close-fixed can never call the issue resolved while it stands.
     *
     * @param list<string> $manifests
     * @return list<array<string, mixed>>
     */
    private static function grouped(string $title, string $body, mixed $number, string $url, array $manifests): array
    {
        $affected = self::affected($body);
        $library  = preg_match('/Fixed in \((?<l>[^)]+?) version\)/u', $body, $m) === 1 ? self::cleanPkg($m['l']) : '';
        if ($library === '') {
            $library = (string)(self::libname(preg_match('/^(\S+?):/u', $title, $m) === 1 ? $m[1] : '') ?? '');
        }
        $library = self::qualify($library, $affected);

        $sections = [];
        $parts    = preg_split('/<summary>\s*(?=(?:CVE|WS)-[0-9A-Za-z-]+\s*<\/summary>)/u', $body) ?: [];
        foreach (array_slice($parts, 1) as $part) {
            if (preg_match('/^((?:CVE|WS)-[0-9A-Za-z-]+)/u', $part, $m) === 1) {
                $sections[$m[1]] = $part;
            }
        }

        $records = [];
        preg_match_all('/^\|\s*\[(?<id>(?:CVE|WS)-[0-9A-Za-z-]+)\][^|]*\|[^|]*?(?<sev>Critical|High|Medium|Low)\s*\|\s*(?<cvss>[0-9.]*)\s*\|[^|]*\|[^|]*\|\s*(?<fix>[^|]*?)\s*\|/mu', $body, $rows, PREG_SET_ORDER);
        foreach ($rows as $row) {
            $id    = $row['id'];
            $fixes = [];
            if (isset($sections[$id])) {
                $fixes = self::fixes('', $sections[$id], self::affected($sections[$id]) ?: $affected);
            } elseif ($library !== '' && preg_match('/^(?:.+?\s+-\s+)?v?([0-9][^\s|]*)$/u', $row['fix'], $m) === 1) {
                $fixes = [['package' => $library, 'version' => self::cleanVer($m[1]), 'direct' => true]];
            }
            $fixes = array_values(array_filter($fixes, static fn ($f) => $f['package'] !== '' && $f['version'] !== ''));
            if ($fixes === [] && $library !== '') {
                // No fix known for this CVE: keep the issue from being closed
                $fixes = [['package' => $library, 'version' => '', 'direct' => true]];
            }
            $records = array_merge(
                $records,
                self::records($fixes, $id, $id, $row['sev'], $row['cvss'] !== '' ? $row['cvss'] : '0', $number, $title, $url, $manifests)
            );
        }
        return $records;
    }

    /**
     * The (package, version) pairs a body's "Fix Resolution" lines name.
     *
     * @param list<string> $affected the vulnerable libraries' full names, from affected()
     * @param array<string, list<array{0: string, 1: string}>> $installed from installed()
     * @return list<array{package: string, version: string, direct: bool}>
     */
    private static function fixes(string $title, string $body, array $affected, array $installed = []): array
    {
        // Affected package names, from the title ("detected in js-yaml-3.14.2.tgz")
        // and from the <b>-wrapped filenames in the body, which is the only
        // source when the title just says "detected in multiple libraries".
        // A file name stands for a full name the paths gave unless none matches.
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
        foreach ($libs as $lib) {
            if ($lib !== '' && array_filter($affected, static fn (string $a): bool => self::sameLibrary($lib, $a)) === []) {
                $affected[] = $lib;
            }
        }
        $affected = self::uniqueSorted($affected);

        $fixes = [];
        preg_match_all("/Direct dependency fix Resolution \\(([^)]+)\\): ([^<\n]+)/u", $body, $mm, PREG_SET_ORDER);
        foreach ($mm as $hit) {
            $fixes[] = ['package' => self::cleanPkg($hit[1]), 'version' => self::cleanVer($hit[2]), 'direct' => true];
        }
        preg_match_all("/(?:^|>|\\s)Fix Resolution \\(([^)]+)\\): ([^<\n]+)/u", $body, $mm, PREG_SET_ORDER);
        foreach ($mm as $hit) {
            $fixes[] = ['package' => self::cleanPkg($hit[1]), 'version' => self::cleanVer($hit[2]), 'direct' => false];
        }
        $named = $repos = $versions = [];
        preg_match_all("/(?:^|>|\\s)Fix Resolution: ([^<\n]+)/u", $body, $mm);
        foreach ($mm[1] as $list) {
            foreach (explode(',', $list) as $entry) {
                $entry = self::trim($entry);
                if ($entry === '') {
                    continue;
                }
                $gav    = self::gav($entry);
                $dashed = $gav === null ? self::dashed($entry) : null;
                if ($gav !== null) {
                    $named[] = $gav;
                } elseif ($dashed !== null && $dashed['repo']) {
                    $repos[] = $dashed;
                } elseif ($dashed !== null) {
                    $named[] = ['package' => $dashed['package'], 'version' => $dashed['version']];
                } elseif (preg_match('/^[0-9]/u', $entry) === 1) {
                    // Bare "Fix Resolution: 3.15.0" names no package; pair the version with
                    // each affected library instead of dropping it.
                    $versions[] = self::cleanVer($entry);
                }
            }
        }
        $inUse = [];
        foreach ($installed as $pairs) {
            foreach ($pairs as [$name, $version]) {
                $inUse[] = [$name, Version::majorLine($version)];
            }
        }
        foreach (self::bareList($named, $repos, $versions, $affected, $inUse) as $fix) {
            $fixes[] = $fix + ['direct' => false];
        }
        return $fixes;
    }

    /**
     * The fixes of a bare "Fix Resolution:" list, narrowed to the libraries the
     * issue reports. Entries for other packages are alternatives or sister
     * artifacts that no manifest has to carry; a repository tag stands for the
     * version of the libraries built from it. When nothing in the list can be
     * tied to a reported library, it is taken as written.
     *
     * @param list<array{package: string, version: string}>             $named
     * @param list<array{package: string, version: string, repo: bool}> $repos
     * @param list<string>                                              $versions
     * @param list<string>                                              $affected
     * @param list<array{0: string, 1: string}>                         $inUse    [name, major line] found in use
     * @return list<array{package: string, version: string}>
     */
    private static function bareList(array $named, array $repos, array $versions, array $affected, array $inUse = []): array
    {
        $out = [];
        foreach ($named as $fix) {
            foreach ($affected as $lib) {
                if (self::sameLibrary($fix['package'], $lib)) {
                    // "json-schema-ref-parser - 15.3.6" is the scoped package the path names
                    $out[] = ['package' => self::isQualified($fix['package']) ? $fix['package'] : $lib, 'version' => $fix['version']];
                }
            }
        }
        // The tags of a library's own repository add its other release
        // branches (spring-boot 3.3.14 beside 3.5.14), but only on a major
        // line the list already names for it: jackson-databind's 3.x tags
        // belong to tools.jackson.core, not com.fasterxml.jackson.core
        $listed = $out;
        foreach ($listed !== [] ? $repos : [] as $tag) {
            $line = Version::majorLine($tag['version']);
            foreach ($listed as $fix) {
                if ($line !== '' && Version::majorLine($fix['version']) === $line
                    && self::normal(self::shortName($fix['package'])) === self::normal($tag['package'])) {
                    $out[] = ['package' => $fix['package'], 'version' => $tag['version']];
                }
            }
        }
        if ($out === [] && $affected !== []) {
            foreach ($repos as $fix) {
                // "r1rv85" is a tag, not a version
                if (preg_match('/^[0-9]/', $fix['version']) !== 1) {
                    continue;
                }
                // The library the repository is named after, if the issue reports
                // it; otherwise every library reported, as a monorepo builds them all
                $own = array_values(array_filter($affected, static fn (string $lib): bool => self::normal(self::shortName($lib)) === self::normal($fix['package'])));
                foreach ($own !== [] ? $own : $affected as $lib) {
                    // A Maven or Go library's next major can ship under other
                    // coordinates (jackson-databind 3 is tools.jackson.core's,
                    // not com.fasterxml.jackson.core's), so for one of those a
                    // tag is its version on a major line in use, or where the
                    // list names a sister package (same groupId) at that
                    // version. multiparty 4.3.0 is still multiparty
                    $lines   = array_column(array_filter($inUse, static fn (array $u): bool => self::sameLibrary($u[0], $lib) || self::sameLibrary($lib, $u[0])), 1);
                    $sisters = array_filter($named, static fn (array $n): bool => $n['version'] === $fix['version']
                        && self::family($n['package']) !== '' && self::family($n['package']) === self::family($lib));
                    if ($lines === [] || !self::renamedAcrossMajors($lib) || in_array(Version::majorLine($fix['version']), $lines, true) || $sisters !== []) {
                        $out[] = ['package' => $lib, 'version' => $fix['version']];
                    }
                }
            }
        }
        if ($out === []) {
            $out = array_merge($named, $affected === []
                ? array_map(static fn (array $f): array => ['package' => $f['package'], 'version' => $f['version']], $repos)
                : []);
        }
        foreach ($versions as $version) {
            foreach ($affected as $lib) {
                $out[] = ['package' => $lib, 'version' => $version];
            }
        }
        $unique = [];
        foreach ($out as $fix) {
            $unique[$fix['package'] . '@' . $fix['version']] = $fix;
        }
        return array_values($unique);
    }

    /**
     * Full names of the vulnerable libraries, from where Mend found them: a
     * Maven, Gradle or Ivy cache path carries the groupId, a node_modules path
     * the npm scope, the Go module cache the module path. npm's registry URL
     * on the "Library home page" line keeps the scope too.
     *
     * @return list<string>
     */
    private static function affected(string $body): array
    {
        $found = [];
        preg_match_all('/Path to vulnerable library: ([^<\n]+)/iu', $body, $mm);
        foreach ($mm[1] as $list) {
            foreach (explode(',', self::printable($list)) as $path) {
                $name = self::libraryAt(self::trim($path))[0];
                if ($name !== '') {
                    $found[] = $name;
                }
            }
        }
        preg_match_all('#registry\.npmjs\.org/((?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+)/-/#', self::printable($body), $mm);
        foreach ($mm[1] as $name) {
            $found[] = $name;
        }
        return self::uniqueSorted($found);
    }

    /**
     * The versions of the vulnerable libraries in use, per manifest. Each
     * library has a section headed by its file name
     * ("<b>netty-codec-http2-4.1.76.Final.jar</b></summary>") that names the
     * dependency file it came in through and the paths it was found at.
     *
     * @return array<string, list<array{0: string, 1: string}>> manifest => [name, version] pairs
     */
    private static function installed(string $body): array
    {
        $parts = preg_split('#<b>([^<]+)</b>\s*</summary>#u', $body, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [];
        $out   = [];
        for ($i = 1; $i + 1 < count($parts); $i += 2) {
            $file    = self::trim(self::printable($parts[$i]));
            $name    = self::libname($file);
            $version = $name === null ? '' : self::fileVersion($file, $name);
            $found   = $name !== null && $version !== '' ? [[$name, $version]] : [];
            preg_match_all('/Path to vulnerable library: ([^<\n]+)/iu', $parts[$i + 1], $mm);
            foreach ($mm[1] as $list) {
                foreach (explode(',', self::printable($list)) as $path) {
                    // One library per section, so the file name's version is a
                    // node_modules path's too
                    [$lib, $at] = self::libraryAt(self::trim($path));
                    if ($lib !== '' && ($at !== '' || $version !== '')) {
                        $found[] = [$lib, $at !== '' ? $at : $version];
                    }
                }
            }
            preg_match_all('/Path to dependency file: ([^<\n]+)/iu', $parts[$i + 1], $mm);
            foreach ($mm[1] as $manifest) {
                $manifest = self::manifestPath($manifest);
                foreach ($manifest !== '' ? $found : [] as $pair) {
                    $out[$manifest][] = $pair;
                }
            }
        }
        return $out;
    }

    /**
     * "netty-codec-http2-4.1.76.Final.jar" -> "4.1.76.Final",
     * "urllib3-2.6.3-py3-none-any.whl" -> "2.6.3".
     */
    private static function fileVersion(string $file, string $name): string
    {
        $base = (string)preg_replace('/\.(tgz|jar|whl|gem|nupkg|zip|egg|tar\.gz|tar|min\.js)$/u', '', $file, 1);
        if (!str_starts_with($base, $name . '-')) {
            return '';
        }
        $version = substr($base, strlen($name) + 1);
        return self::cleanVer(str_ends_with($file, '.whl') ? explode('-', $version)[0] : $version);
    }

    /**
     * The package a vulnerable-library path belongs to and the version found
     * there, each '' when the path does not say.
     *
     * @return array{0: string, 1: string}
     */
    private static function libraryAt(string $path): array
    {
        [$name, $version] = match (true) {
            // ~/.m2/repository/io/netty/netty-codec-http2/4.1.76.Final/netty-codec-http2-4.1.76.Final.jar,
            // or a coursier cache's .../maven2/<same layout>
            preg_match('#(?:/\.m2/repository|/maven2)/(?<g>[^/].*?)/(?<a>[^/]+)/(?<v>[^/]+)/[^/]+\.(?:jar|pom|aar|war)$#', $path, $m) === 1
                => [str_replace('/', '.', $m['g']) . ':' . $m['a'], $m['v']],
            // .gradle/caches/modules-2/files-2.1/io.netty/netty-codec-http2/4.1.76.Final/<sha1>/<file>.jar
            preg_match('#/files-2\.1/(?<g>[^/]+)/(?<a>[^/]+)/(?<v>[^/]+)/#', $path, $m) === 1
                => [$m['g'] . ':' . $m['a'], $m['v']],
            // .ivy2/cache/com.fasterxml.jackson.core/jackson-databind/jars/jackson-databind-2.9.2.jar
            preg_match('#/\.ivy2/cache/(?<g>[^/]+)/(?<a>[^/]+)/[^/]+/(?<f>[^/]+)$#', $path, $m) === 1
                => [$m['g'] . ':' . $m['a'], self::fileVersion($m['f'], $m['a'])],
            // .../node_modules/@babel/core/package.json: the innermost one
            preg_match('#^(?:.*/)?node_modules/(?<n>(?:@[^/]+/)?[^/]+)/package\.json$#', $path, $m) === 1
                => [$m['n'], ''],
            // go/pkg/mod/cache/download/golang.org/x/net/@v/v0.47.0.mod; capitals are stored as "!x"
            preg_match('#/pkg/mod/cache/download/(?<m>.+)/@v/(?<v>[^/]+)\.(?:mod|zip|info)$#', $path, $m) === 1
                => [(string)preg_replace_callback('/!([a-z])/', static fn ($c) => strtoupper($c[1]), $m['m']), $m['v']],
            // site-packages/python_multipart-0.0.20.dist-info, under its normalised name
            preg_match('#/site-packages/(?<p>[^/]+?)-(?<v>[0-9][^/]*)\.(?:dist|egg)-info$#', $path, $m) === 1
                => [strtolower((string)preg_replace('/[-_.]+/', '-', $m['p'])), $m['v']],
            // .nuget/packages/newtonsoft.json/11.0.2/...
            preg_match('#/\.nuget/packages/(?<n>[^/]+)/(?<v>[0-9][^/]*)/#', $path, $m) === 1
                => [$m['n'], $m['v']],
            default => ['', ''],
        };
        // Written into manifests later, so only plain names and versions
        return preg_match('#^[A-Za-z0-9@_][A-Za-z0-9@/._:+~-]*$#', $name) === 1 ? [$name, self::cleanVer($version)] : ['', ''];
    }

    /**
     * The full name in $affected that a short name stands for, or the name
     * itself.
     *
     * @param list<string> $affected
     */
    private static function qualify(string $name, array $affected): string
    {
        if ($name === '' || self::isQualified($name)) {
            return $name;
        }
        foreach ($affected as $lib) {
            if (self::isQualified($lib) && self::sameLibrary($name, $lib)) {
                return $lib;
            }
        }
        return $name;
    }

    /**
     * Whether a name from a fix list is $lib: the same name, or the bare
     * artifact or unscoped name of it.
     */
    private static function sameLibrary(string $name, string $lib): bool
    {
        $n = self::normal($name);
        return $n === self::normal($lib) || (!self::isQualified($name) && $n === self::normal(self::shortName($lib)));
    }

    /**
     * A name carrying its groupId, npm scope or module path.
     */
    private static function isQualified(string $name): bool
    {
        return str_contains($name, ':') || str_contains($name, '/');
    }

    /**
     * Whether a library's next major line can be published under another
     * name: a Maven coordinate (a new groupId or artifactId) or a Go module
     * (v2 is "<module>/v2"). An npm, PyPI or NuGet package keeps its name.
     */
    private static function renamedAcrossMajors(string $lib): bool
    {
        return str_contains($lib, ':') || preg_match('#^[a-z0-9-]+(?:\.[a-z0-9-]+)+/#i', $lib) === 1;
    }

    /**
     * The groupId of a Maven coordinate or the scope of an npm name: the
     * packages released together. '' for anything else.
     */
    private static function family(string $name): string
    {
        return match (true) {
            str_contains($name, ':')                              => explode(':', $name, 2)[0],
            str_starts_with($name, '@') && str_contains($name, '/') => explode('/', $name, 2)[0],
            default                                               => '',
        };
    }

    /**
     * "io.netty:netty-codec-http2" -> "netty-codec-http2", "@babel/core" -> "core",
     * "golang.org/x/net" -> "net".
     */
    private static function shortName(string $name): string
    {
        $parts = preg_split('#[:/]#', $name) ?: [$name];
        return (string)end($parts);
    }

    /**
     * For comparing names only: PyPI treats case and - _ . as equivalent.
     */
    private static function normal(string $name): string
    {
        return strtolower((string)preg_replace('/[-_.]+/', '-', $name));
    }

    /**
     * @param list<array{package: string, version: string, direct: bool}> $fixes
     * @param list<string> $manifests
     * @param array<string, list<array{0: string, 1: string}>> $installed from installed()
     * @return list<array<string, mixed>>
     */
    private static function records(
        array $fixes,
        string $id,
        string $cve,
        string $sev,
        string $cvss,
        mixed $number,
        string $title,
        string $url,
        array $manifests,
        array $installed = []
    ): array {
        $records = [];
        foreach ($fixes as $fix) {
            $unfixed = $fix['version'] === '';
            if ($fix['package'] === '' || ($unfixed && $id === 'ISSUE-' . $number)) {
                continue;
            }
            foreach ($manifests as $manifest) {
                $inUse = [];
                foreach ($installed[$manifest] ?? [] as [$name, $version]) {
                    if (self::sameLibrary($name, $fix['package']) || self::sameLibrary($fix['package'], $name)) {
                        $inUse[] = $version;
                    }
                }
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
                    'fix_versions'     => $unfixed ? [] : [$fix['version']],
                    'ecosystem'        => '',
                    'package'          => $fix['package'],
                    'manifest'         => $manifest,
                    'manifests'        => $manifests,
                    'scope'            => '',
                    'severity'         => strtolower($sev),
                    'cvss'             => is_numeric($cvss) ? $cvss + 0 : 0,
                    'vulnerable_range' => '',
                    'fixed_version'    => $fix['version'],
                    // What the issue found in use, which a dependency the
                    // manifest does not declare has nowhere else to come from
                    'installed'        => self::uniqueSorted($inUse),
                    'direct'           => $fix['direct'],
                    'summary'          => $title,
                    'url'              => $url,
                ] + ($unfixed ? ['state' => 'skipped', 'note' => 'no fixed version known'] : []);
            }
        }
        return $records;
    }

    /**
     * A manifest path from an issue body, relative to the repository root;
     * '' for anything that could point outside it.
     */
    private static function manifestPath(string $path): string
    {
        $path = (string)preg_replace('#^/#', '', self::trim(self::printable($path)), 1);
        if ($path === '' || str_starts_with($path, '/') || str_contains($path, '\\')
            || preg_match('#(^|/)\.\.?(/|$)#', $path) === 1) {
            return '';
        }
        return $path;
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
     * "https://github.com/x/y.git - jackson-databind-2.18.8"; a repository
     * URL gives its name, flagged as a repository rather than a package, and
     * the name prefix some of its tags carry is stripped from the version.
     *
     * @return array{package: string, version: string, repo: bool}|null
     */
    private static function dashed(string $s): ?array
    {
        if (preg_match('/^(?<n>.+?)\s+-\s+(?<v>\S+)$/u', $s, $m) !== 1) {
            return null;
        }
        $name = $m['n'];
        $repo = preg_match('#^https?://|\.git$#u', $name) === 1;
        if ($repo) {
            $parts = explode('/', (string)preg_replace('/\.git$/u', '', $name, 1));
            $name  = (string)end($parts);
        }
        $version = $m['v'];
        if (str_starts_with($version, $name . '-')) {
            $version = substr($version, strlen($name) + 1);
        }
        return ['package' => self::cleanPkg($name), 'version' => self::cleanVer($version), 'repo' => $repo];
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

    /**
     * A version from an issue body, or '' when it is not plainly one: the
     * body is written by whoever opened the issue, and the value ends up in
     * a manifest.
     */
    private static function cleanVer(string $s): string
    {
        $s = self::trim(self::printable($s));
        $s = (string)preg_replace('/^[vV]_/u', '', $s, 1);
        $s = (string)preg_replace('/^[vV](?=[0-9])/u', '', $s, 1);
        $s = self::trim($s);
        return preg_match('/^[0-9A-Za-z][0-9A-Za-z.+_~-]*$/', $s) === 1 ? $s : '';
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
