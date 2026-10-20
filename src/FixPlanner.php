<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Decisions behind auto-fix and close-fixed, kept free of I/O so they can be
 * tested against fixtures.
 *
 * Pure: no I/O.
 *
 * @phpstan-import-type Need from IssueVerifier
 */
final class FixPlanner
{
    /**
     * Collapse pending records to one fix per manifest+package.
     *
     * Each plan row keeps every advisory's candidate versions separately
     * (per-branch alternatives must all survive until the declared version is
     * known) plus every contributing record key, so all of them can be marked.
     *
     * @param array<string, mixed> $db
     * A row's installed lists the versions its issues found in use, for a
     * package the manifest does not declare.
     *
     * @return list<array{manifest: string, ecosystem: string, package: string, spec: array<string, list<string>>, keys: list<string>, pkg_max: string, installed: list<string>}>
     */
    public static function plan(array $db): array
    {
        $meta   = [];   // group => [manifest, ecosystem, package]
        $specs  = [];   // group => advisory id => candidate versions
        $keys   = [];   // group => contributing record keys
        $inUse  = [];   // group => versions found in use
        $maxima = [];
        foreach ($db['vulns'] as $v) {
            if (($v['state'] ?? null) !== 'pending') {
                continue;
            }
            $manifest = (string)($v['manifest'] ?? '');
            $fixed    = (string)($v['fixed_version'] ?? '');
            $eco      = (string)($v['ecosystem'] ?? 'unknown');
            if ($manifest === '' || $fixed === '' || $eco === 'unknown') {
                continue;
            }
            $pkg = (string)($v['package'] ?? '');
            $id  = (string)($v['id'] ?? '?');

            $candidates = array_merge(is_array($v['fix_versions'] ?? null) ? $v['fix_versions'] : [], [$fixed]);
            $candidates = array_values(array_filter(array_map('strval', $candidates), static fn ($c) => $c !== ''));

            $gk        = $manifest . "\0" . $pkg;
            $meta[$gk] = [$manifest, $eco, $pkg];
            foreach ($candidates as $c) {
                $specs[$gk][$id][] = $c;
            }
            $keys[$gk][] = (string)$v['key'];
            foreach (is_array($v['installed'] ?? null) ? $v['installed'] : [] as $installed) {
                if (is_string($installed) && $installed !== '') {
                    $inUse[$gk][$installed] = true;
                }
            }

            // Highest suggested version per package across the whole repo, used
            // when a fix has to be an override rather than a declared bump.
            // Keyed by ecosystem too: the original shell script shared one maximum
            // between, say, an npm and a PyPI package of the same name.
            foreach ($candidates as $c) {
                $maxima[$eco . "\0" . $pkg][] = $c;
            }
        }

        ksort($meta, SORT_STRING);
        $plan = [];
        foreach ($meta as $gk => [$manifest, $eco, $pkg]) {
            $spec = [];
            foreach ($specs[$gk] ?? [] as $id => $cands) {
                $spec[(string)$id] = Version::sortAscending(array_values(array_unique($cands)));
            }
            ksort($spec, SORT_STRING);
            $plan[] = [
                'manifest'  => $manifest,
                'ecosystem' => $eco,
                'package'   => $pkg,
                'spec'      => $spec,
                'keys'      => array_values(array_unique($keys[$gk] ?? [])),
                'pkg_max'   => Version::maxRelease($maxima[$eco . "\0" . $pkg] ?? []),
                'installed' => Version::sortAscending(array_map('strval', array_keys($inUse[$gk] ?? []))),
            ];
        }
        return $plan;
    }

    /**
     * Pending records plan() leaves out, by reason: no fixed version is known
     * yet ("no-fix": an alert with no patched release), or the record names
     * no manifest or no ecosystem to edit ("unplaceable"). They stay pending,
     * so a fix published later is still picked up, but auto-fix has to count
     * them or its tallies do not add up to what is pending.
     *
     * @param array<string, mixed> $db
     * @return array{no-fix: int, unplaceable: int}
     */
    public static function unplanned(array $db): array
    {
        $out = ['no-fix' => 0, 'unplaceable' => 0];
        foreach ($db['vulns'] as $v) {
            if (($v['state'] ?? null) !== 'pending') {
                continue;
            }
            if ((string)($v['manifest'] ?? '') === '' || (string)($v['ecosystem'] ?? 'unknown') === 'unknown') {
                $out['unplaceable']++;
            } elseif ((string)($v['fixed_version'] ?? '') === '') {
                $out['no-fix']++;
            }
        }
        return $out;
    }

    /**
     * Every advisory the database records for each exact coordinate, keyed
     * "ecosystem|package" => advisory id => its fix versions and vulnerable
     * ranges. All states count, not just pending ones: an applied record
     * still says which versions were affected, and a candidate fix must not
     * land inside one of them (tomcat-embed-core 11.0.17 is a real release
     * that the newer advisories list as affected, and writing it opened ten
     * fresh alerts on the push).
     *
     * @param array<string, mixed> $db
     * @return array<string, array<string, array{fixes: list<string>, ranges: list<string>}>>
     */
    public static function advisories(array $db): array
    {
        $out = [];
        foreach ($db['vulns'] as $v) {
            $eco = strtolower((string)($v['ecosystem'] ?? ''));
            $pkg = (string)($v['package'] ?? '');
            if ($eco === '' || $eco === 'unknown' || $pkg === '') {
                continue;
            }
            $id  = (string)($v['id'] ?? '?');
            $fixes = array_values(array_filter(
                array_merge(is_array($v['fix_versions'] ?? null) ? array_map('strval', $v['fix_versions']) : [],
                    [(string)($v['fixed_version'] ?? '')]),
                static fn (string $f): bool => $f !== ''
            ));
            $range = trim((string)($v['vulnerable_range'] ?? ''));
            $key   = $eco . '|' . $pkg;
            $out[$key][$id] ??= ['fixes' => [], 'ranges' => []];
            $out[$key][$id]['fixes']  = array_values(array_unique([...$out[$key][$id]['fixes'], ...$fixes]));
            if ($range !== '' && !in_array($range, $out[$key][$id]['ranges'], true)) {
                $out[$key][$id]['ranges'][] = $range;
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /**
     * The advisories of one coordinate whose known affected range holds
     * $version: either its recorded range literally contains it, or it sits
     * below a fix on its own release line, which is the shape of "still
     * vulnerable" when no range was recorded.
     *
     * @param array<string, array{fixes: list<string>, ranges: list<string>}> $known
     * @return list<string> advisory ids
     */
    public static function vulnerableTarget(string $version, array $known): array
    {
        $floor  = Version::floor($version);
        $branch = $floor === '' ? '' : Version::branch($floor);
        $hits   = [];
        foreach ($known as $id => $advisory) {
            foreach ($advisory['ranges'] as $range) {
                if (Version::rangeContains($range, $floor) === true) {
                    $hits[] = (string)$id;
                    continue 2;
                }
            }
            $fixes = $advisory['fixes'];
            if ($fixes === [] || Version::satisfies($floor, $fixes)) {
                continue;
            }
            if ($branch !== '' && array_filter($fixes, static fn (string $f): bool => Version::branch($f) === $branch) !== []) {
                $hits[] = (string)$id;
            }
        }
        return array_values(array_unique($hits));
    }

    /**
     * The version to write, so a fix cannot pin what no registry publishes,
     * what the database knows is itself vulnerable, or what moves the
     * package backwards: $preferred first, and when it fails a guard the
     * known candidates and the registry's own releases are walked from the
     * top (staying on the current major line unless --allow-major, and on
     * the current qualifier family when one exists there) to the first that
     * passes every guard.
     *
     * @param array<string, list<string>> $spec this fix's advisories => candidate versions
     * @param array<string, array{fixes: list<string>, ranges: list<string>}> $known every advisory recorded for this coordinate, see advisories()
     * @param list<string>|null $registry every version the registry publishes; null when unknown
     * @param (callable(string): ?bool)|null $exists whether the registry publishes one exact version; null when it cannot answer
     * @param bool $allowLower the deliberate prerelease-to-release channel may move down
     * @param bool $anyMajor --allow-major may clamp onto another major line
     * @return array{version: string, why: string} '' version means write nothing, and $why says why not (or why a fallback replaced $preferred)
     */
    public static function safeTarget(
        string $ecosystem,
        string $current,
        string $preferred,
        array $spec,
        array $known,
        ?array $registry,
        ?callable $exists,
        bool $allowLower = false,
        bool $anyMajor = false
    ): array {
        if ($preferred === '') {
            return ['version' => '', 'why' => 'no fix version is known'];
        }
        $maven = $ecosystem === 'maven';
        $why   = self::targetRejected($ecosystem, $current, $preferred, $spec, $known, $exists, $allowLower);
        if ($why === '') {
            return ['version' => $preferred, 'why' => ''];
        }

        $pool = [];
        foreach ($spec as $candidates) {
            foreach ($candidates as $c) {
                $pool[$c] = true;
            }
        }
        foreach ($registry ?? [] as $v) {
            $pool[$v] = true;
        }
        $line    = Version::majorLine($current);
        $family  = $maven ? Version::familySuffix($current) : '';
        // A transitive pin has no current to stay on: the preferred (rejected)
        // version's line is the anchor, so a walk never relocates the whole
        // graph to another major (lodash 4.18.0 -> 4.17.21, not 5.x)
        $anchor  = $line !== '' ? $line : Version::majorLine($preferred);
        $ok      = [];
        foreach (array_keys($pool) as $v) {
            $v = (string)$v;
            if ($v === '' || $v === $preferred || Version::isPrerelease($v)) {
                continue;
            }
            if (!$anyMajor && $anchor !== '' && Version::majorLine($v) !== $anchor) {
                continue;
            }
            if (self::targetRejected($ecosystem, $current, $v, $spec, $known, $exists, $allowLower) !== '') {
                continue;
            }
            $ok[] = $v;
        }
        usort($ok, $maven ? [Version::class, 'compareMaven'] : [Version::class, 'compare']);
        if ($family !== '') {
            $same = array_values(array_filter($ok, static fn (string $v): bool => Version::familySuffix($v) === $family));
            $ok   = $same !== [] ? $same : $ok;
        }
        return ['version' => $ok === [] ? '' : $ok[count($ok) - 1], 'why' => $why];
    }

    /**
     * Why $version may not be written, or '' when every guard passes it.
     *
     * @param array<string, list<string>> $spec
     * @param array<string, array{fixes: list<string>, ranges: list<string>}> $known
     * @param (callable(string): ?bool)|null $exists
     */
    private static function targetRejected(
        string $ecosystem,
        string $current,
        string $version,
        array $spec,
        array $known,
        ?callable $exists,
        bool $allowLower
    ): string {
        $reasons = [];
        if ($exists !== null && $exists($version) === false) {
            $reasons[] = 'is not published on ' . match ($ecosystem) {
                'maven' => 'Maven Central',
                'npm'   => 'the npm registry',
                'pip'   => 'PyPI',
                default => 'its registry',
            };
        }
        $vulnerable = self::vulnerableTarget($version, $known);
        if ($vulnerable !== []) {
            $reasons[] = 'is itself affected by ' . implode(', ', array_slice($vulnerable, 0, 3))
                . (count($vulnerable) > 3 ? ' +' . (count($vulnerable) - 3) . ' more' : '');
        }
        if (!$allowLower && $current !== '') {
            [$floorNew, $floorOld] = [Version::floor($version), Version::floor($current)];
            $downgraded = $floorNew !== '' && $floorOld !== '' && $floorNew !== $floorOld
                && ($ecosystem === 'maven'
                    ? Version::compareMaven($floorNew, $floorOld) < 0
                    : !Version::gte($floorNew, $floorOld));
            if ($downgraded) {
                $reasons[] = 'would downgrade from ' . $current;
            }
        }
        if ($spec !== [] && !self::versionClears($version, $spec, $ecosystem === 'maven')) {
            $reasons[] = 'does not clear the fix';
        }
        return implode(', ', $reasons);
    }

    /**
     * Whether a candidate clears every advisory of the fix being applied:
     * Version::satisfies() rules, or - for Maven, where the byte ordering
     * reads "33.5.0-jre" below a lettered "r09" - at or above some fix under
     * compareMaven().
     *
     * @param array<string, list<string>> $spec
     */
    private static function versionClears(string $version, array $spec, bool $maven): bool
    {
        $floor = Version::floor($version);
        foreach ($spec as $candidates) {
            if (Version::satisfies($floor, $candidates)) {
                continue;
            }
            if ($maven && array_filter($candidates, static fn (string $c): bool => $c !== '' && Version::gteMaven($floor, $c)) !== []) {
                continue;
            }
            return false;
        }
        return true;
    }

    /**
     * Issue-sourced records grouped by issue number, for close-fixed.
     *
     * Expands over refs, not ref: several issues can share one deduped record
     * and every one of them needs closing once the vulnerability is resolved.
     *
     * @param array<string, mixed> $db
     * @return array<int, list<array{ecosystem: string, package: string, fixed_version: string, fix_versions: list<string>, manifest: string}>>
     */
    public static function issueRequirements(array $db): array
    {
        $byIssue = [];
        foreach ($db['vulns'] as $v) {
            if (($v['source'] ?? null) !== 'issue') {
                continue;
            }
            $refs = is_array($v['refs'] ?? null) && $v['refs'] !== [] ? $v['refs'] : [$v['ref'] ?? null];
            $need = [
                'ecosystem'     => (string)($v['ecosystem'] ?? ''),
                'package'       => (string)($v['package'] ?? ''),
                'fixed_version' => (string)($v['fixed_version'] ?? ''),
                'fix_versions'  => array_values(array_map('strval', is_array($v['fix_versions'] ?? null) ? $v['fix_versions'] : [])),
                'manifest'      => (string)($v['manifest'] ?? ''),
            ];
            foreach ($refs as $ref) {
                if (!is_int($ref) || $ref <= 0) {
                    continue;
                }
                $byIssue[$ref][json_encode($need)] = $need;
            }
        }
        ksort($byIssue);
        return array_map('array_values', $byIssue);
    }

    /**
     * What each issue is about, read off its database records: the issue
     * title, a CVE when one is known, the first package it names. For
     * close-fixed's memory (title hash) and its duplicate-title log.
     *
     * @param array<string, mixed> $db
     * @return array<int, array{title: string, cve: string, package: string}>
     */
    public static function issueMeta(array $db): array
    {
        $meta = [];
        foreach ($db['vulns'] as $v) {
            if (($v['source'] ?? null) !== 'issue') {
                continue;
            }
            $refs = is_array($v['refs'] ?? null) && $v['refs'] !== [] ? $v['refs'] : [$v['ref'] ?? null];
            foreach ($refs as $ref) {
                if (!is_int($ref) || $ref <= 0) {
                    continue;
                }
                $m = $meta[$ref] ?? ['title' => '', 'cve' => '', 'package' => ''];
                $m['title']   = $m['title'] !== '' ? $m['title'] : (string)($v['summary'] ?? '');
                $m['cve']     = $m['cve'] !== '' ? $m['cve'] : (string)($v['cve'] ?? '');
                $m['package'] = $m['package'] !== '' ? $m['package'] : (string)($v['package'] ?? '');
                $meta[$ref]  = $m;
            }
        }
        return $meta;
    }

    /**
     * Same-title duplicates among the issues under consideration — the Mend
     * bot files one issue per affected directory per CVE. Titles with more
     * than $minTimes issues count; the list is largest-first, capped at $top.
     *
     * @param array<int, list<Need>>                                $byIssue
     * @param array<int, array{title: string, cve: string, package: string}> $meta
     * @return array{issues: int, titles: list<array{title: string, count: int}>}
     */
    public static function duplicateTitles(array $byIssue, array $meta, int $minTimes = 2, int $top = 5): array
    {
        $counts = [];
        foreach (array_keys($byIssue) as $ref) {
            $title = (string)($meta[$ref]['title'] ?? '');
            if ($title === '') {
                continue;
            }
            $counts[$title] = ($counts[$title] ?? 0) + 1;
        }
        $duplicates = array_filter($counts, static fn (int $n): bool => $n > $minTimes);
        arsort($duplicates);
        $issues = array_sum($duplicates);
        $titles = [];
        foreach (array_slice(array_keys($duplicates), 0, $top) as $title) {
            $titles[] = ['title' => $title, 'count' => $duplicates[$title]];
        }
        return ['issues' => (int)$issues, 'titles' => $titles];
    }

    /**
     * Whether an alert's fix sits on a higher major line than the vulnerable
     * range starts at: ">= 4.0.0, < 5.0.0" patched only by 5.0.0 leaves
     * everyone below 4 stuck on a major upgrade. The range's lowest version
     * token is the line its consumers live on; a range without version
     * tokens says nothing, so it never claims a major is needed.
     */
    public static function alertNeedsMajor(string $vulnerableRange, string $fixedVersion): bool
    {
        if ($vulnerableRange === '' || $fixedVersion === '') {
            return false;
        }
        preg_match_all('/\d+(?:\.\d+)+/', $vulnerableRange, $m);
        if ($m[0] === []) {
            return false;
        }
        $floor = Version::sortAscending($m[0])[0];
        return Version::majorLine($floor) !== '' && Version::majorLine($fixedVersion) !== ''
            && (int)Version::majorLine($fixedVersion) > (int)Version::majorLine($floor);
    }

    /**
     * Whether a declared version resolves one requirement: at or above the
     * fix on its own release line, or above every fix.
     *
     * Being above the recorded fix is not enough. That is one branch's fix
     * (whichever the issue listed last), and netty 4.2.5.Final is above
     * 4.1.137.Final with 4.2.17.Final still to come.
     *
     * @param array{fixed_version: string, fix_versions: list<string>} $need
     */
    public static function requirementMet(string $declared, array $need): bool
    {
        $floor = Version::floor($declared);
        return $floor !== '' && Version::satisfies($floor, self::fixes($need));
    }

    /**
     * What versions that fall short of a requirement still need, for the
     * close-fixed log.
     *
     * @param list<string> $versions
     * @param array{fixed_version: string, fix_versions: list<string>} $need
     */
    public static function shortfall(array $versions, array $need): string
    {
        $fixes = self::fixes($need);
        $above = array_filter($versions, static fn (string $v): bool => Version::isPrerelease(Version::floor($v))
            && Version::gte(Version::floor($v), Version::max($fixes)));
        return 'needs >= ' . implode(' or ', $fixes) . ($above !== [] ? ' (a prerelease above every fix is not known to include one)' : '');
    }

    /**
     * Every fix version of one requirement, lowest first.
     *
     * @param array{fixed_version: string, fix_versions: list<string>} $need
     * @return list<string>
     */
    public static function fixes(array $need): array
    {
        $fixes = array_filter(array_merge($need['fix_versions'], [$need['fixed_version']]), static fn (string $f): bool => $f !== '');
        return Version::sortAscending(array_values(array_unique($fixes)));
    }
}
