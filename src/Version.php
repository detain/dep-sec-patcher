<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Version comparison and fix-version selection.
 *
 * compare() reproduces GNU `sort -V` (gnulib filevercmp) byte for byte, because
 * the original shell script ordered versions with it and Maven-style versions
 * ("4.1.42.Final") depend on its suffix handling. gte() layers the semver rule
 * on top: a release outranks its own prereleases, which sort -V gets backwards.
 *
 * Pure: no I/O.
 */
final class Version
{
    /**
     * The start of a prerelease version, case-insensitive: a numeric release
     * then an alpha/beta/milestone/rc/snapshot/... qualifier. Written in the
     * subset PCRE and Java regexes share, because the Maven versions plugin
     * is handed the same pattern (MavenAuditor::PRERELEASES), so what it
     * passes over and what isPrerelease() reports cannot drift apart.
     */
    public const PRERELEASE = 'v?\\d+(?:\\.\\d+)*[-._]?(?:alpha|a|beta|b|c|milestone|m|rc|cr|pre|preview|ea|snapshot|dev|next|canary|nightly)(?![a-z])';

    /**
     * Three-way comparison with GNU `sort -V` semantics, including sort's
     * last-resort byte comparison when two different strings tie.
     */
    public static function compare(string $a, string $b): int
    {
        $r = self::filevercmp($a, $b);
        if ($r !== 0) {
            return $r < 0 ? -1 : 1;
        }
        return $a === $b ? 0 : (strcmp($a, $b) < 0 ? -1 : 1);
    }

    /**
     * True when $a >= $b.
     *
     * sort -V alone ranks "1.0.0-beta" above "1.0.0"; semver says a release
     * outranks its own prereleases. Left uncorrected that lets a manifest on
     * 1.0.0-beta satisfy a required 1.0.0 and close a live issue, so release
     * parts are compared first and the prerelease rule applied after.
     */
    public static function gte(string $a, string $b): bool
    {
        [$abase, $apre] = self::splitPrerelease($a);
        [$bbase, $bpre] = self::splitPrerelease($b);

        // "1.2" and "1.2.0" are the same release
        if ($abase !== $bbase && self::trimZeros($abase) !== self::trimZeros($bbase)) {
            return self::compare($abase, $bbase) >= 0;
        }
        // Same release: no prerelease outranks any prerelease
        if ($apre === null) {
            return true;
        }
        if ($bpre === null) {
            return false;
        }
        return self::compare($apre, $bpre) >= 0;
    }

    /**
     * Reduce a declared requirement to the lowest version it admits:
     * "^4.17.1" -> "4.17.1", ">= 8.4.2" -> "8.4.2", "~> 2.0" -> "2.0".
     *
     * Only lower bounds and exact pins count, so ">=1.2 <2" yields "1.2" and
     * "<2" yields '' (it admits anything below 2, however old). A union
     * ("^5.4 || ^6.0") yields its lowest alternative. (The original shell
     * script deleted the operators and glued the bounds together into
     * "1.22".) Returns '' when no lower bound is present.
     */
    public static function floor(string $declared): string
    {
        $declared = trim($declared);
        // Maven/NuGet union of ranges: "[1.0,2.0),[3.0,)"
        $parts = preg_split('/(?<=[\])])\s*,\s*(?=[\[(])/', $declared) ?: [$declared];
        if (count($parts) === 1) {
            // npm "||", Composer "||" and "|"
            $parts = preg_split('/\s*\|\|?\s*/', $declared) ?: [$declared];
        }
        if (count($parts) > 1) {
            $floors = array_map([self::class, 'floor'], $parts);
            return in_array('', $floors, true) ? '' : self::sortAscending($floors)[0];
        }

        $range = self::bracketRange($declared);
        if ($range !== null) {
            return $range['lower'] === '' ? '' : self::floor($range['lower']);
        }
        // npm hyphen range "1.2.3 - 2.0.0"
        if (preg_match('/^(\S+)\s+-\s+\S+$/', $declared, $m) === 1) {
            $declared = $m[1];
        }
        preg_match_all('/(===|==|>=|<=|!=|~=|~>|\^|~|>|<|=)?\s*[vV]?([0-9][0-9A-Za-z.+_-]*)/', $declared, $mm, PREG_SET_ORDER);
        $lower = [];
        foreach ($mm as $m) {
            if (in_array($m[1], ['<', '<=', '!='], true)) {
                continue;
            }
            // "1.2.x" / "1.2.*" / "1.0.x-dev" wildcards: the floor is the fixed part
            $lower[] = rtrim((string)preg_replace('/(?:\.[xX*])+(?:-dev)?$/', '', $m[2]), '.');
        }
        return match (count($lower)) {
            0       => '',
            1       => $lower[0],
            default => self::max($lower),
        };
    }

    /**
     * Whether a declared requirement is a union of alternatives
     * ("^5.4 || ^6.0", "[1.0,2.0),[3.0,)"), which a single bumped version
     * cannot replace without dropping an alternative.
     */
    public static function isUnion(string $declared): bool
    {
        return preg_match('/\||[\])]\s*,\s*[\[(]/', $declared) === 1;
    }

    /**
     * The release line a version belongs to, used to tell per-branch fixes
     * apart: "9.0.106" -> "9.0", "4.1.42.Final" -> "4.1", "5" -> "5".
     */
    public static function branch(string $version): string
    {
        $floor = self::floor($version);
        if (preg_match('/^(\d+)(?:\.(\d+))?/', $floor, $m) !== 1) {
            return '';
        }
        return isset($m[2]) ? $m[1] . '.' . $m[2] : $m[1];
    }

    /**
     * The semver compatibility line a version belongs to: its major version,
     * or "0.minor" below 1.0, where a minor release may break (as npm's
     * caret treats it). "4.17.1" -> "4", "0.8.15" -> "0.8".
     */
    public static function majorLine(string $version): string
    {
        if (preg_match('/^(\d+)(?:\.(\d+))?/', self::floor($version), $m) !== 1) {
            return '';
        }
        return $m[1] === '0' && isset($m[2]) ? '0.' . $m[2] : $m[1];
    }

    /**
     * Whether a version clears every advisory in $spec (advisory id =>
     * candidate fix versions).
     *
     * @param array<string, list<string>> $spec
     */
    public static function clearsAll(string $version, array $spec): bool
    {
        foreach ($spec as $candidates) {
            if (!self::satisfies(self::floor($version), $candidates)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether a declared version already clears one advisory, given that
     * advisory's per-branch fix versions.
     *
     * Satisfied when the declared version is at or above a fix on its own
     * release line (tomcat 9.0.110 vs fixes 9.0.106 / 10.1.42 / 11.0.8), or
     * above every fix listed.
     *
     * A prerelease can sort above every fix and still predate them all
     * (netty 5.0.0.Alpha2 is from 2015 and has none of 4.1.137.Final's
     * fixes). Above every fix it only counts when its major line had a
     * release before it and needed no fix: spring-boot 4.2.0-M2 follows 4.0
     * and 4.1, against a fix in 3.0.0. Not so spring 7.1.0-M2 against 7.0.8,
     * which it may predate.
     *
     * @param list<string> $fixes
     */
    public static function satisfies(string $declaredFloor, array $fixes): bool
    {
        $fixes = array_values(array_filter($fixes, static fn ($f) => $f !== ''));
        if ($declaredFloor === '' || $fixes === []) {
            return false;
        }
        $branch   = self::branch($declaredFloor);
        $allBelow = true;
        foreach ($fixes as $fix) {
            $cleared = self::gte($declaredFloor, $fix);
            if ($cleared && $branch !== '' && self::branch($fix) === $branch) {
                return true;
            }
            if (!$cleared) {
                $allBelow = false;
            }
        }
        if (!$allBelow || !self::isPrerelease($declaredFloor)) {
            return $allBelow;
        }
        return !self::opensItsLine($declaredFloor)
            && !in_array(self::majorLine($declaredFloor), array_map([self::class, 'majorLine'], $fixes), true);
    }

    /**
     * Whether a version is the first release of its major line, or a
     * prerelease of it: "5.0.0.Alpha2", "8.0.0-rc.6", "0.9.0-beta" (below
     * 1.0 the line is the minor version, as in majorLine()).
     */
    private static function opensItsLine(string $version): bool
    {
        $parts = preg_match('/^v?(\d+(?:\.\d+)*)/', $version, $m) === 1 ? explode('.', $m[1]) : [];
        $rest  = array_slice($parts, ($parts[0] ?? '') === '0' ? 2 : 1);
        return array_filter($rest, static fn (string $p): bool => ltrim($p, '0') !== '') === [];
    }

    /**
     * Whether a version is an alpha, beta, milestone, release candidate,
     * snapshot, dev or preview build: "5.0.0.Alpha2", "7.1.0-M2",
     * "2.0.0-rc.1", "4.2rc1". A qualifier naming a flavour of a release is
     * not one ("33.0.0-jre", "28.2-android", "4.1.42.Final").
     */
    public static function isPrerelease(string $version): bool
    {
        return preg_match('/^' . self::PRERELEASE . '/i', $version) === 1;
    }

    /**
     * Whether a declared prerelease leaves an advisory with no fix to move up
     * to: it sorts above every fix without being known to include one (netty
     * 5.0.0.Alpha2 against 4.1.137.Final / 4.2.17.Final, spring 7.1.0-M2
     * against 6.2.19 / 7.0.8). releaseForPrerelease() picks the release to
     * go back to.
     *
     * @param array<string, list<string>> $spec
     */
    public static function prereleaseAboveFixes(string $declared, array $spec): bool
    {
        return self::isPrerelease(self::floor($declared)) && !self::clearsAll($declared, $spec) && self::chooseTarget($declared, $spec) === '';
    }

    /**
     * The release to move a prerelease that sits above every fix down to:
     * the newest known fix release on the prerelease's own major line that
     * clears every advisory (spring 7.1.0-M2 -> 7.0.8), else the newest that
     * does on any line (netty 5.0.0.Alpha2 -> 4.2.17.Final, as no 5.x was
     * ever released). '' when it is no such prerelease, or no single release
     * clears everything.
     *
     * @param array<string, list<string>> $spec
     */
    public static function releaseForPrerelease(string $declared, array $spec): string
    {
        if (!self::prereleaseAboveFixes($declared, $spec)) {
            return '';
        }
        $fixes = $spec === [] ? [] : array_values(array_unique(array_merge(...array_values($spec))));
        $ok    = array_values(array_filter(
            $fixes,
            static fn (string $f): bool => $f !== '' && !self::isPrerelease($f) && self::clearsAll($f, $spec)
        ));
        $line  = self::majorLine($declared);
        $same  = array_values(array_filter($ok, static fn (string $f): bool => self::majorLine($f) === $line));
        return self::max($same !== [] ? $same : $ok);
    }

    /**
     * Pick the version to write for one manifest+package.
     *
     * $spec maps advisory id => its candidate fix versions. For each advisory
     * not already satisfied, take the LOWEST fix that clears the declared
     * version, which keeps a project on its current release line; then take
     * the highest of those, since the result has to clear every advisory at
     * once. '' means nothing is left to do.
     *
     * A transitive dependency has no declared version to anchor to, so it gets
     * the repo-wide highest ($pkgMax), which is what an override has to be.
     *
     * @param array<string, list<string>> $spec
     */
    public static function chooseTarget(string $declared, array $spec, string $pkgMax = ''): string
    {
        $floor = $declared === '' ? '' : self::floor($declared);
        if ($floor === '') {
            return $pkgMax;
        }

        $range = self::bracketRange($declared);
        $best  = '';
        foreach ($spec as $candidates) {
            $candidates = self::sortAscending(array_values(array_unique($candidates)));
            if (self::satisfies($floor, $candidates)) {
                continue;
            }
            // A Maven/NuGet range resolves to the newest version it admits, so
            // one that admits a fixed version is already satisfied; pinning it
            // could pull the resolved version down
            if ($range !== null) {
                foreach ($candidates as $c) {
                    if (self::rangeAdmits($range, $c)) {
                        continue 2;
                    }
                }
            }
            $pick = '';
            foreach ($candidates as $c) {
                if ($c !== '' && self::gte($c, $floor)) {
                    $pick = $c;
                    break;
                }
            }
            if ($pick === '') {
                continue;
            }
            if ($best === '' || self::gte($pick, $best)) {
                $best = $pick;
            }
        }

        // Already at or above everything required
        return $best === $floor ? '' : $best;
    }

    /**
     * Parse a Maven/NuGet bracket range such as "[2.8.3,3)", "(,1.0]" or
     * "[1.5]"; null for anything else (including unions of ranges).
     *
     * @return array{lower: string, lowerInclusive: bool, upper: string, upperInclusive: bool}|null
     */
    public static function bracketRange(string $declared): ?array
    {
        $declared = trim($declared);
        if (preg_match('/^\[\s*([^,\[\]()]+?)\s*\]$/', $declared, $m) === 1) {
            return ['lower' => $m[1], 'lowerInclusive' => true, 'upper' => $m[1], 'upperInclusive' => true];
        }
        if (preg_match('/^([\[(])\s*([^,\[\]()]*?)\s*,\s*([^,\[\]()]*?)\s*([\])])$/', $declared, $m) !== 1) {
            return null;
        }
        return [
            'lower'          => $m[2],
            'lowerInclusive' => $m[1] === '[',
            'upper'          => $m[3],
            'upperInclusive' => $m[4] === ']',
        ];
    }

    /**
     * @param array{lower: string, lowerInclusive: bool, upper: string, upperInclusive: bool} $range
     */
    public static function rangeAdmits(array $range, string $version): bool
    {
        if ($range['lower'] !== '') {
            $ok = $range['lowerInclusive'] ? self::gte($version, $range['lower']) : !self::gte($range['lower'], $version);
            if (!$ok) {
                return false;
            }
        }
        if ($range['upper'] !== '') {
            return $range['upperInclusive'] ? self::gte($range['upper'], $version) : !self::gte($version, $range['upper']);
        }
        return true;
    }

    /**
     * @param list<string> $versions
     * @return list<string>
     */
    public static function sortAscending(array $versions): array
    {
        usort($versions, [self::class, 'compare']);
        return $versions;
    }

    /**
     * Highest of a list under compare(), or '' for an empty list.
     *
     * @param list<string> $versions
     */
    public static function max(array $versions): string
    {
        $versions = self::sortAscending(array_values(array_filter($versions, static fn ($v) => $v !== '')));
        return $versions === [] ? '' : $versions[count($versions) - 1];
    }

    /**
     * Highest of a list, leaving out prereleases unless there is nothing
     * else: an override pinned to a release candidate would put every copy
     * of the package on it.
     *
     * @param list<string> $versions
     */
    public static function maxRelease(array $versions): string
    {
        $releases = array_values(array_filter($versions, static fn ($v) => $v !== '' && self::splitPrerelease($v)[1] === null));
        return self::max($releases !== [] ? $releases : $versions);
    }

    /**
     * @return array{0: string, 1: ?string} release part, prerelease part (null when absent)
     */
    private static function splitPrerelease(string $v): array
    {
        $pos = strpos($v, '-');
        if ($pos !== false) {
            return [substr($v, 0, $pos), substr($v, $pos + 1)];
        }
        // PEP 440 / RubyGems / Maven prereleases carry no dash: "4.2rc1",
        // "2.0.0.dev1", "7.0.0.rc1", "1.0.M1"
        if (preg_match('/^(\d+(?:\.\d+)*)\.?((?:a|b|c|rc|alpha|beta|pre|preview|dev|snapshot|m|cr)\.?\d*)$/i', $v, $m) === 1) {
            return [$m[1], $m[2]];
        }
        return [$v, null];
    }

    /**
     * "1.2.0" -> "1.2", "1.0.0" -> "1"; anything not purely numeric unchanged.
     */
    private static function trimZeros(string $v): string
    {
        return preg_match('/^\d+(?:\.\d+)+$/', $v) === 1 ? (string)preg_replace('/(?:\.0+)+$/', '', $v) : $v;
    }

    // ── gnulib filevercmp ────────────────────────────────────────────────────

    private static function filevercmp(string $a, string $b): int
    {
        $alen = strlen($a);
        $blen = strlen($b);
        if ($alen === 0) {
            return $blen === 0 ? 0 : -1;
        }
        if ($blen === 0) {
            return 1;
        }

        // "." sorts first, then "..", then other names with a leading ".".
        if ($a[0] === '.') {
            if ($b[0] !== '.') {
                return -1;
            }
            $adot = $alen === 1;
            $bdot = $blen === 1;
            if ($adot) {
                return $bdot ? 0 : -1;
            }
            if ($bdot) {
                return 1;
            }
            $adotdot = $a[1] === '.' && $alen === 2;
            $bdotdot = $b[1] === '.' && $blen === 2;
            if ($adotdot) {
                return $bdotdot ? 0 : -1;
            }
            if ($bdotdot) {
                return 1;
            }
        } elseif ($b[0] === '.') {
            return 1;
        }

        $aprefix = self::filePrefixLen($a);
        $bprefix = self::filePrefixLen($b);
        $onePass = $aprefix === $alen && $bprefix === $blen;

        $result = self::verrevcmp($a, $aprefix, $b, $bprefix);
        return ($result !== 0 || $onePass) ? $result : self::verrevcmp($a, $alen, $b, $blen);
    }

    /**
     * Length of $s without its trailing (\.[A-Za-z~][A-Za-z0-9~]*)* suffix.
     */
    private static function filePrefixLen(string $s): int
    {
        $n         = strlen($s);
        $prefixlen = 0;
        $i         = 0;
        while (true) {
            if ($i === $n) {
                return $prefixlen;
            }
            $i++;
            $prefixlen = $i;
            while ($i + 1 < $n && $s[$i] === '.' && (ctype_alpha($s[$i + 1]) || $s[$i + 1] === '~')) {
                for ($i += 2; $i < $n && (ctype_alnum($s[$i]) || $s[$i] === '~'); $i++) {
                    // skip the suffix chunk
                }
            }
        }
    }

    private static function order(string $s, int $pos, int $len): int
    {
        if ($pos === $len) {
            return -1;
        }
        $c = $s[$pos];
        if (ctype_digit($c)) {
            return 0;
        }
        if (ctype_alpha($c)) {
            return ord($c);
        }
        if ($c === '~') {
            return -2;
        }
        return ord($c) + 256;
    }

    private static function verrevcmp(string $s1, int $s1len, string $s2, int $s2len): int
    {
        $p1 = 0;
        $p2 = 0;
        while ($p1 < $s1len || $p2 < $s2len) {
            $firstDiff = 0;
            while (($p1 < $s1len && !ctype_digit($s1[$p1])) || ($p2 < $s2len && !ctype_digit($s2[$p2]))) {
                $c1 = self::order($s1, $p1, $s1len);
                $c2 = self::order($s2, $p2, $s2len);
                if ($c1 !== $c2) {
                    return $c1 - $c2;
                }
                $p1++;
                $p2++;
            }
            while ($p1 < $s1len && $s1[$p1] === '0') {
                $p1++;
            }
            while ($p2 < $s2len && $s2[$p2] === '0') {
                $p2++;
            }
            while ($p1 < $s1len && $p2 < $s2len && ctype_digit($s1[$p1]) && ctype_digit($s2[$p2])) {
                if ($firstDiff === 0) {
                    $firstDiff = ord($s1[$p1]) - ord($s2[$p2]);
                }
                $p1++;
                $p2++;
            }
            if ($p1 < $s1len && ctype_digit($s1[$p1])) {
                return 1;
            }
            if ($p2 < $s2len && ctype_digit($s2[$p2])) {
                return -1;
            }
            if ($firstDiff !== 0) {
                return $firstDiff;
            }
        }
        return 0;
    }
}
