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

        if ($abase !== $bbase) {
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
     * Reduce a declared requirement to the version it pins or starts from:
     * "^4.17.1" -> "4.17.1", ">= 8.4.2" -> "8.4.2", "~> 2.0" -> "2.0".
     *
     * Takes the first version-looking token, so a range such as ">=1.2 <2"
     * yields "1.2". (The original shell script deleted the operators and glued the
     * bounds together into "1.22".) Returns '' when nothing numeric is present.
     */
    public static function floor(string $declared): string
    {
        if (preg_match('/[0-9][0-9A-Za-z.+_-]*/', $declared, $m) !== 1) {
            return '';
        }
        // "1.2.x" / "1.2.*" wildcards: the floor is the fixed part
        return rtrim(preg_replace('/\.[xX*](?:\.[xX*])*$/', '', $m[0]) ?? $m[0], '.');
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
     * Whether a declared version already clears one advisory, given that
     * advisory's per-branch fix versions.
     *
     * Satisfied when the declared version is at or above a fix on its own
     * release line (tomcat 9.0.110 vs fixes 9.0.106 / 10.1.42 / 11.0.8), or
     * above every fix listed.
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
        return $allBelow;
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
     * @return array{0: string, 1: ?string} release part, prerelease part (null when absent)
     */
    private static function splitPrerelease(string $v): array
    {
        $pos = strpos($v, '-');
        if ($pos === false) {
            return [$v, null];
        }
        return [substr($v, 0, $pos), substr($v, $pos + 1)];
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
