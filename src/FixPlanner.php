<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Decisions behind auto-fix and close-fixed, kept free of I/O so they can be
 * tested against fixtures.
 *
 * Pure: no I/O.
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
