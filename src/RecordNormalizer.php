<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Normalises GitHub's vulnerability sources into the shared record shape the
 * local database stores: Dependabot alerts, repository security advisories,
 * and (via IssueParser) security-bot issues.
 *
 * Every record carries enough context (ecosystem, package, manifest path,
 * vulnerable range, fixed version) to re-apply its fix offline later.
 *
 * Pure: no I/O.
 */
final class RecordNormalizer
{
    /**
     * NOTE: the alerts API reports state in lowercase ("open"), and the
     * ecosystem lives under .dependency.package.ecosystem, NOT
     * .security_advisory.ecosystem, which is always null.
     *
     * @param list<array<string, mixed>> $alerts rows from repos/{repo}/dependabot/alerts
     * @return list<array<string, mixed>>
     */
    public static function fromDependabotAlerts(array $alerts): array
    {
        $records = [];
        foreach ($alerts as $a) {
            if (($a['state'] ?? null) !== 'open') {
                continue;
            }
            $dep      = $a['dependency'] ?? [];
            $adv      = $a['security_advisory'] ?? [];
            $vuln     = $a['security_vulnerability'] ?? [];
            $eco      = self::str($dep['package']['ecosystem'] ?? null, 'unknown');
            $name     = self::str($dep['package']['name'] ?? null, '');
            $keyName  = self::str($dep['package']['name'] ?? null, '?');
            $manifest = self::str($dep['manifest_path'] ?? null, '');
            $id       = self::str($adv['ghsa_id'] ?? null, 'DBOT-' . ($a['number'] ?? ''));
            $fixed    = self::str($vuln['first_patched_version']['identifier'] ?? null, '');

            $records[] = [
                'key'              => $eco . '|' . $keyName . '|' . $manifest . '|' . $id,
                'source'           => 'dependabot',
                'id'               => $id,
                'cve'              => self::str($adv['cve_id'] ?? null, ''),
                'ref'              => $a['number'] ?? 0,
                'ecosystem'        => $eco,
                'package'          => $name,
                'manifest'         => $manifest,
                'manifests'        => $manifest === '' ? [] : [$manifest],
                'scope'            => self::str($dep['scope'] ?? null, ''),
                'severity'         => self::str($adv['severity'] ?? null, ''),
                'cvss'             => $adv['cvss']['score'] ?? 0,
                'vulnerable_range' => self::str($vuln['vulnerable_version_range'] ?? null, ''),
                'fixed_version'    => $fixed,
                'fix_versions'     => $fixed === '' ? [] : [$fixed],
                'direct'           => ($dep['scope'] ?? null) === 'runtime',
                'summary'          => self::str($adv['summary'] ?? null, ''),
                'url'              => $a['html_url'] ?? null,
            ];
        }
        return $records;
    }

    /**
     * @param list<array<string, mixed>> $advisories rows from repos/{repo}/security-advisories
     * @return list<array<string, mixed>>
     */
    public static function fromSecurityAdvisories(array $advisories): array
    {
        $records = [];
        foreach ($advisories as $a) {
            if (!in_array($a['state'] ?? null, ['published', 'draft', 'triage'], true)) {
                continue;
            }
            $vulns = $a['vulnerabilities'] ?? [];
            if (!is_array($vulns) || $vulns === []) {
                $vulns = [['package' => null]];
            }
            foreach ($vulns as $v) {
                $pkg  = is_array($v['package'] ?? null) ? $v['package'] : [];
                $eco  = strtolower(self::str($pkg['ecosystem'] ?? null, 'unknown'));
                $name = self::str($pkg['name'] ?? null, '');
                $keyName = self::str($pkg['name'] ?? null, '?');
                $ghsa = self::str($a['ghsa_id'] ?? null, '');

                $records[] = [
                    'key'              => $eco . '|' . $keyName . '||' . $ghsa,
                    'source'           => 'advisory',
                    'id'               => $ghsa,
                    'cve'              => self::str($a['cve_id'] ?? null, ''),
                    'ref'              => 0,
                    'ecosystem'        => $eco,
                    'package'          => $name,
                    'manifest'         => '',
                    'manifests'        => [],
                    'scope'            => '',
                    'severity'         => self::str($a['severity'] ?? null, ''),
                    'cvss'             => $a['cvss']['score'] ?? 0,
                    'vulnerable_range' => self::str($v['vulnerable_version_range'] ?? null, ''),
                    'fixed_version'    => self::str($v['patched_versions'] ?? null, ''),
                    'direct'           => false,
                    'summary'          => self::str($a['summary'] ?? null, ''),
                    'url'              => self::str($a['html_url'] ?? null, ''),
                ];
            }
        }
        return $records;
    }

    /**
     * Infer the ecosystem from the manifest filename when the source did not
     * say, then lowercase it.
     *
     * @param array<string, mixed> $record
     * @return array<string, mixed>
     */
    public static function withEcosystem(array $record): array
    {
        $eco = $record['ecosystem'] ?? null;
        if ($eco === null || $eco === '' || $eco === 'unknown') {
            $eco = ManifestPaths::ecosystemFor((string)($record['manifest'] ?? ''));
        }
        $record['ecosystem'] = strtolower((string)$eco);
        return $record;
    }

    /**
     * jq's `x // y`: null and false fall through to the default.
     */
    private static function str(mixed $value, string $default): string
    {
        return $value === null || $value === false ? $default : (string)$value;
    }
}
