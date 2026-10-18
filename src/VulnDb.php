<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use JsonException;
use RuntimeException;

/**
 * The local vulnerability database: every record collected from Dependabot,
 * advisories and security-bot issues, with what has been applied.
 *
 * File format (unchanged from the original shell script, so existing databases load):
 *   {"schema":1, "repo":"owner/name", "updated":"<iso>", "vulns":{"<key>":{...}}}
 *
 * upsert()/applyStates() are pure; load()/save() are the only I/O.
 */
final class VulnDb
{
    /**
     * @return array<string, mixed>
     */
    public static function empty(): array
    {
        return ['schema' => 1, 'repo' => '', 'updated' => '', 'vulns' => []];
    }

    /**
     * Load the database. A missing file yields an empty database; a corrupt
     * one is reported through $corrupt and also treated as empty, rather than
     * failing every later step.
     *
     * @param-out bool $corrupt
     * @return array<string, mixed>
     */
    public static function load(string $path, ?bool &$corrupt = null): array
    {
        $corrupt = false;
        if (!is_file($path) || filesize($path) === 0) {
            return self::empty();
        }
        try {
            $db = json_decode((string)file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            $corrupt = true;
            return self::empty();
        }
        if (!is_array($db) || !isset($db['vulns']) || !is_array($db['vulns'])) {
            $corrupt = true;
            return self::empty();
        }
        return $db;
    }

    /**
     * Atomic replace: write a sibling temp file and rename it over the
     * original, so a crash mid-write never leaves a truncated database. (The
     * shell version wrote under /tmp and mv'd across filesystems, which is a
     * copy, not an atomic rename.)
     *
     * @param array<string, mixed> $db
     */
    public static function save(string $path, array $db): void
    {
        $data = $db;
        // An empty PHP array would serialise as [] and change the shape
        $data['vulns'] = $db['vulns'] === [] ? new \stdClass() : $db['vulns'];

        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new RuntimeException("cannot create {$dir}");
        }
        $tmp = tempnam($dir, '.vulndb.');
        if ($tmp === false) {
            throw new RuntimeException("cannot create a temp file in {$dir}");
        }
        if (file_put_contents($tmp, JsonFile::encode($data)) === false || !rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException("cannot write {$path}");
        }
        @chmod($path, 0600);
    }

    /**
     * Merge collected records. Existing first_seen/state/applied_at/note are
     * preserved so re-running never loses the record of what was already
     * applied; refs and fix_versions are unioned so duplicate issues reporting
     * the same vulnerability all persist.
     *
     * @param array<string, mixed>       $db
     * @param list<array<string, mixed>> $records
     * @return array<string, mixed>
     */
    public static function upsert(array $db, array $records, string $now, string $repo): array
    {
        foreach ($records as $v) {
            $key = (string)$v['key'];
            $old = $db['vulns'][$key] ?? [];
            $db['vulns'][$key] = array_merge($v, [
                'first_seen'   => self::orDefault($old['first_seen'] ?? null, $now),
                'last_seen'    => $now,
                // A record can arrive already settled (an issue CVE with no known fix)
                'state'        => self::orDefault($old['state'] ?? null, $v['state'] ?? 'pending'),
                'applied_at'   => self::orDefault($old['applied_at'] ?? null, null),
                'note'         => self::orDefault($old['note'] ?? null, $v['note'] ?? ''),
                'refs'         => self::unique(array_merge(self::listOf($old['refs'] ?? null), self::listOf($v['refs'] ?? null))),
                'fix_versions' => self::unique(array_merge(self::listOf($old['fix_versions'] ?? null), self::listOf($v['fix_versions'] ?? null))),
            ]);
        }
        if ($repo !== '') {
            $db['repo'] = $repo;
        }
        $db['updated'] = $now;
        return $db;
    }

    /**
     * Retire pending records of one source that GitHub no longer reports:
     * an alert that was fixed or dismissed, an issue that was closed. Only
     * called with a complete listing, never after a failed or partial one.
     *
     * @param array<string, mixed> $db
     * @param array<string, true>  $seenKeys keys of the records just collected from $source
     * @param array<int, true>|null $openRefs for issues: the open issue numbers (a record
     *                                        stays while any of its refs is open)
     * @return array<string, mixed>
     */
    public static function retire(array $db, string $source, array $seenKeys, string $now, ?array $openRefs = null): array
    {
        foreach ($db['vulns'] as $key => $v) {
            if (($v['source'] ?? null) !== $source || ($v['state'] ?? null) !== 'pending' || isset($seenKeys[$key])) {
                continue;
            }
            if ($openRefs !== null) {
                foreach (self::listOf($v['refs'] ?? null) as $ref) {
                    if (is_int($ref) && isset($openRefs[$ref])) {
                        continue 2;
                    }
                }
            }
            $db['vulns'][$key]['state'] = 'resolved';
            $db['vulns'][$key]['note']  = "no longer open on GitHub as of {$now}";
        }
        return $db;
    }

    /**
     * Record apply outcomes in one pass. (Writing one key at a time rewrote
     * the whole file per record, O(n^2): over ten minutes on 2k records.)
     *
     * @param array<string, mixed>                                $db
     * @param list<array{key: string, state: string, note: string}> $updates
     * @return array<string, mixed>
     */
    public static function applyStates(array $db, array $updates, string $now): array
    {
        foreach ($updates as $u) {
            if (!isset($db['vulns'][$u['key']])) {
                continue;
            }
            $db['vulns'][$u['key']]['state'] = $u['state'];
            $db['vulns'][$u['key']]['note']  = $u['note'];
            if ($u['state'] === 'applied') {
                $db['vulns'][$u['key']]['applied_at'] = $now;
            }
        }
        return $db;
    }

    /**
     * @param array<string, mixed> $db
     */
    public static function countState(array $db, string $state): int
    {
        $n = 0;
        foreach ($db['vulns'] as $v) {
            if (($v['state'] ?? null) === $state) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * jq `//`: null and false fall through to the default.
     */
    private static function orDefault(mixed $value, mixed $default): mixed
    {
        return $value === null || $value === false ? $default : $value;
    }

    /**
     * @return list<mixed>
     */
    private static function listOf(mixed $value): array
    {
        return is_array($value) ? array_values($value) : [];
    }

    /**
     * jq `unique`: sorted (numbers before strings), duplicates removed.
     *
     * @param list<mixed> $values
     * @return list<mixed>
     */
    private static function unique(array $values): array
    {
        $out = [];
        foreach ($values as $v) {
            $out[json_encode($v)] = $v;
        }
        $out = array_values($out);
        usort($out, static function ($a, $b): int {
            $ta = is_int($a) || is_float($a) ? 0 : 1;
            $tb = is_int($b) || is_float($b) ? 0 : 1;
            if ($ta !== $tb) {
                return $ta <=> $tb;
            }
            return $ta === 0 ? $a <=> $b : strcmp((string)$a, (string)$b);
        });
        return $out;
    }
}
