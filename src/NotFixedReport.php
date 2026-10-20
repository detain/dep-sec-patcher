<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * The "not fixed and why" diagnostic: still-open Dependabot alerts and
 * still-pending database records, bucketed by the reason they are waiting,
 * each bucket a bounded list of package + version + count.
 *
 * Pure: no I/O. build() shapes the JSON report section; consoleLines()
 * renders the same data as stable text (one total line per section, one
 * itemised line per non-empty bucket).
 *
 * @phpstan-type Item   array{package: string, ecosystem: string, version: string}
 * @phpstan-type Counted array{ecosystem: string, package: string, version: string, count: int}
 * @phpstan-type Bucket array{total: int, items: list<Counted>, more: int}
 * @phpstan-type Section array{total: int, buckets: array<string, Bucket>}
 * @phpstan-type Report array{dependabot_alerts: Section, vuln_db_records: Section}
 */
final class NotFixedReport
{
    /** Items per bucket in the JSON report; the rest only shows as +N more. */
    public const TOP = 10;
    /** Items per bucket on the console, which must stay compact. */
    public const CONSOLE_TOP = 3;

    /** Report order for the Dependabot section. @var list<string> */
    public const DEPENDABOT_BUCKETS = [
        'fix-available-awaiting-bot-PR', 'no-fix-upstream', 'needs-major', 'covered-by-open-PR',
    ];
    /** Report order for the database section. @var list<string> */
    public const DATABASE_BUCKETS = [
        'needs-major', 'no-valid-fix', 'override-did-not-evict', 'not-declared', 'manifest-missing', 'cannot-edit', 'no-fix-yet', 'would-set', 'other',
    ];

    /**
     * Which bucket an auto-fix note describes, keyed on the wording the
     * planner writes into the record.
     */
    public static function noteReason(string $note): string
    {
        if ($note === '') {
            return 'other';
        }
        return match (true) {
            str_starts_with($note, 'no valid fix')            => 'no-valid-fix',
            str_contains($note, 'lock still resolves')        => 'override-did-not-evict',
            str_contains($note, 'needs a major upgrade')      => 'needs-major',
            str_starts_with($note, 'manifest not found')      => 'manifest-missing',
            str_starts_with($note, 'cannot edit')             => 'cannot-edit',
            str_contains($note, 'not declared')
                || str_contains($note, 'neither declared')
                || str_contains($note, 'workspace specifier') => 'not-declared',
            str_contains($note, 'no fixed version')           => 'no-fix-yet',
            str_starts_with($note, 'would set')               => 'would-set',
            default                                           => 'other',
        };
    }

    /**
     * Shape two bucketed item lists into the report section. Each item is
     * {package, ecosystem, version}; identical items collapse into one with
     * a count. Empty buckets are left out; the totals count every record.
     *
     * @param array<string, list<Item>> $dependabot
     * @param array<string, list<Item>> $database
     * @return Report
     */
    public static function build(array $dependabot, array $database): array
    {
        return [
            'dependabot_alerts' => self::section($dependabot, self::DEPENDABOT_BUCKETS),
            'vuln_db_records'   => self::section($database, self::DATABASE_BUCKETS),
        ];
    }

    /**
     * @param array<string, list<Item>> $buckets
     * @param list<string>              $order
     * @return Section
     */
    private static function section(array $buckets, array $order): array
    {
        $names   = array_merge($order, array_keys(array_diff_key($buckets, array_flip($order))));
        $section = ['total' => 0, 'buckets' => []];
        foreach ($names as $name) {
            $items = $buckets[$name] ?? [];
            if ($items === []) {
                continue;
            }
            $section['buckets'][$name] = self::aggregate($items, self::TOP);
            $section['total']         += count($items);
        }
        return $section;
    }

    /**
     * Count identical items, highest first, capped at $top with the rest
     * summarised in `more`.
     *
     * @param list<Item> $items
     * @return Bucket
     */
    public static function aggregate(array $items, int $top = self::TOP): array
    {
        $counts = [];
        foreach ($items as $item) {
            $k = $item['ecosystem'] . "\0" . $item['package'] . "\0" . $item['version'];
            $counts[$k] = ($counts[$k] ?? 0) + 1;
        }
        arsort($counts);
        $out = [];
        foreach ($counts as $k => $n) {
            [$eco, $pkg, $ver] = explode("\0", $k, 3);
            $out[] = ['ecosystem' => $eco, 'package' => $pkg, 'version' => $ver, 'count' => $n];
        }
        $shown = array_slice($out, 0, $top);
        return ['total' => array_sum($counts), 'items' => $shown, 'more' => count($out) - count($shown)];
    }

    /**
     * The section as console text: a header, then one total line per
     * non-empty source and one itemised line per non-empty bucket.
     *
     * @param Report $report
     * @return list<string>
     */
    public static function consoleLines(array $report): array
    {
        $lines = ['not fixed and why:'];
        $what  = ['dependabot_alerts' => 'open Dependabot alerts', 'vuln_db_records' => 'pending database records'];
        foreach ($what as $key => $label) {
            $section = $report[$key];
            if ($section['total'] === 0) {
                continue;
            }
            $parts = [];
            foreach ($section['buckets'] as $name => $bucket) {
                $parts[] = $name . '=' . $bucket['total'];
            }
            $lines[] = "  {$label} ({$section['total']}): " . implode(', ', $parts);
            foreach ($section['buckets'] as $name => $bucket) {
                $names = array_slice(array_map([self::class, 'itemName'], $bucket['items']), 0, self::CONSOLE_TOP);
                $more  = count($bucket['items']) - count($names);
                $lines[] = "    {$name}: " . implode(', ', $names) . ($more > 0 ? " (+{$more} more)" : '');
            }
        }
        return count($lines) === 1 ? [] : $lines;
    }

    /**
     * @param Counted $item
     */
    private static function itemName(array $item): string
    {
        $name = trim($item['ecosystem'] . ' ' . $item['package'] . ' ' . $item['version']);
        return $name . ' x' . $item['count'];
    }
}
