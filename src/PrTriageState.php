<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use JsonException;
use RuntimeException;

/**
 * Per-repository memory for the dependency-bot PR triage step: which PRs have
 * been seen, what was concluded about each, when the bot was last asked to
 * rebase and how many times. Without it every pass re-discovered the same
 * blocked PRs, asked for the same rebase forever, and never noticed that the
 * alert behind a PR had been resolved by someone else.
 *
 * File format (one per repository, under its state directory):
 *   {"schema":1, "repo":"owner/name", "updated":"<iso>", "prs":{"<number>":{...}}}
 *
 * An entry carries first_seen, last_seen, sightings and outcome, plus the
 * fields an action left behind: rebase_requested_at, rebase_requests,
 * rebase_last_at, merge_commit, alert_driven, title. outcome is one of the
 * words in self::OUTCOMES; the set documents the state file, and reading one
 * back never fails because an older or newer tool used a word it does not know.
 *
 * rebaseAction() and secondsSince() are pure; load() and save() are the only I/O.
 */
final class PrTriageState
{
    /** Times the bot is asked to rebase one PR before it is left alone for good. */
    public const MAX_REBASE_REQUESTS = 3;
    /** Minimum seconds between two rebase requests for the same PR. */
    public const NUDGE_INTERVAL = 86400;
    /** Seconds a gone PR's final verdict is kept as a log; other gone entries drop at once. */
    public const TERMINAL_RETENTION = 2592000;   // 30 days

    /** @var list<string> what an entry's outcome field can hold */
    public const OUTCOMES = [
        'merged', 'auto-merge', 'needs-major', 'blocked-ci', 'blocked-protection', 'merge-failed',
        'rebase-requested', 'rebase-nudged', 'rebase-refused', 'rebase-failed', 'manual-instructions',
        'behind-waiting', 'rebase-waiting', 'blocked-permanent', 'superseded-closed', 'would-supersede',
        'close-failed', 'unknown-mergeability', 'counted',
    ];

    /** @var array<string, array<string, mixed>> */
    private array $prs;

    /**
     * @param array<string, array<string, mixed>> $prs the entries read, or seeded
     */
    private function __construct(
        private readonly string $path,
        private readonly string $now,
        private readonly string $repo,
        array $prs
    ) {
        $this->prs = $prs;
    }

    /**
     * Read the memory for one repository. A missing file yields a fresh one;
     * an unreadable one is reported through $corrupt and also starts fresh:
     * lost throttling must not stop a run from triaging.
     *
     * @param-out bool $corrupt
     */
    public static function load(string $path, string $now, string $repo = '', ?bool &$corrupt = null): self
    {
        $corrupt = false;
        $prs     = [];
        if (is_file($path) && filesize($path) > 0) {
            try {
                $data = json_decode((string)file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                $data = null;
            }
            if (is_array($data) && is_array($data['prs'] ?? null)) {
                foreach ($data['prs'] as $number => $entry) {
                    $number = (string)$number;
                    if (is_array($entry) && preg_match('/^\d+$/', $number) === 1) {
                        $prs[$number] = $entry;
                    }
                }
            } else {
                $corrupt = true;
            }
        }
        return new self($path, $now, $repo, $prs);
    }

    /**
     * One sighting of one PR: the bookkeeping (first_seen, last_seen,
     * sightings) advances and the given fields are merged in.
     *
     * @param array<string, mixed> $changes
     */
    public function record(string $number, array $changes): void
    {
        $old            = $this->prs[$number] ?? [];
        $this->prs[$number] = array_merge($old, [
            'first_seen' => (string)($old['first_seen'] ?? $this->now),
            'last_seen'  => $this->now,
            'sightings'  => (int)($old['sightings'] ?? 0) + 1,
        ], $changes);
    }

    /**
     * What is remembered about one PR; [] when it never was.
     *
     * @return array<string, mixed>
     */
    public function get(string $number): array
    {
        return $this->prs[$number] ?? [];
    }

    /**
     * Forget PRs a complete listing no longer sees. Entries that recorded a
     * final verdict (merged, closed, permanently blocked) stay for
     * TERMINAL_RETENTION as a log; everything else goes at once, so a PR
     * reopened later starts its memory fresh.
     *
     * @param list<string> $openNumbers
     */
    public function retain(array $openNumbers): void
    {
        $open = array_flip($openNumbers);
        foreach (array_keys($this->prs) as $number) {
            $number  = (string)$number;
            $entry   = $this->prs[$number];
            $outcome = (string)($entry['outcome'] ?? '');
            if (isset($open[$number])) {
                continue;
            }
            $terminal = in_array($outcome, ['merged', 'auto-merge', 'blocked-permanent'], true)
                || str_ends_with($outcome, '-closed');
            $age      = self::secondsSince((string)($entry['last_seen'] ?? ''), $this->now);
            if (!$terminal || $age === null || $age > self::TERMINAL_RETENTION) {
                unset($this->prs[$number]);
            }
        }
    }

    /**
     * Atomic replace: a sibling temp file renamed over the original, so an
     * interrupted write never leaves a half file the next run calls corrupt.
     */
    public function save(): void
    {
        $data = [
            'schema'  => 1,
            'repo'    => $this->repo,
            'updated' => $this->now,
            'prs'     => $this->prs === [] ? new \stdClass() : $this->prs,
        ];
        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException("cannot create {$dir}");
        }
        $tmp = tempnam($dir, '.triage.');
        if ($tmp === false) {
            throw new RuntimeException("cannot create a temp file in {$dir}");
        }
        if (file_put_contents($tmp, JsonFile::encode($data)) === false || !rename($tmp, $this->path)) {
            @unlink($tmp);
            throw new RuntimeException("cannot write {$this->path}");
        }
        @chmod($this->path, 0600);
    }

    /**
     * What to do with a PR whose rebase request is still outstanding. Pure
     * throttle arithmetic: $requests counts the rebase commands posted for
     * this PR (the first included), $sinceLastSeconds is the age of the
     * newest one.
     *
     * @return string 'nudge' ask again, 'wait' the last ask is too recent,
     *                'stop'  asked the maximum already: leave it alone
     */
    public static function rebaseAction(int $requests, int $sinceLastSeconds): string
    {
        if ($requests >= self::MAX_REBASE_REQUESTS) {
            return $sinceLastSeconds >= self::NUDGE_INTERVAL ? 'stop' : 'wait';
        }
        return $sinceLastSeconds >= self::NUDGE_INTERVAL ? 'nudge' : 'wait';
    }

    /**
     * Whole seconds from one ISO-8601 UTC timestamp to the next; null when
     * either cannot be read, so callers treat an unreadable record as "no
     * history" rather than as permission to comment again.
     */
    public static function secondsSince(string $then, string $now): ?int
    {
        $from = strtotime($then);
        $to   = strtotime($now);
        return $from === false || $to === false ? null : max(0, $to - $from);
    }
}
