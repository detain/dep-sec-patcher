<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use JsonException;
use RuntimeException;

/**
 * Per-repository memory for the close-fixed step: what each open issue's
 * last verdict was, what it was based on, and which files it depended on.
 * Without it every run re-verifies thousands of issues whose manifests have
 * not changed since the last run, and re-pays for the same lockfile reads
 * once per duplicate a Mend bot filed per directory.
 *
 * File format (one per repository, under its state directory):
 *   {"schema":1, "repo":"owner/name", "updated":"<iso>", "issues":{"<number>":{...}}}
 *
 * An entry carries verdict, checked_at, since (how long this same verdict
 * has stood) and the needs key, plus what the verdict was about — why
 * (unverifiable reason class), detail, evidence (closing table for a fixed
 * verdict), paths (the manifest and lockfile names it read), head (the
 * commit it was drawn against, for a diff-based change scan), key, and the
 * bookkeeping title_hash, cve, package, annotated_at.
 *
 * reuseVerdict(), needsAnnotation(), resolve() and key() are pure;
 * load() and save() are the only I/O. Ages arrive as the caller's
 * PrTriageState::secondsSince() result, so this class never reads a clock.
 *
 * @phpstan-import-type Need from IssueVerifier
 * @phpstan-import-type Verdict from IssueVerifier
 */
final class CloseState
{
    /** Seconds a non-transitive verdict may stand in for re-verification. */
    public const REUSE_WINDOW = 604800;          // 7 days
    /** Seconds an open issue's entry survives before the next run re-reads it. */
    public const ENTRY_RETENTION = 2592000;      // 30 days

    /** @var list<string> what an entry's verdict field can hold */
    public const VERDICTS = ['fixed', 'unresolved', 'unverifiable', 'out-of-scope'];

    /** The unverifiable class whose only cure is a lockfile appearing */
    public const TRANSITIVE_WHY = 'transitive, no lockfile';

    /** @var array<string, array<string, mixed>> */
    private array $issues;

    /**
     * @param array<string, array<string, mixed>> $issues the entries read, or seeded
     */
    private function __construct(
        private readonly string $path,
        private readonly string $now,
        private readonly string $repo,
        array $issues
    ) {
        $this->issues = $issues;
    }

    /**
     * Read the memory for one repository. A missing file yields a fresh one;
     * an unreadable one is reported through $corrupt and also starts fresh:
     * lost memory must not stop a run from closing what is verifiably fixed.
     *
     * @param-out bool $corrupt
     */
    public static function load(string $path, string $now, string $repo = '', ?bool &$corrupt = null): self
    {
        $corrupt = false;
        $issues  = [];
        if (is_file($path) && filesize($path) > 0) {
            try {
                $data = json_decode((string)file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                $data = null;
            }
            if (is_array($data) && is_array($data['issues'] ?? null)) {
                foreach ($data['issues'] as $number => $entry) {
                    $number = (string)$number;
                    if (is_array($entry) && preg_match('/^\d+$/', $number) === 1) {
                        $issues[$number] = $entry;
                    }
                }
            } else {
                $corrupt = true;
            }
        }
        return new self($path, $now, $repo, $issues);
    }

    /**
     * What is remembered about one issue; [] when it never was.
     *
     * @return array<string, mixed>
     */
    public function get(string $number): array
    {
        return $this->issues[$number] ?? [];
    }

    /**
     * Remember what one verification concluded. An entry whose verdict and
     * unverifiable reason are unchanged keeps its original `since` — that is
     * what makes "unverifiable for over a week" a real age — and its record
     * of having been annotated, so re-verification cannot restart either clock.
     *
     * @param array<string, mixed> $fields key, why, detail, evidence, paths,
     *                                     head, title_hash, cve, package
     */
    public function remember(string $number, string $verdict, array $fields): void
    {
        $old  = $this->issues[$number] ?? [];
        $same = $old !== []
            && (string)($old['verdict'] ?? '') === $verdict
            && (string)($old['why'] ?? '') === (string)($fields['why'] ?? '');
        $entry = $same
            ? array_merge($old, $fields, [
                'verdict'      => $verdict,
                'checked_at'   => $this->now,
                'since'        => (string)($old['since'] ?? $old['checked_at'] ?? $this->now),
                'annotated_at' => (string)($old['annotated_at'] ?? ''),
            ])
            // A new verdict is a new record: fields describing the old one
            // (its why, its detail, its closing table) must not haunt it.
            : $fields + [
                'verdict'    => $verdict,
                'checked_at' => $this->now,
                'since'      => $this->now,
            ];
        if (($entry['annotated_at'] ?? '') === '') {
            unset($entry['annotated_at']);
        }
        if (($entry['why'] ?? '') === '') {
            unset($entry['why']);
        }
        if (($entry['detail'] ?? '') === '') {
            unset($entry['detail']);
        }
        if (($entry['evidence'] ?? '') === '') {
            unset($entry['evidence']);
        }
        if (($entry['cve'] ?? '') === '') {
            unset($entry['cve']);
        }
        if (($entry['package'] ?? '') === '') {
            unset($entry['package']);
        }
        $this->issues[$number] = $entry;
    }

    /**
     * Note that the issue has been told, in a comment, what is missing.
     */
    public function markAnnotated(string $number): void
    {
        if (isset($this->issues[$number])) {
            $this->issues[$number]['annotated_at'] = $this->now;
        }
    }

    /**
     * Forget what issues GitHub no longer lists as open: a closed issue's
     * memory has done its job. Entries for open issues age out after
     * ENTRY_RETENTION so no verdict stands on memory alone for a month —
     * except one an annotated unverifiable: its comment is the repository's
     * record, and a fresh entry after the drop could post a second one.
     *
     * @param list<string> $openNumbers
     */
    public function retain(array $openNumbers): void
    {
        $open = array_flip($openNumbers);
        foreach (array_keys($this->issues) as $number) {
            $number = (string)$number;
            if (!isset($open[$number])) {
                unset($this->issues[$number]);
                continue;
            }
            $entry = $this->issues[$number];
            $kept  = (string)($entry['verdict'] ?? '') === 'unverifiable' && ($entry['annotated_at'] ?? '') !== '';
            $age   = PrTriageState::secondsSince((string)($entry['checked_at'] ?? ''), $this->now);
            if (!$kept && ($age === null || $age > self::ENTRY_RETENTION)) {
                unset($this->issues[$number]);
            }
        }
    }

    /**
     * The oldest verification still on file, for one `git log --since` over
     * all of them; '' when the memory is empty.
     */
    public function oldestCheck(): string
    {
        $oldest = '';
        foreach ($this->issues as $entry) {
            $at = (string)($entry['checked_at'] ?? '');
            if ($at !== '' && ($oldest === '' || strcmp($at, $oldest) < 0)) {
                $oldest = $at;
            }
        }
        return $oldest;
    }

    /**
     * The distinct commits remembered verdicts were drawn against. Entries
     * from before commits were recorded come back as '' among them: nothing
     * can be diffed against those, and the caller falls back to scanning by
     * date until re-verification has replaced them.
     *
     * @return list<string>
     */
    public function rememberedHeads(): array
    {
        $heads = [];
        foreach ($this->issues as $entry) {
            $heads[(string)($entry['head'] ?? '')] = true;
        }
        return array_keys($heads);
    }

    /**
     * The stable identity of a requirement list: what a verdict was computed
     * from, so changed issue data (a bot edit, a new OSV fix) invalidates the
     * cached verdict even when no file changed.
     *
     * @param list<Need> $needs
     */
    public static function key(array $needs): string
    {
        return sha1(json_encode($needs, JSON_THROW_ON_ERROR) ?: '');
    }

    /**
     * Whether the remembered verdict can stand in for verifying again:
     * a known verdict about the same requirements, a readable age, files
     * untouched since the check. One verdict lives by its own rule —
     * "transitive, no lockfile" can only change when a lockfile appears,
     * so it is reused at any age (ENTRY_RETENTION still forces a fresh
     * look monthly); every other verdict expires after $maxAge seconds.
     *
     * @param array<string, mixed> $entry
     */
    public static function reuseVerdict(array $entry, string $needsKey, ?int $age, bool $pathChanged, bool $lockfileAppeared, int $maxAge = self::REUSE_WINDOW): bool
    {
        if ($entry === [] || !in_array((string)($entry['verdict'] ?? ''), self::VERDICTS, true)) {
            return false;
        }
        if ($needsKey === '' || (string)($entry['key'] ?? '') !== $needsKey) {
            return false;
        }
        if ($age === null || $pathChanged) {
            return false;
        }
        if ((string)$entry['verdict'] === 'unverifiable' && (string)($entry['why'] ?? '') === self::TRANSITIVE_WHY) {
            return !$lockfileAppeared;
        }
        return $age <= $maxAge;
    }

    /**
     * Whether an issue has been unverifiable long enough to deserve one
     * comment saying what is missing: continuously past $maxAge (aged on
     * `since`, which re-verification does not reset) and never annotated.
     *
     * @param array<string, mixed> $entry the entry as it stood before this run
     */
    public static function needsAnnotation(array $entry, ?int $age, int $maxAge = self::REUSE_WINDOW): bool
    {
        if ($age === null || $age <= $maxAge || ($entry['annotated_at'] ?? '') !== '') {
            return false;
        }
        return (string)($entry['verdict'] ?? '') === 'unverifiable';
    }

    /**
     * The verdict an entry remembers, in the shape IssueVerifier::verify
     * returns it.
     *
     * @param array<string, mixed> $entry
     * @return Verdict
     */
    public static function verdictFrom(array $entry): array
    {
        $verdict = (string)($entry['verdict'] ?? '');
        return [
            'ok'       => $verdict === 'fixed',
            'reason'   => $verdict === 'fixed' ? '' : $verdict,
            'detail'   => (string)($entry['detail'] ?? ''),
            'evidence' => (string)($entry['evidence'] ?? ''),
        ];
    }

    /**
     * Resolve one issue's verdict as cheaply as memory allows: an identical
     * requirement list already verified this run answers at once — the Mend
     * bot files one issue per directory per CVE, so thousands share one check
     * — else a live cached verdict, else a fresh verification that feeds the
     * batch for the duplicates to come.
     *
     * @param list<Need>      $needs
     * @param array<string, mixed> $entry
     * @param array<string, Verdict> $batch
     * @param callable(list<Need>): Verdict $verify
     * @return array{0: Verdict, 1: string} origin: verified / shared / cached
     */
    public static function resolve(array $needs, array $entry, ?int $age, bool $pathChanged, bool $lockfileAppeared, callable $verify, array &$batch): array
    {
        $batchKey = json_encode($needs, JSON_THROW_ON_ERROR) ?: '';
        if (array_key_exists($batchKey, $batch)) {
            return [$batch[$batchKey], 'shared'];
        }
        if (self::reuseVerdict($entry, self::key($needs), $age, $pathChanged, $lockfileAppeared)) {
            return [self::verdictFrom($entry), 'cached'];
        }
        $verdict = $verify($needs);
        $batch[$batchKey] = $verdict;
        return [$verdict, 'verified'];
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
            'issues'  => $this->issues === [] ? new \stdClass() : $this->issues,
        ];
        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException("cannot create {$dir}");
        }
        $tmp = tempnam($dir, '.close.');
        if ($tmp === false) {
            throw new RuntimeException("cannot create a temp file in {$dir}");
        }
        if (file_put_contents($tmp, JsonFile::encode($data)) === false || !rename($tmp, $this->path)) {
            @unlink($tmp);
            throw new RuntimeException("cannot write {$this->path}");
        }
        @chmod($this->path, 0600);
    }
}
