<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;
use Detain\DepSecPatcher\Version;

/**
 * One language ecosystem: which directories it owns, how to update and audit
 * one of them, and how many copies of its tool may run at once.
 */
abstract class Auditor
{
    /** Option name (--no-<name>) and summary key. */
    abstract public function name(): string;

    /** Program whose absence skips the ecosystem. */
    abstract public function tool(): string;

    /**
     * Basename patterns (fnmatch) that make a directory a target.
     *
     * @return list<string>
     */
    abstract public function manifests(): array;

    abstract public function audit(Context $ctx, string $dir): TargetResult;

    /**
     * Reason to skip the whole ecosystem, or null to run it.
     */
    public function skipReason(Context $ctx): ?string
    {
        return ProcessRunner::has($this->tool()) ? null : $this->tool() . ' not installed';
    }

    /**
     * @return list<string> target directories, relative to the root
     */
    public function targets(Context $ctx): array
    {
        return $ctx->files->dirsWith($this->manifests());
    }

    /**
     * One-off work in the parent before any target runs (database updates,
     * tool installs). Runs once even when targets run in parallel.
     *
     * @param list<string> $targets
     */
    public function prepare(Context $ctx, array $targets): void
    {
    }

    /**
     * Directories (relative) an audit of $dir may write into, so the guard
     * can undo build output there too. Defaults to the target itself.
     *
     * @return list<string>
     */
    public function guardDirs(Context $ctx, string $dir): array
    {
        return [$dir];
    }

    /**
     * File names within a guarded directory that the guard must remove again
     * when the audit created them, update mode included — the lockfile of a
     * package manager this directory does not use. Empty by default: what an
     * update run resolved, it normally keeps.
     *
     * @return list<string>
     */
    public function guardPurge(Context $ctx, string $dir): array
    {
        return [];
    }

    /**
     * Concurrency group for a target. Targets in one group share a limit.
     */
    public function group(Context $ctx, string $dir): string
    {
        return $this->name();
    }

    /**
     * Concurrency policy per group this auditor uses.
     *
     * @return array<string, ConcurrencyPolicy>
     */
    public function concurrency(Context $ctx): array
    {
        return [$this->name() => ConcurrencyPolicy::unlimited($this->tool())];
    }

    // ── helpers for subclasses ───────────────────────────────────────────────

    /**
     * @param list<string>          $argv
     * @param array<string, string> $env
     */
    protected function run(Context $ctx, string $dir, array $argv, ?int $timeout = null, array $env = []): CommandResult
    {
        $opt = ['label' => $this->name() . ':' . ($dir === '' ? '.' : $dir), 'env' => $env + $ctx->env];
        if ($timeout !== null) {
            $opt['timeout'] = $timeout;
        }
        return $ctx->runner->run($argv, $this->abs($ctx, $dir), $opt);
    }

    protected function abs(Context $ctx, string $dir): string
    {
        return $dir === '' ? $ctx->root : $ctx->root . '/' . $dir;
    }

    protected function exists(Context $ctx, string $dir, string $file): bool
    {
        return file_exists($this->abs($ctx, $dir) . '/' . $file);
    }

    /**
     * Policy that is unlimited from $minimum on, and one-at-a-time below it.
     */
    protected function gated(string $tool, string $version, string $minimum, string $why): ConcurrencyPolicy
    {
        if ($version !== '' && Version::gte($version, $minimum)) {
            return ConcurrencyPolicy::unlimited($tool, $version);
        }
        return ConcurrencyPolicy::serial($tool, $version, $why, $minimum);
    }

    /**
     * Decode a tool's JSON output; tolerates log noise before the document.
     */
    protected static function json(string $stdout): mixed
    {
        $stdout = trim($stdout);
        $data   = json_decode($stdout, true);
        if ($data === null) {
            $start = strcspn($stdout, '{[');
            if ($start < strlen($stdout)) {
                $data = json_decode(substr($stdout, $start), true);
            }
        }
        return $data;
    }

    /**
     * Normalise severity labels from different tools.
     */
    protected static function severity(?string $sev): string
    {
        $sev = strtolower(trim((string)$sev));
        return match ($sev) {
            'critical', 'high', 'low', 'info' => $sev,
            'moderate', 'medium' => 'moderate',
            'informational' => 'info',
            default => 'unknown',
        };
    }
}
