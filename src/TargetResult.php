<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * What one ecosystem audit of one directory found. Built in the worker,
 * reported and counted by the parent.
 */
final class TargetResult
{
    public const PASS  = 'PASS';
    public const FAIL  = 'FAIL';   // vulnerabilities at or above the threshold
    public const ERROR = 'ERROR';  // the tool itself failed or timed out
    public const WARN  = 'WARN';   // informational step failed, or findings below the threshold
    public const SKIP  = 'SKIP';

    /** @var list<string> */
    public array $notes = [];
    /** @var list<string> */
    public array $tail = [];

    public function __construct(
        public string $status = self::PASS,
        public string $detail = '',
        public int $vulns = 0,
        public int $outdated = 0,
        public float $seconds = 0.0,
    ) {
    }

    public function note(string $note): self
    {
        $this->notes[] = $note;
        return $this;
    }

    /**
     * Record a command failure as an error, keeping the end of its output.
     */
    public static function fromFailure(CommandResult $r, string $what): self
    {
        $t       = new self(self::ERROR, $what . ' ' . $r->failureReason());
        $t->tail = $r->tail(12);
        return $t;
    }

    /**
     * Severity counts -> status: anything high or critical (CVSS >= 7, the
     * default threshold) fails; lower findings only warn.
     *
     * @param array<string, int> $bySeverity lowercase severity => count
     */
    public static function fromSeverities(array $bySeverity, string $what): self
    {
        $total = array_sum($bySeverity);
        if ($total === 0) {
            return new self(self::PASS, "{$what}: no known vulnerabilities");
        }
        $parts = [];
        foreach (['critical', 'high', 'moderate', 'medium', 'low', 'info', 'unknown'] as $sev) {
            if (!empty($bySeverity[$sev])) {
                $parts[] = $bySeverity[$sev] . ' ' . $sev;
            }
        }
        $serious = ($bySeverity['critical'] ?? 0) + ($bySeverity['high'] ?? 0) + ($bySeverity['unknown'] ?? 0);
        return new self(
            $serious > 0 ? self::FAIL : self::WARN,
            "{$what}: {$total} vulnerabilit" . ($total === 1 ? 'y' : 'ies') . ' (' . implode(', ', $parts) . ')',
            $total
        );
    }
}
