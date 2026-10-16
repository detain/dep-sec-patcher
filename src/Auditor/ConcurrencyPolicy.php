<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

/**
 * How many copies of a tool may run at once, and why.
 */
final class ConcurrencyPolicy
{
    private function __construct(
        public readonly string $tool,
        public readonly int $limit,           // PHP_INT_MAX = no limit
        public readonly string $version,      // detected, '' when unknown
        public readonly string $why = '',     // reason it is serialised
        public readonly string $minimum = '', // version that lifts the limit, '' = none known
    ) {
    }

    public static function unlimited(string $tool, string $version = ''): self
    {
        return new self($tool, PHP_INT_MAX, $version);
    }

    public static function serial(string $tool, string $version, string $why, string $minimum = ''): self
    {
        return new self($tool, 1, $version, $why, $minimum);
    }

    public function serialised(): bool
    {
        return $this->limit === 1;
    }

    /**
     * Startup notice for a serialised tool.
     */
    public function notice(): string
    {
        $tool = $this->tool . ($this->version !== '' ? ' ' . $this->version : '');
        if ($this->minimum !== '') {
            return "{$tool} runs one job at a time: {$this->why}. Upgrade to {$this->tool} >= {$this->minimum} to run it concurrently.";
        }
        return "{$tool} runs one job at a time: {$this->why}.";
    }
}
