<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Outcome of one external command.
 */
final class CommandResult
{
    /**
     * @param string $output stdout and stderr interleaved as they arrived (tail-capped)
     */
    public function __construct(
        public readonly string $command,
        public readonly int $exitCode,
        public readonly bool $timedOut,
        public readonly string $stdout,
        public readonly string $output,
        public readonly float $seconds,
    ) {
    }

    public function ok(): bool
    {
        return $this->exitCode === 0 && !$this->timedOut;
    }

    /**
     * Last $lines non-empty lines of the combined output.
     *
     * @return list<string>
     */
    public function tail(int $lines = 20): array
    {
        $all = array_values(array_filter(
            preg_split('/\r?\n|\r/', $this->output) ?: [],
            static fn ($l) => trim($l) !== ''
        ));
        return array_slice($all, -$lines);
    }

    /**
     * Short reason for a failure, for result lines.
     */
    public function failureReason(): string
    {
        if ($this->timedOut) {
            return 'timed out after ' . self::duration($this->seconds);
        }
        return $this->exitCode === 127 ? 'command not found / failed to start' : 'exit ' . $this->exitCode;
    }

    public static function duration(float $seconds): string
    {
        $s = (int)round($seconds);
        if ($s < 60) {
            return $s . 's';
        }
        if ($s < 3600) {
            return intdiv($s, 60) . 'm' . sprintf('%02d', $s % 60) . 's';
        }
        return intdiv($s, 3600) . 'h' . sprintf('%02d', intdiv($s % 3600, 60)) . 'm';
    }
}
