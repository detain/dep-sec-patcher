<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Status output and the PASS/FAIL/SKIP/WARN/INFO counters.
 *
 * Only the parent process counts: forked workers report back through
 * TargetResult, because a counter bumped inside a child is lost when it exits
 * (the original shell script lost every counter bumped inside `bash -c` and xargs).
 */
final class Console
{
    public int $pass = 0;
    public int $fail = 0;
    public int $skip = 0;
    public int $warn = 0;
    public int $info = 0;

    private string $red;
    private string $green;
    private string $yellow;
    private string $blue;
    private string $dim;
    private string $reset;

    public function __construct(
        private bool $color,
        private string $prefix = '[dep-sec-patcher]'
    ) {
        $this->red    = $color ? "\033[0;31m" : '';
        $this->green  = $color ? "\033[0;32m" : '';
        $this->yellow = $color ? "\033[0;33m" : '';
        $this->blue   = $color ? "\033[0;34m" : '';
        $this->dim    = $color ? "\033[2m" : '';
        $this->reset  = $color ? "\033[0m" : '';
    }

    public function ok(string $msg): void
    {
        $this->pass++;
        $this->emit("{$this->green}[OK]{$this->reset}   {$msg}");
    }

    public function fail(string $msg): void
    {
        $this->fail++;
        $this->emit("{$this->red}[FAIL]{$this->reset} {$msg}");
    }

    public function skip(string $msg): void
    {
        $this->skip++;
        $this->emit("{$this->yellow}[SKIP]{$this->reset} {$msg}");
    }

    public function warn(string $msg): void
    {
        $this->warn++;
        $this->emit("{$this->yellow}[WARN]{$this->reset} {$msg}");
    }

    public function info(string $msg): void
    {
        $this->info++;
        $this->emit("{$this->blue}[INFO]{$this->reset} {$msg}");
    }

    /**
     * A line that is not a result: headers, notes, progress.
     */
    public function line(string $msg = ''): void
    {
        $this->emit($msg);
    }

    /**
     * Indented, dimmed detail under a result (tool output, failure tails).
     */
    public function detail(string $msg): void
    {
        $this->emit("{$this->dim}    {$msg}{$this->reset}");
    }

    public function heading(string $msg): void
    {
        $this->emit("{$this->blue}── {$msg} " . str_repeat('─', max(3, 60 - mb_strlen($msg))) . $this->reset);
    }

    public function colorFor(string $status): string
    {
        return match ($status) {
            'PASS' => $this->green,
            'FAIL' => $this->red,
            'SKIP', 'WARN' => $this->yellow,
            default => $this->reset,
        };
    }

    public function reset(): string
    {
        return $this->reset;
    }

    public function blue(): string
    {
        return $this->blue;
    }

    /**
     * One write per line: below PIPE_BUF a write to a pipe is atomic, so lines
     * from parallel workers never interleave mid-line.
     */
    private function emit(string $msg): void
    {
        fwrite(STDOUT, $this->prefix . ($msg === '' ? '' : ' ' . $msg) . "\n");
    }
}
