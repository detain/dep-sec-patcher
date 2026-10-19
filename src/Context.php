<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Everything an auditor needs, shared (by copy) with forked workers.
 */
final class Context
{
    /** @var array<string, string> extra environment for tool invocations */
    public array $env = [];
    /** @var array<string, string> tool => detected version ('' when unknown) */
    private array $versions = [];
    /** @var array<string, mixed> per-auditor state set during prepare() */
    public array $state = [];

    public function __construct(
        public readonly Options $opt,
        public readonly Console $console,
        public readonly ProcessRunner $runner,
        public readonly string $root,
        public readonly string $reportDir,
        public readonly ManifestIndex $files,
        public readonly string $subdir = '',
    ) {
    }

    /**
     * Directory the whole-tree scanners run in: the root, or --subdir inside it.
     * Target directories ($files) stay relative to the root either way.
     */
    public function scanRoot(): string
    {
        return $this->subdir === '' ? $this->root : $this->root . '/' . $this->subdir;
    }

    public function checkMode(): bool
    {
        return $this->opt->mode === 'check';
    }

    /**
     * Version of a tool, from `$argv` output, cached for the run.
     *
     * @param list<string> $argv
     */
    public function toolVersion(string $tool, array $argv, string $pattern = '/(\d+\.\d+(?:\.\d+)?)/'): string
    {
        if (!array_key_exists($tool, $this->versions)) {
            $version = '';
            if (ProcessRunner::has($argv[0])) {
                $r = $this->runner->run($argv, $this->root, ['timeout' => 120, 'label' => $tool]);
                // Strip ANSI colour: `mvn -v` prints "\e[1mApache Maven 3.8.7\e[m"
                $out = CommandResult::plain($r->output);
                if (preg_match($pattern, $out, $m) === 1) {
                    $version = $m[1];
                }
            }
            $this->versions[$tool] = $version;
        }
        return $this->versions[$tool];
    }

    /**
     * Report directory for one tool, created on demand, outside the scanned tree.
     */
    public function reportPath(string $tool, string $relDir, string $file): string
    {
        $dir = $this->reportDir . '/' . $tool . '/' . ($relDir === '' ? '_root' : str_replace('/', '__', $relDir));
        if (!is_dir($dir)) {
            @mkdir($dir, 0775, true);
        }
        return $dir . '/' . $file;
    }
}
