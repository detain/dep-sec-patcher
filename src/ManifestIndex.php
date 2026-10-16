<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * One walk of the scanned tree, shared by every ecosystem.
 *
 * Dependency and build directories are pruned: a leftover vendor/ or
 * node_modules/ holds other projects' manifests, which must never be audited
 * or "fixed" as if they were ours. Directory symlinks are not followed.
 *
 * With a subdirectory only that part of the tree is walked, but every path is
 * still relative to the root, the coordinate system GitHub reports manifest
 * paths in.
 */
final class ManifestIndex
{
    public const PRUNE = [
        '.git', 'node_modules', 'vendor', 'target', '.gradle', '.dart_tool', '__pycache__',
        '.venv', '.tox', '_build', '.build', '.bundle', '.idea', '.scannerwork',
    ];

    /** @var list<string> paths relative to the root */
    private array $files = [];
    /** @var array<string, true> extra directory names pruned anywhere */
    private array $excludeNames = [];
    /** @var array<string, true> extra directory paths (relative to the root) pruned */
    private array $excludePaths = [];

    /**
     * @param string       $subdir  walk only this directory (relative to the root, '' = all)
     * @param list<string> $exclude extra directories to prune: a bare name matches
     *                              anywhere, a path containing '/' is relative to the root
     */
    public function __construct(private string $root, string $subdir = '', array $exclude = [])
    {
        foreach ($exclude as $entry) {
            $entry = trim($entry, '/');
            if ($entry === '') {
                continue;
            }
            if (str_contains($entry, '/')) {
                $this->excludePaths[$entry] = true;
            } else {
                $this->excludeNames[$entry] = true;
            }
        }
        $subdir = trim($subdir, '/');
        if ($subdir === '' || !$this->pruned($subdir)) {
            $this->walk($subdir);
        }
        sort($this->files, SORT_STRING);
    }

    /**
     * @param list<string> $files relative paths, for tests
     */
    public static function fromList(string $root, array $files): self
    {
        $index        = (new \ReflectionClass(self::class))->newInstanceWithoutConstructor();
        $index->root  = $root;
        $index->files = $files;
        $index->excludeNames = [];
        $index->excludePaths = [];
        sort($index->files, SORT_STRING);
        return $index;
    }

    /**
     * @return list<string>
     */
    public function files(): array
    {
        return $this->files;
    }

    /**
     * Directories (relative, '' for the root) containing a file whose basename
     * matches any of the fnmatch() patterns.
     *
     * @param list<string> $patterns
     * @return list<string>
     */
    public function dirsWith(array $patterns): array
    {
        $dirs = [];
        foreach ($this->files as $file) {
            $base = basename($file);
            foreach ($patterns as $pattern) {
                if (fnmatch($pattern, $base)) {
                    $dir        = dirname($file);
                    $dirs[$dir === '.' ? '' : $dir] = true;
                    break;
                }
            }
        }
        $dirs = array_map('strval', array_keys($dirs));
        sort($dirs, SORT_STRING);
        return $dirs;
    }

    /**
     * @param list<string> $patterns
     */
    public function any(array $patterns): bool
    {
        return $this->dirsWith($patterns) !== [];
    }

    public function root(): string
    {
        return $this->root;
    }

    /**
     * Whether a directory (relative to the root) is excluded by the extra
     * names or paths.
     */
    private function pruned(string $rel): bool
    {
        return isset($this->excludePaths[$rel]) || isset($this->excludeNames[basename($rel)]);
    }

    private function walk(string $rel): void
    {
        $abs     = $rel === '' ? $this->root : $this->root . '/' . $rel;
        $entries = @scandir($abs);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $abs . '/' . $entry;
            $sub  = $rel === '' ? $entry : $rel . '/' . $entry;
            if (is_link($path)) {
                if (is_file($path)) {
                    $this->files[] = $sub;
                }
                continue;
            }
            if (is_dir($path)) {
                if (!in_array($entry, self::PRUNE, true) && !$this->pruned($sub)) {
                    $this->walk($sub);
                }
                continue;
            }
            $this->files[] = $sub;
        }
    }
}
