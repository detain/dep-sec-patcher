<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Leaves an audited directory as it was found, apart from the changes the mode
 * allows.
 *
 * Package managers drop node_modules/, vendor/, target/, obj/, .dart_tool/ and
 * friends into the scanned tree, and audits need lockfiles that projects
 * do not always ship. The guard snapshots the directory's top level (and
 * sbt's project/) before an audit, then:
 *   - always removes entries that did not exist before but are build or
 *     dependency directories;
 *   - in check mode ("audit only, no writes") also removes every other new
 *     file and restores every file whose content changed.
 *
 * Only entries that did NOT exist beforehand are ever deleted, so a project's
 * own bin/ or build/ directory is never touched.
 */
final class WorkspaceGuard
{
    private const BUILD_DIRS = [
        'node_modules', 'vendor', 'target', 'obj', 'bin', 'build', '.gradle', '.dart_tool', '_build', 'deps',
        '.build', '.bundle', '.venv', '__pycache__', '.bsp', 'project/target', 'project/project',
        '.swiftpm', '.pub-cache', '.mix', '.elixir_ls',
    ];
    private const MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024;

    /** @var array<string, true> entries present before */
    private array $before = [];
    /** @var array<string, string> file => content, for restoring in check mode */
    private array $contents = [];

    public function __construct(private string $dir, private bool $checkMode)
    {
        foreach (['', 'project/'] as $prefix) {
            $entries = @scandir($this->dir . '/' . $prefix);
            if ($entries === false) {
                continue;
            }
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $rel = $prefix . $entry;
                $this->before[$rel] = true;
                $abs = $this->dir . '/' . $rel;
                if ($checkMode && is_file($abs) && !is_link($abs) && filesize($abs) <= self::MAX_SNAPSHOT_BYTES) {
                    $this->contents[$rel] = (string)file_get_contents($abs);
                }
            }
        }
    }

    /**
     * @return list<string> human-readable list of what was undone
     */
    public function restore(): array
    {
        $undone = [];
        foreach (['', 'project/'] as $prefix) {
            if ($prefix !== '' && !isset($this->before['project'])) {
                // project/ itself is new; it is handled as a top-level entry
                continue;
            }
            $entries = @scandir($this->dir . '/' . $prefix);
            if ($entries === false) {
                continue;
            }
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $rel = $prefix . $entry;
                if (isset($this->before[$rel])) {
                    continue;
                }
                $isBuildDir = in_array($rel, self::BUILD_DIRS, true);
                if ($isBuildDir || $this->checkMode) {
                    self::remove($this->dir . '/' . $rel);
                    if (!$isBuildDir) {
                        $undone[] = "removed {$rel}";
                    }
                }
            }
        }
        foreach ($this->contents as $rel => $content) {
            $abs = $this->dir . '/' . $rel;
            if (!is_file($abs) || (string)file_get_contents($abs) !== $content) {
                file_put_contents($abs, $content);
                $undone[] = "restored {$rel}";
            }
        }
        return $undone;
    }

    private static function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        // Some tools (go, cargo) create read-only directories, whose entries
        // cannot be unlinked until the directory is writable again
        @chmod($path, 0755);
        $dirs = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($dirs as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isDir() && !$item->isLink()) {
                @chmod($item->getPathname(), 0755);
            }
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isDir() && !$item->isLink()) {
                @rmdir($item->getPathname());
            } else {
                @chmod($item->getPathname(), 0644);
                @unlink($item->getPathname());
            }
        }
        @rmdir($path);
    }
}
