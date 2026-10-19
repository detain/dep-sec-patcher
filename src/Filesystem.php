<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Recursive removal that stays inside the tree it is given.
 */
final class Filesystem
{
    /**
     * Delete a file, a symlink or a whole directory tree. Symlinks are
     * unlinked, never followed or chmod()ed: a clone of an untrusted
     * repository can link anywhere, and chmod() acts on the link's target.
     */
    public static function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        try {
            // Some tools (go, cargo) create read-only directories, whose
            // entries cannot be unlinked until the directory is writable again
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
                    @unlink($item->getPathname());
                }
            }
        } catch (\UnexpectedValueException) {
            // A directory that cannot be opened: leave the rest for the caller to report
        }
        @rmdir($path);
    }
}
