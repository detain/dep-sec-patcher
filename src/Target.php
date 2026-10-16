<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * The tree being scanned, after TARGET resolution.
 */
final class Target
{
    /**
     * @param string $root       absolute path of the directory or checkout
     * @param string $subdir     part of $root to scan ('' = all of it)
     * @param string $githubRepo OWNER/NAME for the GitHub steps ('' = none)
     * @param string $repoNote   where $githubRepo came from, or why there is none
     * @param bool   $remote     whether $root is a cache clone of $url
     * @param string $url        remote URL ('' for a local target)
     * @param string $source     TARGET as given on the command line
     */
    public function __construct(
        public readonly string $root,
        public readonly string $subdir = '',
        public readonly string $githubRepo = '',
        public readonly string $repoNote = '',
        public readonly bool $remote = false,
        public readonly string $url = '',
        public readonly string $source = '',
    ) {
    }

    public function scanRoot(): string
    {
        return $this->subdir === '' ? $this->root : $this->root . '/' . $this->subdir;
    }

    /**
     * Whether a path relative to the root (a manifest path as GitHub reports
     * it) lies inside the scanned part of the tree.
     */
    public function inScope(string $rel): bool
    {
        return $this->subdir === '' || str_starts_with(ltrim($rel, '/'), $this->subdir . '/');
    }
}
