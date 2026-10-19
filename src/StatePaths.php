<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use InvalidArgumentException;

/**
 * Where a target's state lives: the vulnerability database, reports, the run
 * lock and (for a remote target) the clone.
 *
 * Default, under ${XDG_STATE_HOME:-~/.local/state}/dep-sec-patcher/:
 *   vulns/<slug>.json   the vulnerability database, kept between runs
 *   <slug>/reports/     the latest run's reports
 *   <slug>/run.lock     one run per target at a time; deleted when the run ends
 *   <slug>/checkout/    the clone of a remote target; deleted when the run
 *                       ends unless --keep-clone
 *
 * The database lives outside <slug>/ so that nothing a rerun needs is in
 * there. With --state-dir everything, the database included, is under STATE.
 *
 * slug(), baseDir() and resolve() are pure.
 */
final class StatePaths
{
    public function __construct(
        public readonly string $stateDir,
        public readonly string $vulnDb,
        public readonly string $reportDir,
        public readonly string $workdir,
        public readonly string $lockFile,
        /** Where the database used to be by default, to move it from; '' when its location was given */
        public readonly string $legacyVulnDb = '',
    ) {
    }

    /**
     * Directory name for a target's state. From the GitHub repository when
     * there is one ("owner__name", lowercased: GitHub names are
     * case-insensitive, and an owner cannot contain "_", so the split is
     * unambiguous); otherwise "<name>-<hash>" of the target's identity (the
     * realpath of a local directory, or the normalised URL of a remote).
     */
    public static function slug(string $githubRepo, string $identity, string $name = ''): string
    {
        if ($githubRepo !== '') {
            return strtolower(str_replace('/', '__', $githubRepo));
        }
        $name = $name !== '' ? $name : basename($identity);
        $name = trim((string)preg_replace('/[^A-Za-z0-9._-]+/', '-', $name), '.-');
        $hash = substr(sha1($identity), 0, 8);
        return ($name === '' ? 'target' : strtolower($name)) . '-' . $hash;
    }

    /**
     * ${XDG_STATE_HOME:-$HOME/.local/state}/dep-sec-patcher. A relative
     * XDG_STATE_HOME is ignored, as the XDG spec requires.
     *
     * @param array<string, string> $env
     */
    public static function baseDir(array $env): string
    {
        $xdg = $env['XDG_STATE_HOME'] ?? '';
        if ($xdg !== '' && str_starts_with($xdg, '/')) {
            return rtrim($xdg, '/') . '/dep-sec-patcher';
        }
        $home = $env['HOME'] ?? '';
        if ($home === '') {
            throw new InvalidArgumentException('cannot locate a state directory: set HOME or XDG_STATE_HOME, or pass --state-dir');
        }
        return rtrim($home, '/') . '/.local/state/dep-sec-patcher';
    }

    /**
     * @param array<string, string> $env
     */
    public static function resolve(Options $opt, string $slug, array $env, string $cwd): self
    {
        $base  = $opt->stateDir === '' ? self::baseDir($env) : '';
        $state = $opt->stateDir !== '' ? self::absolute($opt->stateDir, $cwd) : $base . '/' . $slug;
        $db    = match (true) {
            $opt->vulnDb !== ''   => self::absolute($opt->vulnDb, $cwd),
            $opt->stateDir !== '' => $state . '/vulns.json',
            default               => $base . '/vulns/' . $slug . '.json',
        };
        return new self(
            $state,
            $db,
            $opt->reportDir !== '' ? self::absolute($opt->reportDir, $cwd) : $state . '/reports',
            $opt->workdir !== '' ? self::absolute($opt->workdir, $cwd) : $state . '/checkout',
            $state . '/run.lock',
            $opt->vulnDb === '' && $opt->stateDir === '' ? $state . '/vulns.json' : '',
        );
    }

    /**
     * Absolute, lexically normalised path ("." and ".." resolved, no
     * trailing slash); relative paths are taken from $cwd.
     */
    public static function absolute(string $path, string $cwd): string
    {
        if (!str_starts_with($path, '/')) {
            $path = rtrim($cwd, '/') . '/' . $path;
        }
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($parts);
                continue;
            }
            $parts[] = $part;
        }
        return '/' . implode('/', $parts);
    }

    /**
     * Like realpath(), but also for a path that does not exist yet: the
     * nearest existing ancestor is resolved (following symlinks) and the rest
     * appended.
     */
    public static function canonical(string $path): string
    {
        $path   = self::absolute($path, '/');
        $suffix = '';
        while ($path !== '/' && !file_exists($path)) {
            $suffix = '/' . basename($path) . $suffix;
            $path   = dirname($path);
        }
        $real = realpath($path);
        $full = rtrim($real === false ? $path : $real, '/') . $suffix;
        return $full === '' ? '/' : $full;
    }

    /**
     * Whether $path is $dir or lies inside it (after resolving symlinks).
     */
    public static function inside(string $path, string $dir): bool
    {
        $path = self::canonical($path);
        $dir  = self::canonical($dir);
        return $path === $dir || str_starts_with($path, rtrim($dir, '/') . '/');
    }
}
