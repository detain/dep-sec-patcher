<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Manifest filename knowledge: which ecosystem owns a file, and which source
 * manifest a lockfile belongs to.
 *
 * Pure apart from sourceManifestFor()'s optional directory lister, which is
 * injected so tests do not need a filesystem.
 */
final class ManifestPaths
{
    /**
     * Ecosystem for a manifest path, by basename. Lockfiles are included:
     * Dependabot reports most alerts against the lockfile (package-lock.json
     * etc.) rather than the source manifest.
     */
    public static function ecosystemFor(string $path): string
    {
        $base = basename($path);
        return match (true) {
            in_array($base, ['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'], true)
                => 'npm',
            in_array($base, ['composer.json', 'composer.lock'], true)
                => 'composer',
            preg_match('/requirements.*\.txt$|constraints.*\.txt$/', $base) === 1,
            in_array($base, ['Pipfile', 'Pipfile.lock', 'pyproject.toml', 'poetry.lock', 'setup.py'], true)
                => 'pip',
            $base === 'pom.xml'
                => 'maven',
            str_starts_with($base, 'build.gradle'), $base === 'gradle.lockfile'
                => 'gradle',
            in_array($base, ['go.mod', 'go.sum'], true)
                => 'go',
            in_array($base, ['mix.exs', 'mix.lock'], true)
                => 'hex',
            in_array($base, ['Gemfile', 'Gemfile.lock'], true)
                => 'rubygems',
            in_array($base, ['Cargo.toml', 'Cargo.lock'], true)
                => 'cargo',
            in_array($base, ['pubspec.yaml', 'pubspec.lock'], true)
                => 'pub',
            preg_match('/\.(csproj|fsproj|sln|nuspec)$/', $base) === 1,
            in_array($base, ['packages.config', 'packages.lock.json'], true)
                => 'nuget',
            in_array($base, ['Package.swift', 'Package.resolved'], true)
                => 'swift',
            default => 'unknown',
        };
    }

    /**
     * A lockfile records resolved versions; the package manager regenerates it
     * and it must never be hand-edited (package.json-shaped keys written into a
     * v3 package-lock.json produce a file npm will not honour). Point a fix at
     * the sibling source manifest instead.
     *
     * @param ?callable $listDir (relative dir): list of basenames in it; only
     *        consulted for NuGet, whose project file name varies
     */
    public static function sourceManifestFor(string $rel, ?callable $listDir = null): string
    {
        $dir    = dirname($rel);
        $dir    = $dir === '.' ? '' : $dir;
        $prefix = $dir === '' ? '' : $dir . '/';

        switch (basename($rel)) {
            case 'package-lock.json':
            case 'npm-shrinkwrap.json':
            case 'yarn.lock':
            case 'pnpm-lock.yaml':
                return $prefix . 'package.json';
            case 'composer.lock':
                return $prefix . 'composer.json';
            case 'Gemfile.lock':
                return $prefix . 'Gemfile';
            case 'Cargo.lock':
                return $prefix . 'Cargo.toml';
            case 'go.sum':
                return $prefix . 'go.mod';
            case 'mix.lock':
                return $prefix . 'mix.exs';
            case 'pubspec.lock':
                return $prefix . 'pubspec.yaml';
            case 'Pipfile.lock':
                return $prefix . 'Pipfile';
            case 'poetry.lock':
                return $prefix . 'pyproject.toml';
            case 'packages.lock.json':
                // NuGet keeps the lock beside the project file, whose name varies
                $entries = $listDir !== null ? $listDir($dir) : [];
                sort($entries);
                foreach ($entries as $entry) {
                    if (preg_match('/\.(csproj|fsproj)$/', $entry) === 1) {
                        return $prefix . $entry;
                    }
                }
                return $rel;
            default:
                return $rel;
        }
    }
}
