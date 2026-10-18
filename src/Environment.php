<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * PATH for the tools this runs. Cron and systemd start with a minimal PATH
 * and never source ~/.bashrc, so the usual per-user install locations of Go,
 * cargo, .NET global tools and SDKMAN candidates are added in front, and
 * those of nvm, Yarn, pnpm, swiftly, ~/.local/bin and $GEM_HOME behind.
 *
 * Pure apart from the injectable directory checks.
 */
final class Environment
{
    /**
     * @param array<string, string>             $env
     * @param (callable(string): bool)|null      $isDir
     * @param (callable(string): list<string>)|null $glob
     */
    public static function toolPath(array $env, ?callable $isDir = null, ?callable $glob = null): string
    {
        $isDir ??= static fn (string $d): bool => is_dir($d);
        $glob  ??= static fn (string $p): array => glob($p, GLOB_ONLYDIR) ?: [];
        $home   = rtrim($env['HOME'] ?? '', '/');

        $extra = ['/usr/local/go/bin'];
        if (($env['GOBIN'] ?? '') !== '') {
            $extra[] = $env['GOBIN'];
        }
        $gopath = $env['GOPATH'] ?? '';
        foreach ($gopath !== '' ? explode(':', $gopath) : ($home !== '' ? [$home . '/go'] : []) as $dir) {
            if ($dir !== '') {
                $extra[] = rtrim($dir, '/') . '/bin';
            }
        }
        $cargo = $env['CARGO_HOME'] ?? ($home !== '' ? $home . '/.cargo' : '');
        if ($cargo !== '') {
            $extra[] = rtrim($cargo, '/') . '/bin';
        }
        $dotnet = $env['DOTNET_CLI_HOME'] ?? $home;
        if ($dotnet !== '') {
            $extra[] = rtrim($dotnet, '/') . '/.dotnet/tools';
        }
        $sdkman = $env['SDKMAN_DIR'] ?? ($home !== '' ? $home . '/.sdkman' : '');
        if ($sdkman !== '') {
            foreach ($glob(rtrim($sdkman, '/') . '/candidates/*/current/bin') as $dir) {
                $extra[] = $dir;
            }
        }

        // Per-user installs that usually reach PATH only through an rc file:
        // appended, so they fill gaps without overriding the caller's choice
        // cron's default PATH is /usr/bin:/bin, without /usr/local/bin
        $fallback = ['/usr/local/bin'];
        if ($home !== '') {
            $fallback[] = $home . '/.local/bin';
            $fallback[] = $home . '/.yarn/bin';
            $fallback[] = $home . '/.local/share/swiftly/bin';
        }
        $pnpm = $env['PNPM_HOME'] ?? ($home !== '' ? $home . '/.local/share/pnpm' : '');
        if ($pnpm !== '') {
            $fallback[] = rtrim($pnpm, '/');
        }
        if (($env['GEM_HOME'] ?? '') !== '') {
            $fallback[] = rtrim($env['GEM_HOME'], '/') . '/bin';
        }
        // nvm: the newest installed Node.js
        $nvm = $env['NVM_DIR'] ?? ($home !== '' ? $home . '/.nvm' : '');
        if ($nvm !== '') {
            $nodes = $glob(rtrim($nvm, '/') . '/versions/node/v*/bin');
            usort($nodes, static fn (string $a, string $b): int => version_compare(basename(dirname($b)), basename(dirname($a))));
            if ($nodes !== []) {
                $fallback[] = $nodes[0];
            }
        }

        $path    = $env['PATH'] ?? '';
        $entries = array_merge(
            array_values(array_filter($extra, $isDir)),
            $path !== '' ? explode(':', $path) : ['/usr/local/bin', '/usr/bin', '/bin'],
            array_values(array_filter($fallback, $isDir))
        );
        // First occurrence wins a PATH lookup, so dropping later duplicates
        // changes nothing but the length
        $seen = [];
        $out  = [];
        foreach ($entries as $entry) {
            if ($entry === '' || isset($seen[$entry])) {
                continue;
            }
            $seen[$entry] = true;
            $out[]        = $entry;
        }
        return implode(':', $out);
    }
}
