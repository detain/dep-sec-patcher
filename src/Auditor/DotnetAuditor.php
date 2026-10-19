<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;
use Detain\DepSecPatcher\Version;

/**
 * .NET: dotnet-outdated for updates, `dotnet list package --vulnerable` for
 * the audit; in update mode each package still vulnerable after that is moved
 * to the newest release on its line with `dotnet add package` (a direct
 * reference pins a transitive one), and the audit runs again. Update mode previously never audited at all (it only listed
 * outdated packages), and the listing needs a restore first, which nothing did.
 */
final class DotnetAuditor extends Auditor
{
    private const ENV = [
        'DOTNET_CLI_TELEMETRY_OPTOUT'        => '1',
        'DOTNET_NOLOGO'                      => '1',
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE'  => '1',
        // No long-lived MSBuild nodes or build servers: they outlive the audit
        'MSBUILDDISABLENODEREUSE'                => '1',
        'DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER'   => '1',
        'UseSharedCompilation'                   => 'false',
    ];

    public function name(): string
    {
        return 'dotnet';
    }

    public function tool(): string
    {
        return 'dotnet';
    }

    public function manifests(): array
    {
        return ['*.sln', '*.csproj', '*.fsproj'];
    }

    /**
     * A solution and the projects it references are one target: restoring
     * the .sln covers them, and auditing them again double-counted every
     * vulnerability. Projects outside any solution are targets of their own.
     */
    public function targets(Context $ctx): array
    {
        $owned   = [];
        $targets = [];
        foreach ($ctx->files->dirsWith(['*.sln']) as $dir) {
            $targets[] = $dir;
            foreach ($this->solutionProjects($ctx, $dir) as $projectDir) {
                $owned[$projectDir] = true;
            }
        }
        foreach ($ctx->files->dirsWith(['*.csproj', '*.fsproj']) as $dir) {
            if (!isset($owned[$dir]) && !in_array($dir, $targets, true)) {
                $targets[] = $dir;
            }
        }
        sort($targets, SORT_STRING);
        return $targets;
    }

    public function guardDirs(Context $ctx, string $dir): array
    {
        return array_values(array_unique(array_merge([$dir], $this->solutionProjects($ctx, $dir))));
    }

    /**
     * Directories (relative to the root) of the projects a directory's .sln
     * files reference.
     *
     * @return list<string>
     */
    private function solutionProjects(Context $ctx, string $dir): array
    {
        $dirs = [];
        foreach (glob($this->abs($ctx, $dir) . '/*.sln') ?: [] as $sln) {
            preg_match_all('/^Project\([^)]*\)\s*=\s*"[^"]*",\s*"([^"]+\.(?:cs|fs)proj)"/m', (string)@file_get_contents($sln), $m);
            foreach ($m[1] as $proj) {
                $projDir = dirname(str_replace('\\', '/', $proj));
                $rel     = trim(($dir === '' ? '' : $dir . '/') . ($projDir === '.' ? '' : $projDir), '/');
                if (!str_contains('/' . $rel . '/', '/../')) {
                    $dirs[] = $rel;
                }
            }
        }
        return $dirs;
    }

    public function concurrency(Context $ctx): array
    {
        return ['dotnet' => ConcurrencyPolicy::serial(
            'dotnet',
            $ctx->toolVersion('dotnet', ['dotnet', '--version']),
            'NuGet\'s cross-process locking on the shared global packages folder is only partial (no fixed version known)'
        )];
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $abs   = $this->abs($ctx, $dir);
        $files = array_map('basename', glob($abs . '/*.sln') ?: []);
        if ($files === []) {
            $files = array_map('basename', array_merge(glob($abs . '/*.csproj') ?: [], glob($abs . '/*.fsproj') ?: []));
        }
        $notes = [];

        if (!$ctx->checkMode()) {
            if (ProcessRunner::has('dotnet-outdated')) {
                $r = $this->run($ctx, $dir, ['dotnet-outdated', '-u:Auto'], null, self::ENV);
                if (!$r->ok()) {
                    $notes[] = 'dotnet-outdated ' . $r->failureReason();
                }
            } else {
                $notes[] = 'dotnet-outdated not installed: packages not upgraded';
            }
        }

        $found = $this->listVulnerable($ctx, $dir, $files);
        if ($found instanceof TargetResult) {
            $found->notes = array_merge($notes, $found->notes);
            return $found;
        }

        // dotnet-outdated only moves direct references, and to the newest
        // version it accepts; a vulnerable transitive package (Newtonsoft.Json
        // under Swashbuckle) stays. Pin each vulnerable package to the newest
        // release on its line (any line with --allow-major) by a direct
        // PackageReference, then audit again.
        if (!$ctx->checkMode() && $found['packages'] !== []) {
            $changed = false;
            foreach ($found['packages'] as $pkg) {
                [$moved, $notes[]] = $this->pin($ctx, $dir, $pkg);
                $changed = $changed || $moved;
            }
            if ($changed) {
                $again = $this->listVulnerable($ctx, $dir, $files);
                if ($again instanceof TargetResult) {
                    $again->notes = array_merge($notes, $again->notes);
                    return $again;
                }
                $found = $again;
            }
        }

        $t = TargetResult::fromSeverities($found['counts'], 'dotnet list package --vulnerable');
        $t->notes = array_merge($notes, array_slice(array_values(array_unique($found['hits'])), 0, 10));
        return $t;
    }

    /**
     * Restore and list the vulnerable packages of each solution or project file.
     *
     * @param list<string> $files
     * @return TargetResult|array{counts: array<string, int>, hits: list<string>, packages: list<array{project: string, id: string, version: string, transitive: bool}>}
     */
    private function listVulnerable(Context $ctx, string $dir, array $files): TargetResult|array
    {
        $counts   = [];
        $hits     = [];
        $packages = [];
        foreach ($files as $file) {
            $r = $this->run($ctx, $dir, ['dotnet', 'restore', $file], null, self::ENV);
            if (!$r->ok()) {
                return TargetResult::fromFailure($r, "dotnet restore {$file}");
            }
            $r    = $this->run($ctx, $dir, ['dotnet', 'list', $file, 'package', '--vulnerable', '--include-transitive', '--format', 'json'], null, self::ENV);
            $data = self::json($r->stdout);
            if (!is_array($data) || !isset($data['projects'])) {
                return TargetResult::fromFailure($r, "dotnet list {$file} package --vulnerable");
            }
            foreach ($data['projects'] as $project) {
                foreach (($project['frameworks'] ?? []) as $fw) {
                    foreach (array_merge($fw['topLevelPackages'] ?? [], $fw['transitivePackages'] ?? []) as $pkg) {
                        foreach (($pkg['vulnerabilities'] ?? []) as $v) {
                            $sev          = self::severity($v['severity'] ?? null);
                            $counts[$sev] = ($counts[$sev] ?? 0) + 1;
                            $hits[]       = ($pkg['id'] ?? '?') . ' ' . ($pkg['resolvedVersion'] ?? '') . ' (' . ($v['severity'] ?? '?') . ')';
                        }
                    }
                }
            }
            $packages = array_merge($packages, self::vulnerablePackages($data));
        }
        return ['counts' => $counts, 'hits' => $hits, 'packages' => $packages];
    }

    /**
     * The vulnerable packages of a `dotnet list package --vulnerable --format json`
     * document, one per project and package id (the highest version resolved
     * across the project's target frameworks).
     *
     * @param array<mixed> $data
     * @return list<array{project: string, id: string, version: string, transitive: bool}>
     */
    public static function vulnerablePackages(array $data): array
    {
        $out = [];
        foreach (($data['projects'] ?? []) as $project) {
            $path = is_array($project) && is_string($project['path'] ?? null) ? $project['path'] : '';
            if ($path === '') {
                continue;
            }
            foreach (($project['frameworks'] ?? []) as $fw) {
                foreach (['topLevelPackages' => false, 'transitivePackages' => true] as $key => $transitive) {
                    foreach (($fw[$key] ?? []) as $pkg) {
                        $id      = is_string($pkg['id'] ?? null) ? $pkg['id'] : '';
                        $version = is_string($pkg['resolvedVersion'] ?? null) ? $pkg['resolvedVersion'] : '';
                        if ($id === '' || $version === '' || empty($pkg['vulnerabilities'])) {
                            continue;
                        }
                        $k = $path . "\0" . strtolower($id);
                        if (isset($out[$k])) {
                            // Direct in any framework makes it direct
                            $out[$k]['transitive'] = $out[$k]['transitive'] && $transitive;
                            $out[$k]['version']    = Version::max([$out[$k]['version'], $version]);
                            continue;
                        }
                        $out[$k] = ['project' => $path, 'id' => $id, 'version' => $version, 'transitive' => $transitive];
                    }
                }
            }
        }
        return array_values($out);
    }

    /**
     * The version to move a vulnerable package to: the newest release above
     * $current, on its major line unless $allowMajor. Null when there is none.
     *
     * @param list<string> $available
     */
    public static function upgradeTarget(string $current, array $available, bool $allowMajor): ?string
    {
        $line       = Version::majorLine($current);
        $candidates = array_values(array_filter($available, static fn (string $v): bool =>
            !Version::isPrerelease($v) && !str_contains($v, '-') && Version::compare($v, $current) > 0
            && ($allowMajor || Version::majorLine($v) === $line)));
        $best = Version::max($candidates);
        return $best === '' ? null : $best;
    }

    /**
     * Released versions of a package on the configured NuGet sources, from
     * `dotnet package search --exact-match` (no prereleases unless asked).
     *
     * @return list<string>
     */
    public static function searchVersions(string $stdout, string $id): array
    {
        $data = self::json($stdout);
        $out  = [];
        foreach ((is_array($data) ? ($data['searchResult'] ?? []) : []) as $source) {
            foreach (($source['packages'] ?? []) as $pkg) {
                if (is_string($pkg['version'] ?? null) && strcasecmp((string)($pkg['id'] ?? ''), $id) === 0) {
                    $out[] = $pkg['version'];
                }
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * Move one vulnerable package to its upgrade target with `dotnet add
     * package`, which rewrites the PackageReference (or the central
     * PackageVersion), adding one when the package was only transitive.
     *
     * @param array{project: string, id: string, version: string, transitive: bool} $pkg
     * @return array{0: bool, 1: string} whether the project changed, and a note
     */
    private function pin(Context $ctx, string $dir, array $pkg): array
    {
        $id = $pkg['id'];
        $r  = $this->run($ctx, $dir, ['dotnet', 'package', 'search', $id, '--exact-match', '--format', 'json'], null, self::ENV);
        $available = self::searchVersions($r->stdout, $id);
        if ($available === []) {
            return [false, "{$id} {$pkg['version']}: no versions found (dotnet package search " . ($r->ok() ? 'returned none' : $r->failureReason()) . ')'];
        }
        $target = self::upgradeTarget($pkg['version'], $available, $ctx->opt->allowMajor);
        if ($target === null) {
            $newer = self::upgradeTarget($pkg['version'], $available, true);
            return [false, $newer === null
                ? "{$id} {$pkg['version']}: no newer release to upgrade to"
                : "{$id} {$pkg['version']}: no newer release on its major line; {$newer} needs --allow-major"];
        }
        $project = $pkg['project'];
        $r = $this->run($ctx, $dir, ['dotnet', 'add', $project, 'package', $id, '--version', $target], null, self::ENV);
        $where = basename($project);
        if (!$r->ok()) {
            return [false, "dotnet add {$where} package {$id} --version {$target} " . $r->failureReason()];
        }
        return [true, $pkg['transitive']
            ? "pinned {$id} {$pkg['version']} -> {$target} in {$where} (was transitive)"
            : "upgraded {$id} {$pkg['version']} -> {$target} in {$where}"];
    }
}
