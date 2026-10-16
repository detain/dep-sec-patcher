<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * .NET: dotnet-outdated for updates, `dotnet list package --vulnerable` for
 * the audit. Update mode previously never audited at all (it only listed
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

        $counts = [];
        $hits   = [];
        foreach ($files as $file) {
            $r = $this->run($ctx, $dir, ['dotnet', 'restore', $file], null, self::ENV);
            if (!$r->ok()) {
                $t = TargetResult::fromFailure($r, "dotnet restore {$file}");
                $t->notes = $notes;
                return $t;
            }
            $r    = $this->run($ctx, $dir, ['dotnet', 'list', $file, 'package', '--vulnerable', '--include-transitive', '--format', 'json'], null, self::ENV);
            $data = self::json($r->stdout);
            if (!is_array($data) || !isset($data['projects'])) {
                $t = TargetResult::fromFailure($r, "dotnet list {$file} package --vulnerable");
                $t->notes = $notes;
                return $t;
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
        }
        $t = TargetResult::fromSeverities($counts, 'dotnet list package --vulnerable');
        $t->notes = array_merge($notes, array_slice(array_values(array_unique($hits)), 0, 10));
        return $t;
    }
}
