<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\DotnetAuditor;
use Detain\DepSecPatcher\Console;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;
use PHPUnit\Framework\TestCase;

/**
 * Update mode moves packages `dotnet list package --vulnerable` reports to a
 * newer release, pinning transitive ones with a direct reference. The
 * end-to-end cases run against a stand-in `dotnet` script, never NuGet.
 */
class DotnetAuditorTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testVulnerablePackagesOnePerProjectAndId(): void
    {
        $data = ['projects' => [
            ['path' => '/r/a.csproj', 'frameworks' => [
                ['framework' => 'net6.0', 'transitivePackages' => [
                    ['id' => 'Newtonsoft.Json', 'resolvedVersion' => '11.0.2', 'vulnerabilities' => [['severity' => 'High']]],
                    ['id' => 'Safe.Pkg', 'resolvedVersion' => '1.0.0'],
                ]],
                ['framework' => 'net8.0', 'topLevelPackages' => [
                    ['id' => 'newtonsoft.json', 'resolvedVersion' => '12.0.1', 'vulnerabilities' => [['severity' => 'High']]],
                ]],
            ]],
            ['path' => '/r/b.csproj', 'frameworks' => [['transitivePackages' => [
                ['id' => 'System.Text.Json', 'resolvedVersion' => '8.0.0', 'vulnerabilities' => [['severity' => 'High']]],
            ]]]],
        ]];
        $this->assertSame([
            ['project' => '/r/a.csproj', 'id' => 'Newtonsoft.Json', 'version' => '12.0.1', 'transitive' => false],
            ['project' => '/r/b.csproj', 'id' => 'System.Text.Json', 'version' => '8.0.0', 'transitive' => true],
        ], DotnetAuditor::vulnerablePackages($data));
    }

    public function testUpgradeTargetRespectsMajorLineAndSkipsPrereleases(): void
    {
        $versions = ['11.0.1', '11.0.2', '12.0.3', '13.0.1', '13.0.4', '14.0.0-beta1'];
        $this->assertNull(DotnetAuditor::upgradeTarget('11.0.2', $versions, false), 'nothing newer on 11.x');
        $this->assertSame('13.0.4', DotnetAuditor::upgradeTarget('11.0.2', $versions, true));
        $this->assertSame('11.0.2', DotnetAuditor::upgradeTarget('11.0.1', $versions, false));
        $this->assertNull(DotnetAuditor::upgradeTarget('13.0.4', $versions, true), 'a prerelease is not an upgrade');
    }

    public function testSearchVersionsKeepsOnlyTheExactId(): void
    {
        $out = '{"version":2,"problems":[],"searchResult":[{"sourceName":"nuget","packages":['
            . '{"id":"Newtonsoft.Json","version":"13.0.1"},{"id":"Newtonsoft.Json.Bson","version":"1.0.2"}]},'
            . '{"sourceName":"mirror","packages":[{"id":"newtonsoft.json","version":"13.0.1"}]}]}';
        $this->assertSame(['13.0.1'], DotnetAuditor::searchVersions($out, 'Newtonsoft.Json'));
        $this->assertSame([], DotnetAuditor::searchVersions('error', 'x'));
    }

    public function testUpdateModePinsATransitivePackageWithAllowMajor(): void
    {
        [$root, $log] = $this->fakeProject();
        $t = $this->audit($root, ['--update', '--allow-major']);
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $this->assertContains('pinned Newtonsoft.Json 11.0.2 -> 13.0.4 in app.csproj (was transitive)', $t->notes);
        $this->assertStringContainsString("add {$root}/app.csproj package Newtonsoft.Json --version 13.0.4", (string)file_get_contents($log));
    }

    public function testUpdateModeWithoutAllowMajorNamesTheMajorUpgrade(): void
    {
        [$root, $log] = $this->fakeProject();
        $t = $this->audit($root, ['--update']);
        $this->assertSame(TargetResult::FAIL, $t->status);
        $this->assertContains('Newtonsoft.Json 11.0.2: no newer release on its major line; 13.0.4 needs --allow-major', $t->notes);
        $this->assertStringNotContainsString(' add ', ' ' . (string)file_get_contents($log));
    }

    public function testCheckModeChangesNothing(): void
    {
        [$root, $log] = $this->fakeProject();
        $t = $this->audit($root, ['--check']);
        $this->assertSame(TargetResult::FAIL, $t->status);
        $calls = (string)file_get_contents($log);
        $this->assertStringNotContainsString('package search', $calls);
        $this->assertStringNotContainsString(' add ', ' ' . $calls);
    }

    /**
     * A project directory and a stand-in `dotnet` first on PATH: Newtonsoft.Json
     * 11.0.2 is vulnerable until `dotnet add` has run.
     *
     * @return array{0: string, 1: string} project root, call log
     */
    private function fakeProject(): array
    {
        $root = $this->scratchDir('dotnet');
        $bin  = $this->scratchDir('dotnet-bin');
        file_put_contents($root . '/app.csproj', "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n");
        $log = $root . '/calls.log';
        $vulnerable = json_encode(['version' => 1, 'projects' => [['path' => $root . '/app.csproj', 'frameworks' => [
            ['framework' => 'net8.0', 'transitivePackages' => [
                ['id' => 'Newtonsoft.Json', 'resolvedVersion' => '11.0.2', 'vulnerabilities' => [['severity' => 'High', 'advisoryurl' => 'x']]],
            ]],
        ]]]]);
        $clean  = json_encode(['version' => 1, 'projects' => [['path' => $root . '/app.csproj', 'frameworks' => []]]]);
        $search = json_encode(['version' => 2, 'problems' => [], 'searchResult' => [['sourceName' => 'nuget', 'packages' => array_map(
            static fn (string $v): array => ['id' => 'Newtonsoft.Json', 'version' => $v],
            ['11.0.1', '11.0.2', '12.0.3', '13.0.1', '13.0.4']
        )]]]);
        $script = "#!/bin/sh\n"
            . 'echo "$*" >> ' . escapeshellarg($log) . "\n"
            . "case \"\$1 \$2\" in\n"
            . "  'restore '*) exit 0 ;;\n"
            . "  'package search') echo " . escapeshellarg((string)$search) . "; exit 0 ;;\n"
            . "  'add '*) touch " . escapeshellarg($root . '/.pinned') . "; exit 0 ;;\n"
            . "  'list '*) if [ -e " . escapeshellarg($root . '/.pinned') . " ]; then echo " . escapeshellarg((string)$clean)
            . '; else echo ' . escapeshellarg((string)$vulnerable) . "; fi; exit 0 ;;\n"
            . "esac\nexit 2\n";
        file_put_contents($bin . '/dotnet', $script);
        chmod($bin . '/dotnet', 0755);
        // No dotnet-outdated on this PATH: the pin step must stand on its own
        $this->setEnv('PATH', $bin . ':/usr/bin:/bin');
        return [$root, $log];
    }

    /**
     * @param list<string> $args
     */
    private function audit(string $root, array $args): TargetResult
    {
        $out = fopen('php://memory', 'w+');
        $this->assertIsResource($out);
        $console = new Console(false, '[t]', $out);
        $ctx = new Context(Options::parse($args, []), $console, new ProcessRunner($console, 30), $root, $root . '/reports', new ManifestIndex($root, ''));
        return (new DotnetAuditor())->audit($ctx, '');
    }
}
