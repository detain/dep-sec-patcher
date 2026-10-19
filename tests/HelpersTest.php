<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\GoAuditor;
use Detain\DepSecPatcher\Auditor\MavenAuditor;
use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\JsonFile;
use Detain\DepSecPatcher\ManifestPaths;
use Detain\DepSecPatcher\RecordNormalizer;
use Detain\DepSecPatcher\Scanner\NetworkScanner;
use Detain\DepSecPatcher\TargetResult;
use Detain\DepSecPatcher\TokenHarvester;
use PHPUnit\Framework\TestCase;

/**
 * Small pure pieces: manifest naming, JSON formatting, token harvesting,
 * GitHub record normalisation, result classification, report parsers.
 */
class HelpersTest extends TestCase
{
    public function testCommandOutputIsShownAsPlainText(): void
    {
        $out = "\e[31m-- [E008] Not Found Error\e[0m\n\e]0;owned\a\e]8;;https://x\e\\link\e]8;;\e\\\r\ntab\there\e[2K\e[1A\x07\n";
        $r   = new CommandResult('sbt', 1, false, '', $out, 0.0);
        $this->assertSame(['-- [E008] Not Found Error', 'link', "tab\there"], $r->tail());
    }

    public function testEcosystemFor(): void
    {
        $this->assertSame('npm', ManifestPaths::ecosystemFor('a/b/package-lock.json'));
        $this->assertSame('pip', ManifestPaths::ecosystemFor('dev-requirements.txt'));
        $this->assertSame('gradle', ManifestPaths::ecosystemFor('build.gradle.kts'));
        $this->assertSame('nuget', ManifestPaths::ecosystemFor('src/X.csproj'));
        $this->assertSame('unknown', ManifestPaths::ecosystemFor(''));
    }

    public function testSourceManifestFor(): void
    {
        $this->assertSame('a/package.json', ManifestPaths::sourceManifestFor('a/yarn.lock'));
        $this->assertSame('composer.json', ManifestPaths::sourceManifestFor('composer.lock'));
        $this->assertSame('a/pom.xml', ManifestPaths::sourceManifestFor('a/pom.xml'));
        $lister = static fn (string $dir): array => $dir === 'n' ? ['packages.lock.json', 'Z.csproj', 'A.csproj'] : [];
        $this->assertSame('n/A.csproj', ManifestPaths::sourceManifestFor('n/packages.lock.json', $lister));
        $this->assertSame('m/packages.lock.json', ManifestPaths::sourceManifestFor('m/packages.lock.json', $lister));
    }

    public function testJsonIndentDetectionAndEncoding(): void
    {
        $this->assertSame('    ', JsonFile::detectIndent("{\n    \"a\": 1\n}"));
        $this->assertSame("\t", JsonFile::detectIndent("{\n\t\"a\": 1\n}"));
        $this->assertSame('  ', JsonFile::detectIndent('{"a":1}'));
        $this->assertSame("{\n  \"a\": {\n    \"b\": \"c/d é\"\n  },\n  \"e\": []\n}\n", JsonFile::encode(['a' => ['b' => 'c/d é'], 'e' => []]));
        $this->assertSame("{\n\t\"a\": 1.0\n}\n", JsonFile::encode(['a' => 1.0], "\t"));
    }

    public function testTokenHarvester(): void
    {
        $rc = "# GH_TOKEN=commented\nexport GH_TOKEN=\"abc123\"\nexport NVD_API_KEY='k-1'\nGITHUB_TOKEN=late \n";
        $this->assertSame('late', TokenHarvester::fromContent($rc, ['GH_TOKEN', 'GITHUB_TOKEN']), 'last assignment wins');
        $this->assertSame('k-1', TokenHarvester::fromContent($rc, ['NVD_API_KEY']));
        $this->assertNull(TokenHarvester::fromContent($rc, ['NOPE']));
    }

    public function testDependabotAlertNormalisation(): void
    {
        $alerts = [[
            'number' => 324, 'state' => 'open', 'html_url' => 'https://x/324',
            'dependency' => ['package' => ['ecosystem' => 'npm', 'name' => 'qs'], 'manifest_path' => 'a/package-lock.json', 'scope' => 'runtime'],
            'security_advisory' => ['ghsa_id' => 'GHSA-1', 'cve_id' => null, 'severity' => 'medium', 'cvss' => ['score' => 5.3], 'summary' => 's'],
            'security_vulnerability' => ['vulnerable_version_range' => '< 6.15.2', 'first_patched_version' => ['identifier' => '6.15.2']],
        ], ['number' => 1, 'state' => 'fixed']];
        $records = RecordNormalizer::fromDependabotAlerts($alerts);
        $this->assertCount(1, $records, 'non-open alerts are dropped');
        $r = $records[0];
        $this->assertSame('npm|qs|a/package-lock.json|GHSA-1', $r['key']);
        $this->assertSame('', $r['cve']);
        $this->assertSame(['6.15.2'], $r['fix_versions']);
        $this->assertTrue($r['direct']);
    }

    public function testEcosystemInference(): void
    {
        $this->assertSame('pip', RecordNormalizer::withEcosystem(['ecosystem' => '', 'manifest' => 'x/requirements.txt'])['ecosystem']);
        $this->assertSame('maven', RecordNormalizer::withEcosystem(['ecosystem' => 'Maven', 'manifest' => 'x/build.gradle'])['ecosystem']);
    }

    public function testSeverityClassification(): void
    {
        $this->assertSame(TargetResult::PASS, TargetResult::fromSeverities([], 'x')->status);
        $this->assertSame(TargetResult::WARN, TargetResult::fromSeverities(['moderate' => 2, 'low' => 1], 'x')->status);
        $t = TargetResult::fromSeverities(['high' => 1, 'moderate' => 2], 'npm audit');
        $this->assertSame(TargetResult::FAIL, $t->status);
        $this->assertSame(3, $t->vulns);
        $this->assertSame('npm audit: 3 vulnerabilities (1 high, 2 moderate)', $t->detail);
        $this->assertSame(TargetResult::FAIL, TargetResult::fromSeverities(['unknown' => 1], 'x')->status, 'unrated counts as serious');
    }

    public function testDependencyCheckReport(): void
    {
        $report = json_encode(['dependencies' => [
            ['fileName' => 'gson-2.8.1.jar', 'vulnerabilities' => [['cvssv3' => ['baseScore' => 7.5], 'cvssv2' => ['score' => 5.0]]]],
            ['fileName' => 'okhttp-2.7.5.jar', 'vulnerabilities' => [['cvssv3' => ['baseScore' => 5.5]]]],
            ['fileName' => 'clean.jar'],
        ]]);
        $t = MavenAuditor::fromReport((string)$report, 7.0);
        $this->assertSame(TargetResult::FAIL, $t->status);
        $this->assertSame(2, $t->vulns);
        $this->assertStringContainsString('1 with CVSS >= 7', $t->detail);
        $this->assertSame(TargetResult::WARN, MavenAuditor::fromReport((string)$report, 9.0)->status);
        $this->assertSame(TargetResult::PASS, MavenAuditor::fromReport('{"dependencies":[]}', 7.0)->status);
        $this->assertSame(TargetResult::ERROR, MavenAuditor::fromReport('nope', 7.0)->status);
    }

    public function testGovulncheckFindingsSplitStdlib(): void
    {
        $out = "Vulnerability #1: GO-2025-1\n    desc\n  Module: golang.org/x/net\n    Found in: golang.org/x/net@v0.47.0\n    Fixed in: golang.org/x/net@v0.55.0\n\n"
            . "Vulnerability #2: GO-2025-2\n    desc\n  Standard library\n    Found in: stdlib@go1.23.5\n    Fixed in: stdlib@go1.23.7\n";
        [$modules, $stdlib] = GoAuditor::parseFindings($out);
        $this->assertSame(['GO-2025-1 golang.org/x/net@v0.47.0 -> golang.org/x/net@v0.55.0'], $modules);
        $this->assertSame(['GO-2025-2 stdlib@go1.23.5'], $stdlib);
    }

    public function testNetworkScannerIgnoresPlaceholders(): void
    {
        $files = [
            'docs/Api.md'          => "password = 'password_example'\napi_key = \"YOUR_API_KEY\"\n",
            'src/config.py'        => "password = 'uD1c!@cgD'\n",
            'conf/app.yaml'        => "url: http://example.com/x\nschema: http://json-schema.org/draft-07/schema\nhost: http://localhost:8080\n",
            'conf/other.yaml'      => "url: http://api.vendor.test/v2\ntls: TLSv1.0\n",
            'test/fixture.json'    => "{\"u\": \"http://api.vendor.test\"}",
            'keys.env'             => "AWS=AKIAABCDEFGHIJKLMNOP\n",
            'package-lock.json'    => "password = 'realpass123'\n",
        ];
        $found = NetworkScanner::scan(array_keys($files), static fn ($f) => $files[$f]);
        $this->assertSame(['conf/other.yaml'], $found['http'], 'allowed hosts, examples and tests are skipped');
        $this->assertSame(['password' => ['src/config.py'], 'aws key' => ['keys.env']], $found['credentials']);
        $this->assertSame(['conf/other.yaml'], $found['tls']);
    }
}
