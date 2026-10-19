<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\AdvisoryLookup;
use Detain\DepSecPatcher\IssueParser;
use Detain\DepSecPatcher\SbtLocator;
use PHPUnit\Framework\TestCase;

/**
 * Issues whose own fix list is no use (empty, or only jackson-databind 3.x
 * for a 2.x dependency) completed from OSV, and sbt issues that name no
 * dependency file placed by the build.sbt declaring their library. The issue
 * bodies are real Mend issues from interserver/interserver-api-samples cut
 * down to the parts the parser reads; OSV's answers are canned.
 */
class AdvisoryLookupTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/dsp-osv-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->dir);
    }

    /**
     * @return array<string, mixed>
     */
    private static function issue(string $title, string $body, int $number = 7359): array
    {
        return ['number' => $number, 'title' => $title, 'body' => $body, 'url' => "https://github.com/o/r/issues/{$number}"];
    }

    /**
     * #7359: two 2.x lines in use, and Mend suggests only 3.1.4 (tools.jackson.core's).
     *
     * @return array<string, mixed>
     */
    private static function jacksonIssue(): array
    {
        $section = static fn (string $v, string $manifest): string => "<details><summary><b>jackson-databind-{$v}.jar</b></summary>\n"
            . "<p>Sample Path to Dependency File: {$manifest}</p>\n"
            . "<p>Path to vulnerable library: /home/wss-scanner/.m2/repository/com/fasterxml/jackson/core/jackson-databind/{$v}/jackson-databind-{$v}.jar</p>\n"
            . "Dependency Hierarchy:\n  - swagger-inflector-2.0.14.jar (Root Library)\n    - :x: **jackson-databind-{$v}.jar** (Vulnerable Library)\n</details>\n";
        return self::issue(
            'CVE-2026-54513 (High) detected in multiple libraries',
            "## CVE-2026-54513 - High Severity Vulnerability\n"
            . $section('2.19.0', '/OPENAPI-REST-API/swagger-client/inflector/pom.xml')
            . $section('2.12.7', '/OPENAPI-REST-API/openapi-client/scala-pekko/pom.xml')
            . "<details><summary>CVSS 3 Score Details (<b>8.1</b>)</summary></details>\n"
            . "<p>Fix Resolution: https://github.com/FasterXML/jackson-databind.git - jackson-databind-3.1.4</p>\n"
        );
    }

    /** OSV's answer for jackson-databind, as /v1/query gives it (trimmed). */
    private static function jacksonOsv(): string
    {
        $range = static fn (string $pkg, string $from, string $fixed): array => [
            'package' => ['ecosystem' => 'Maven', 'name' => $pkg],
            'ranges'  => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => $from], ['fixed' => $fixed]]]],
        ];
        return (string)json_encode(['vulns' => [
            ['id' => 'GHSA-rmj7-2vxq-3g9f', 'aliases' => ['CVE-2026-54513'], 'affected' => [
                $range('com.fasterxml.jackson.core:jackson-databind', '2.10.0', '2.18.8'),
                $range('com.fasterxml.jackson.core:jackson-databind', '2.19.0', '2.21.4'),
                // OSV lists the 3.x fix under the 2.x coordinates too
                $range('com.fasterxml.jackson.core:jackson-databind', '3.0.0', '3.1.4'),
                $range('tools.jackson.core:jackson-databind', '3.0.0', '3.1.4'),
            ]],
            ['id' => 'GHSA-other', 'aliases' => ['CVE-2026-1'], 'affected' => [
                $range('com.fasterxml.jackson.core:jackson-databind', '2.0.0', '2.9.9'),
            ]],
        ]]);
    }

    /**
     * @param list<string|null> $responses returned in turn, the last one repeated
     * @param list<string> $requests filled with each request body
     * @return callable(string, string): ?string
     */
    private static function http(array $responses, array &$requests): callable
    {
        return static function (string $url, string $body) use (&$responses, &$requests): ?string {
            $requests[] = $body;
            return count($responses) > 1 ? array_shift($responses) : $responses[0];
        };
    }

    public function testFixOnTheLineInUseReplacesAnotherMajorsFix(): void
    {
        $this->assertSame([], IssueParser::parseIssue(self::jacksonIssue()), 'without a lookup: skipped, as before');

        $requests = [];
        $osv      = new AdvisoryLookup('', self::http([self::jacksonOsv()], $requests));
        $records  = IssueParser::parseIssue(self::jacksonIssue(), $osv->asCallable());

        $this->assertCount(2, $records);
        foreach ($records as $r) {
            $this->assertSame('com.fasterxml.jackson.core:jackson-databind', $r['package']);
            $this->assertSame('CVE-2026-54513', $r['id']);
            // Per release line, and never the 3.x one
            $this->assertSame(['2.18.8', '2.21.4'], $r['fix_versions']);
            $this->assertSame('2.18.8', $r['fixed_version']);
            $this->assertSame('osv', $r['fix_source']);
            $this->assertArrayNotHasKey('state', $r);
        }
        $this->assertSame(['2.12.7'], $records[0]['installed']);
        $this->assertSame(['2.19.0'], $records[1]['installed']);
        $this->assertCount(1, $requests);
        $this->assertSame(['package' => ['ecosystem' => 'Maven', 'name' => 'com.fasterxml.jackson.core:jackson-databind']], json_decode($requests[0], true));
    }

    public function testNoFixOnTheLineInUseLeavesThatManifestOut(): void
    {
        $requests = [];
        $only3    = (string)json_encode(['vulns' => [['id' => 'CVE-2026-54513', 'affected' => [[
            'package' => ['ecosystem' => 'Maven', 'name' => 'com.fasterxml.jackson.core:jackson-databind'],
            'ranges'  => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '3.0.0'], ['fixed' => '3.1.4']]]],
        ]]]]]);
        $osv = new AdvisoryLookup('', self::http([$only3], $requests));
        $this->assertSame([], IssueParser::parseIssue(self::jacksonIssue(), $osv->asCallable()));
    }

    public function testIssueWithoutFixResolutionGetsOsvsFix(): void
    {
        // #647: Mend lists no fix at all
        $issue = self::issue(
            'CVE-2024-38828 (Medium) detected in spring-webmvc-5.1.17.RELEASE.jar',
            "<details><summary>Vulnerable Library - <b>spring-webmvc-5.1.17.RELEASE.jar</b></summary>\n"
            . "<p>Path to dependency file: /OPENAPI-REST-API/swagger-client/spring-mvc/pom.xml</p>\n"
            . "<p>Path to vulnerable library: /home/wss-scanner/.m2/repository/org/springframework/spring-webmvc/5.1.17.RELEASE/spring-webmvc-5.1.17.RELEASE.jar</p>\n"
            . '</details>',
            647
        );
        $answer = (string)json_encode(['vulns' => [['id' => 'GHSA-2rmj-mq67-h97g', 'aliases' => ['CVE-2024-38828'], 'affected' => [[
            'package' => ['ecosystem' => 'Maven', 'name' => 'org.springframework:spring-webmvc'],
            'ranges'  => [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '5.3.42']]]],
        ]]]]]);
        $requests = [];
        $records  = IssueParser::parseIssue($issue, (new AdvisoryLookup('', self::http([$answer], $requests)))->asCallable());
        $this->assertCount(1, $records);
        $this->assertSame('org.springframework:spring-webmvc', $records[0]['package']);
        $this->assertSame('OPENAPI-REST-API/swagger-client/spring-mvc/pom.xml', $records[0]['manifest']);
        $this->assertSame('5.3.42', $records[0]['fixed_version']);
        $this->assertSame(['5.1.17.RELEASE'], $records[0]['installed']);
    }

    public function testNetworkFailureDegradesToNoRecordsAndStopsAsking(): void
    {
        $requests = [];
        $osv      = new AdvisoryLookup('', self::http([null], $requests));
        $this->assertSame([], IssueParser::parseIssue(self::jacksonIssue(), $osv->asCallable()));
        $this->assertNull($osv->fixedVersions('Maven', 'a:b', 'CVE-1'));
        $this->assertNull($osv->fixedVersions('Maven', 'c:d', 'CVE-1'));
        $this->assertNull($osv->fixedVersions('Maven', 'e:f', 'CVE-1'));
        $this->assertCount(3, $requests, 'a package that failed is not asked again, and three failures end the asking');

        $requests = [];
        $osv      = new AdvisoryLookup('', self::http(['<html>rate limited</html>'], $requests));
        $this->assertNull($osv->fixedVersions('Maven', 'a:b', 'CVE-1'), 'a body that is not JSON is a failure');
    }

    public function testAnswersAreCachedPerPackageAcrossRuns(): void
    {
        $file     = $this->dir . '/osv-cache.json';
        $requests = [];
        $osv      = new AdvisoryLookup($file, self::http([self::jacksonOsv()], $requests), null, 1000);
        $this->assertSame(['2.18.8', '2.21.4', '3.1.4'], $osv->fixedVersions('Maven', 'com.fasterxml.jackson.core:jackson-databind', 'CVE-2026-54513'));
        $this->assertSame(['2.9.9'], $osv->fixedVersions('Maven', 'com.fasterxml.jackson.core:jackson-databind', 'cve-2026-1'), 'by alias, any case');
        $this->assertSame([], $osv->fixedVersions('Maven', 'com.fasterxml.jackson.core:jackson-databind', 'CVE-2099-1'), 'unknown to OSV');
        $this->assertCount(1, $requests);
        $this->assertFileExists($file);

        // The next run reads the file, until the answer is a day old
        $later = new AdvisoryLookup($file, self::http([null], $requests), null, 1000 + 3600);
        $this->assertSame(['2.18.8', '2.21.4', '3.1.4'], $later->fixedVersions('Maven', 'com.fasterxml.jackson.core:jackson-databind', 'GHSA-RMJ7-2VXQ-3G9F'));
        $this->assertCount(1, $requests);
        $stale = new AdvisoryLookup($file, self::http([(string)json_encode(['vulns' => []])], $requests), null, 1000 + 86400);
        $this->assertSame([], $stale->fixedVersions('Maven', 'com.fasterxml.jackson.core:jackson-databind', 'CVE-2026-54513'));
        $this->assertCount(2, $requests);
    }

    public function testPagesAreFollowed(): void
    {
        $vuln = static fn (string $id, string $fixed): array => ['id' => $id, 'affected' => [[
            'package' => ['ecosystem' => 'npm', 'name' => 'axios'],
            'ranges'  => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => $fixed]]]],
        ]]];
        $requests = [];
        $osv      = new AdvisoryLookup('', self::http([
            (string)json_encode(['vulns' => [$vuln('CVE-1', '1.0.0')], 'next_page_token' => 'p2']),
            (string)json_encode(['vulns' => [$vuln('CVE-2', '1.6.0')]]),
        ], $requests));
        $this->assertSame(['1.6.0'], $osv->fixedVersions('npm', 'axios', 'CVE-2'));
        $this->assertSame('p2', json_decode($requests[1], true)['page_token']);
    }

    public function testOsvEcosystems(): void
    {
        $this->assertSame('Maven', AdvisoryLookup::osvEcosystem('a/pom.xml'));
        $this->assertSame('Maven', AdvisoryLookup::osvEcosystem('a/build.gradle.kts'));
        $this->assertSame('Maven', AdvisoryLookup::osvEcosystem('a/build.sbt'));
        $this->assertSame('npm', AdvisoryLookup::osvEcosystem('package.json'));
        $this->assertSame('PyPI', AdvisoryLookup::osvEcosystem('requirements.txt'));
        $this->assertSame('', AdvisoryLookup::osvEcosystem('README.md'));
    }

    /**
     * #7346: an sbt scan names only the Ivy cache, never the build file.
     *
     * @return array<string, mixed>
     */
    private static function sbtIssue(): array
    {
        return self::issue(
            'CVE-2026-54556 (High) detected in http4s-ember-core_3-0.23.26.jar',
            "<details><summary>Vulnerable Library - <b>http4s-ember-core_3-0.23.26.jar</b></summary>\n"
            . "<p>Path to vulnerable library: /home/wss-scanner/.ivy2/cache/org.http4s/http4s-ember-core_3/jars/http4s-ember-core_3-0.23.26.jar</p>\n"
            . "Dependency Hierarchy:\n  - http4s-ember-client_3-0.23.26.jar (Root Library)\n    - :x: **http4s-ember-core_3-0.23.26.jar** (Vulnerable Library)\n"
            . "</details>\n<p>Fix Resolution: https://github.com/http4s/http4s.git - v0.23.35</p>\n",
            7346
        );
    }

    public function testSbtIssueIsPlacedInTheBuildDeclaringItsRootLibrary(): void
    {
        $builds = [
            'scala-http4s/build.sbt' => "scalaVersion := \"3.6.4\"\nval Http4sVersion  = \"0.23.26\"\nlibraryDependencies ++= Seq(\n"
                . "  \"org.http4s\"   %% \"http4s-ember-client\" % Http4sVersion,\n)\n",
            // Same library for another Scala version: not the one Mend found
            'scala-old/build.sbt' => "scalaVersion := \"2.13.12\"\nlibraryDependencies += \"org.http4s\" %% \"http4s-ember-client\" % \"0.23.26\"\n",
            // Another version
            'scala-new/build.sbt' => "scalaVersion := \"3.3.0\"\nlibraryDependencies += \"org.http4s\" %% \"http4s-ember-client\" % \"0.23.30\"\n",
            'other/pom.xml' => '',
        ];
        $locate = new SbtLocator(array_keys($builds), static fn (string $f): ?string => $builds[$f] ?? null);

        $this->assertSame([], IssueParser::parseIssue(self::sbtIssue()), 'without a locator: no dependency file, no records');
        $records = IssueParser::parseIssue(self::sbtIssue(), null, $locate);
        $this->assertCount(1, $records);
        $this->assertSame('scala-http4s/build.sbt', $records[0]['manifest']);
        $this->assertSame('org.http4s:http4s-ember-core_3', $records[0]['package']);
        $this->assertSame('0.23.35', $records[0]['fixed_version']);
    }

    public function testSbtDeclarations(): void
    {
        $sbt = "scalaVersion  := \"2.11.12\"\nval http4sVersion = \"0.15.12a\"\n"
            . "libraryDependencies ++= Seq(\n  \"joda-time\" % \"joda-time\" % \"2.2\",\n"
            . "  \"org.http4s\" %% \"http4s-server-metrics\" % http4sVersion,\n  // \"org.x\" %% \"commented\" % \"1.0\",\n)\n";
        $this->assertTrue(SbtLocator::declares($sbt, 'http4s-server-metrics_2.11', '0.15.12a'));
        $this->assertTrue(SbtLocator::declares($sbt, 'joda-time', '2.2'));
        $this->assertFalse(SbtLocator::declares($sbt, 'http4s-server-metrics_2.12', '0.15.12a'), 'other Scala version');
        $this->assertFalse(SbtLocator::declares($sbt, 'http4s-server-metrics_2.11', '0.18.0'), 'other version');
        $this->assertFalse(SbtLocator::declares($sbt, 'commented_2.11', '1.0'));
        // No scalaVersion and a version from elsewhere: the artifact decides
        $this->assertTrue(SbtLocator::declares('libraryDependencies += "a" %% "b" % V.b', 'b_3', '1.0'));
    }
}
