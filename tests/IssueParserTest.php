<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\IssueParser;
use PHPUnit\Framework\TestCase;

/**
 * Mend Bolt issue bodies -> remediation records. The parser began as a port of
 * the original shell script's jq program, and on a public repository's 6530
 * open issues the two produced identical output (14828 records); it now
 * departs from it where a bare fix list named the wrong package. These cases
 * pin each body shape.
 */
class IssueParserTest extends TestCase
{
    /**
     * @return array<string, mixed>
     */
    private static function issue(string $title, string $body, int $number = 42): array
    {
        return ['number' => $number, 'title' => $title, 'body' => $body, 'url' => "https://github.com/o/r/issues/{$number}"];
    }

    public function testNamedFixResolution(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2025-7783 (Critical) detected in form-data-2.5.1.tgz',
            '<p>Path to dependency file: /OPENAPI-REST-API/client/js/package.json</p>'
            . '<p>CVSS 3 Score Details (<b>9.4</b>)</p>'
            . '<p>Fix Resolution (form-data): 2.5.4</p>'
            . '<p>Direct dependency fix Resolution (superagent): 7.0.0</p>'
        ));
        $this->assertCount(2, $records);
        // Direct-dependency fixes come first, as in the jq program
        $this->assertSame('superagent', $records[0]['package']);
        $this->assertTrue($records[0]['direct']);
        $this->assertSame('form-data', $records[1]['package']);
        $this->assertSame('2.5.4', $records[1]['fixed_version']);
        $this->assertFalse($records[1]['direct']);

        $r = $records[1];
        $this->assertSame('OPENAPI-REST-API/client/js/package.json|form-data|CVE-2025-7783', $r['key']);
        $this->assertSame('OPENAPI-REST-API/client/js/package.json', $r['manifest'], 'leading slash stripped');
        $this->assertSame('critical', $r['severity']);
        $this->assertSame(9.4, $r['cvss']);
        $this->assertSame([42], $r['refs']);
        $this->assertSame(['2.5.4'], $r['fix_versions']);
        $this->assertSame('', $r['ecosystem'], 'inferred later from the manifest');
    }

    public function testBareListOfCoordinatesAndDashedEntries(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-1 (High) detected in multiple libraries',
            "<p>Path to dependency file: /a/go.mod</p>\n"
            . '<p>Fix Resolution: io.netty:netty-all:4.1.42.Final, golang.org/x/net - v0.55.0,'
            . 'https://github.com/FasterXML/jackson-databind.git - jackson-databind-2.18.8</p>'
        ));
        $pairs = array_map(static fn ($r) => [$r['package'], $r['fixed_version']], $records);
        $this->assertSame([
            ['io.netty:netty-all', '4.1.42.Final'],
            ['golang.org/x/net', '0.55.0'],
            ['jackson-databind', '2.18.8'],
        ], $pairs);
    }

    public function testBareVersionIsPairedWithEveryAffectedLibrary(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-2 (Medium) detected in js-yaml-3.14.2.tgz',
            '<p>Path to dependency file: /x/package.json</p><p>Vulnerable Library - <b>js-yaml-3.13.0.tgz</b></p>'
            . '<p>Fix Resolution: 3.15.0</p>'
        ));
        $this->assertCount(1, $records);
        $this->assertSame('js-yaml', $records[0]['package']);
        $this->assertSame('3.15.0', $records[0]['fixed_version']);
    }

    /**
     * @param list<array<string, mixed>> $records
     * @return list<array{0: mixed, 1: mixed}>
     */
    private static function pairs(array $records): array
    {
        return array_map(static fn ($r) => [$r['package'], $r['fixed_version']], $records);
    }

    public function testARepositoryUrlGivesWayToThePackageThePathNames(): void
    {
        // The tarball name drops the scope; the unscoped json-schema-ref-parser
        // is another package, which never reached 15.x
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-15195 (Medium) detected in json-schema-ref-parser-9.0.9.tgz',
            "<p>Library home page: <a href=\"https://registry.npmjs.org/@\u{2060}apidevtools/json-schema-ref-parser/-/json-schema-ref-parser-9.0.9.tgz\">x</a></p>\n"
            . "<p>Sample Path to Dependency File: /srv/package.json</p>\n"
            . "<p>Path to vulnerable library: /srv/node_modules/@\u{2060}apidevtools/json-schema-ref-parser/package.json</p>\n"
            . "<p>Fix Resolution: https://github.com/APIDevTools/json-schema-ref-parser.git - v15.3.6,@\u{2060}apidevtools/json-schema-ref-parser - 15.3.6</p>"
        ));
        $this->assertSame([['@apidevtools/json-schema-ref-parser', '15.3.6']], self::pairs($records));
    }

    public function testABareListIsNarrowedToTheLibrariesTheIssueReports(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-12816 (High) detected in bcprov-jdk18on-1.80.jar',
            "<p>Path to dependency file: /kotlin/build.gradle</p>\n"
            . "<p>Path to vulnerable library: /tmp/cache/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on/1.80/e22100b4/bcprov-jdk18on-1.80.jar</p>\n"
            . '<p>Fix Resolution: org.bouncycastle:bcprov-lts8on:2.73.12,org.bouncycastle:bcprov-jdk15to18:1.85,'
            . 'org.bouncycastle:bcprov-jdk18on:1.85,https://github.com/bcgit/bc-java.git - r1rv85</p>'
        ));
        $this->assertSame([['org.bouncycastle:bcprov-jdk18on', '1.85']], self::pairs($records), 'alternatives and the repository tag dropped');

        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-83557 (Medium) detected in multiple libraries',
            "<p>Path to dependency file: /pom.xml</p>\n"
            . "<p>Path to vulnerable library: /home/u/.m2/repository/com/fasterxml/jackson/core/jackson-databind/2.12.4/jackson-databind-2.12.4.jar,"
            . "/home/u/.ivy2/cache/com.fasterxml.jackson.core/jackson-databind/bundles/jackson-databind-2.12.7.jar</p>\n"
            . '<p>Fix Resolution: tools.jackson.core:jackson-databind:3.2.2,com.fasterxml.jackson.core:jackson-databind:2.18.10</p>'
        ));
        $this->assertSame([['com.fasterxml.jackson.core:jackson-databind', '2.18.10']], self::pairs($records), 'same artifact, other group');
    }

    public function testARepositoryTagIsTheVersionOfTheLibrariesTheIssueReports(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-48043 (Medium) detected in netty-codec-http2-4.1.76.Final.jar, netty-codec-http2-4.1.67.Final.jar',
            "<p>Path to dependency file: /pom.xml</p>\n"
            . "<p>Path to vulnerable library: /home/u/.m2/repository/io/netty/netty-codec-http2/4.1.76.Final/netty-codec-http2-4.1.76.Final.jar</p>\n"
            . "<p>Fix Resolution: https://github.com/netty/netty.git - netty-4.1.135.Final</p>"
        ));
        $this->assertSame([['io.netty:netty-codec-http2', '4.1.135.Final']], self::pairs($records));

        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-49356 (Low) detected in core-7.29.0.tgz',
            "<p>Path to dependency file: /js/package.json</p>\n"
            . "<p>Path to vulnerable library: /js/node_modules/@babel/core/package.json,/ts/node_modules/@babel/core/package.json</p>\n"
            . "<p>Fix Resolution: https://github.com/babel/babel.git - 7.29.6,https://github.com/babel/babel.git - 8.0.0-rc.6</p>"
        ));
        $this->assertSame([['@babel/core', '7.29.6'], ['@babel/core', '8.0.0-rc.6']], self::pairs($records), 'not the npm packages "babel" or "core"');

        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-84304 (High) detected in google.golang.org/grpc-v1.75.1',
            "<p>Path to dependency file: /tf/go.mod</p>\n"
            . "<p>Path to vulnerable library: /home/u/go/pkg/mod/cache/download/google.golang.org/grpc/@v/v1.75.1.mod,"
            . "/home/u/go/pkg/mod/cache/download/github.com/!azure/go-autorest/@v/v14.2.0.mod</p>\n"
            . "<p>Fix Resolution: https://github.com/grpc/grpc-go.git - v1.83.1</p>"
        ));
        $this->assertSame([
            ['github.com/Azure/go-autorest', '1.83.1'],
            ['google.golang.org/grpc', '1.83.1'],
        ], self::pairs($records), 'every library reported when the repository is named after none');
    }

    public function testARepositoryTagOnAnotherMajorLineThanTheOneInUseIsNotTrusted(): void
    {
        // jackson-databind's 3.x tags are tools.jackson.core releases; no
        // com.fasterxml.jackson.core:jackson-databind 3.1.4 exists
        $section = static fn (string $v): string => "<details><summary><b>jackson-databind-{$v}.jar</b></summary>\n"
            . "<p>Sample Path to Dependency File: /java/pom.xml</p>\n"
            . "<p>Path to vulnerable library: /home/u/.m2/repository/com/fasterxml/jackson/core/jackson-databind/{$v}/jackson-databind-{$v}.jar</p>\n</details>\n";
        $body = $section('2.21.0') . $section('2.21.2');
        $this->assertSame([], IssueParser::parseIssue(self::issue(
            'CVE-2026-54518 (Medium) detected in jackson-databind-2.21.0.jar, jackson-databind-2.21.2.jar',
            $body . '<p>Fix Resolution: https://github.com/FasterXML/jackson-databind.git - jackson-databind-3.1.4</p>'
        )));
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-54519 (Medium) detected in jackson-databind-2.21.0.jar, jackson-databind-2.21.2.jar',
            $body . '<p>Fix Resolution: https://github.com/FasterXML/jackson-databind.git - jackson-databind-2.21.3</p>'
        ));
        $this->assertSame([['com.fasterxml.jackson.core:jackson-databind', '2.21.3']], self::pairs($records));
        $this->assertSame(['2.21.0', '2.21.2'], $records[0]['installed'], 'what the issue found in use');

        // A sister artifact listed at the tag's version vouches for it
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-41853 (Medium) detected in spring-webmvc-5.1.17.RELEASE.jar',
            "<details><summary><b>spring-webmvc-5.1.17.RELEASE.jar</b></summary>\n<p>Path to dependency file: /spring/pom.xml</p>\n"
            . "<p>Path to vulnerable library: /home/u/.m2/repository/org/springframework/spring-webmvc/5.1.17.RELEASE/spring-webmvc-5.1.17.RELEASE.jar</p>\n</details>\n"
            . '<p>Fix Resolution: org.springframework:spring-web:6.2.19,https://github.com/spring-projects/spring-framework.git - v6.2.19</p>'
        ));
        $this->assertSame([['org.springframework:spring-webmvc', '6.2.19']], self::pairs($records));
    }

    public function testANewMajorTagIsTrustedForAPackageThatKeepsItsName(): void
    {
        // An npm package is the same package on its next major line
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-8159 (High) detected in multiparty-3.3.2.tgz',
            "<details><summary>Vulnerable Library - <b>multiparty-3.3.2.tgz</b></summary>\n"
            . "<p>Sample Path to Dependency File: /web/package.json</p>\n"
            . "<p>Path to vulnerable library: /web/node_modules/multiparty/package.json</p>\n</details>\n"
            . '<p>Fix Resolution: https://github.com/pillarjs/multiparty.git - 4.3.0</p>'
        ));
        $this->assertSame([['multiparty', '4.3.0']], self::pairs($records));
        $this->assertSame(['3.3.2'], $records[0]['installed']);

        // A Go module's v2 is another module path
        $this->assertSame([], IssueParser::parseIssue(self::issue(
            'CVE-2026-1 (High) detected in github.com/gin-gonic/gin-v1.9.1',
            "<details><summary>Vulnerable Library - <b>github.com/gin-gonic/gin-v1.9.1</b></summary>\n"
            . "<p>Sample Path to Dependency File: /svc/go.mod</p>\n"
            . "<p>Path to vulnerable library: /home/u/go/pkg/mod/cache/download/github.com/gin-gonic/gin/@v/v1.9.1.mod</p>\n</details>\n"
            . '<p>Fix Resolution: https://github.com/gin-gonic/gin.git - v2.0.0</p>'
        )));
    }

    public function testOwnRepositoryTagsAddReleaseBranchesOnTheMajorLinesListed(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-40973 (High) detected in spring-boot-2.1.16.RELEASE.jar',
            "<p>Path to dependency file: /pom.xml</p>\n"
            . "<p>Path to vulnerable library: /home/u/.m2/repository/org/springframework/boot/spring-boot/2.1.16.RELEASE/spring-boot-2.1.16.RELEASE.jar</p>\n"
            . '<p>Fix Resolution: https://github.com/spring-projects/spring-boot.git - v4.0.6,org.springframework.boot:spring-boot:4.0.6,'
            . 'https://github.com/spring-projects/spring-boot.git - v3.3.14,org.springframework.boot:spring-boot:3.5.14,'
            . 'https://github.com/spring-projects/spring-boot.git - v5.0.0</p>'
        ));
        $this->assertSame([
            ['org.springframework.boot:spring-boot', '4.0.6'],
            ['org.springframework.boot:spring-boot', '3.5.14'],
            ['org.springframework.boot:spring-boot', '3.3.14'],
        ], self::pairs($records), 'v5.0.0 is on no line the list names');
    }

    public function testBareVersionIsPairedWithTheFullNamesOfTheReportedLibraries(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-59647 (Medium) detected in bcprov-jdk18on-1.80.jar, bcpkix-jdk18on-1.80.jar',
            "<p>Path to dependency file: /build.gradle</p>\n"
            . "<p>Path to vulnerable library: /c/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on/1.80/e221/bcprov-jdk18on-1.80.jar</p>\n"
            . "<p>Path to vulnerable library: /c/.gradle/caches/modules-2/files-2.1/org.bouncycastle/bcpkix-jdk18on/1.80/5277/bcpkix-jdk18on-1.80.jar</p>\n"
            . '<p>Fix Resolution: 1.85</p>'
        ));
        $this->assertSame([['org.bouncycastle:bcpkix-jdk18on', '1.85'], ['org.bouncycastle:bcprov-jdk18on', '1.85']], self::pairs($records));

        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-53537 (Low) detected in python_multipart-0.0.20-py3-none-any.whl',
            "<p>Path to dependency file: /requirements.txt</p>\n"
            . "<p>Path to vulnerable library: /tmp/env/lib/python3.9/site-packages/python_multipart-0.0.20.dist-info</p>\n"
            . '<p>Fix Resolution: 0.0.30</p>'
        ));
        $this->assertSame([['python-multipart', '0.0.30']], self::pairs($records), 'one name for the dist-info and the wheel');
    }

    public function testInvisibleCharactersAndVersionPrefixesAreStripped(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-3 (Low) detected in lib',
            "<p>Path to dependency file: /m/requirements.txt</p><p>Fix Resolution (url\u{2060}lib3): v2.6.3</p>"
        ));
        $this->assertSame('urllib3', $records[0]['package']);
        $this->assertSame('2.6.3', $records[0]['fixed_version']);
    }

    public function testOneRecordPerManifest(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'WS-2026-0001 (High) detected in x',
            '<p>Path to dependency file: /b/package.json</p><p>Path to dependency file: /a/package.json</p>'
            . '<p>Fix Resolution (x): 1.0.1</p>'
        ));
        $this->assertSame(['a/package.json', 'b/package.json'], array_column($records, 'manifest'));
        $this->assertSame('WS-2026-0001', $records[0]['id']);
    }

    public function testIssueWithoutCveIsKeyedByNumber(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'Vulnerable dependency',
            '<p>Path to dependency file: /a/Gemfile</p><p>Fix Resolution (rack): 3.1.5</p>',
            77
        ));
        $this->assertSame('ISSUE-77', $records[0]['id']);
        $this->assertSame('a/Gemfile|rack|ISSUE-77', $records[0]['key']);
    }

    public function testIssuesWithoutFixOrManifestYieldNothing(): void
    {
        $this->assertSame([], IssueParser::parseIssue(self::issue('Bug report', 'Nothing to see')));
        $this->assertSame([], IssueParser::parseIssue(self::issue('CVE-1 (High)', '<p>Fix Resolution (x): 1.0</p>')));
    }

    public function testInvalidUtf8DoesNotDropTheIssue(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            "CVE-2026-4 (High) detected in \xff lib",
            "<p>Path to dependency file: /a/package.json</p><p>Fix Resolution (qs): 6.15.2</p>"
        ));
        $this->assertCount(1, $records);
    }

    public function testGroupedMendIssueGivesOneRecordPerCve(): void
    {
        $body = "<details><summary> Vulnerable Library - <b>axios-1.3.5.tgz</b></summary>\n"
            . "<p>Sample Path to Dependency File: /package.json</p>\n</details>\n\n## Vulnerabilities\n\n"
            . "| Vulnerability | Severity | CVSS | Dependency | Type | Fixed in (axios version) | Remediation Possible** |\n"
            . "| --- | --- | --- | --- | --- | --- | --- |\n"
            . "| [CVE-2026-1](https://x) | <img src='x'> Critical | 9.3 | axios-1.3.5.tgz | Direct | 1.20.0 | &#10060; |\n"
            . "| [CVE-2026-2](https://x) | <img src='x'> High | 8.7 | axios-1.3.5.tgz | Direct | axios - 1.16.0 | &#10060; |\n"
            . "| [CVE-2026-3](https://x) | <img src='x'> Medium | 5.0 | axios-1.3.5.tgz | Direct | N/A | &#10060; |\n"
            . "\n## Details\n\n<details>\n\n<summary> CVE-2026-1</summary>\n\n###  Vulnerable Library - <b>axios-1.3.5.tgz</b>\n"
            . "<p>Sample Path to Dependency File: /package.json</p>\n<p>Fix Resolution: 1.20.0</p>\n</details>";
        $records = IssueParser::parseIssue(self::issue('axios-1.3.5.tgz: 3 vulnerabilities (highest severity is: 9.3)', $body, 24));
        $rows = array_map(static fn ($r) => [$r['id'], $r['package'], $r['fixed_version'], $r['severity'], $r['state'] ?? 'pending'], $records);
        $this->assertSame([
            ['CVE-2026-1', 'axios', '1.20.0', 'critical', 'pending'],
            ['CVE-2026-2', 'axios', '1.16.0', 'high', 'pending'],       // table only: details were truncated
            ['CVE-2026-3', 'axios', '', 'medium', 'skipped'],           // no fix known: keeps the issue open
        ], $rows);
        $this->assertSame('package.json|axios|CVE-2026-1', $records[0]['key']);
        $this->assertSame([24], $records[0]['refs']);
    }

    public function testHostileBodiesAreNeutralised(): void
    {
        $records = IssueParser::parseIssue(self::issue(
            'CVE-2026-9 (High) detected in lib-1.0.0.jar',
            "<p>Path to dependency file: /build.gradle</p>\n<p>Fix Resolution (com.acme:lib): 9.9.9\" + Eval.me('x') + \"</p>\n"
        ));
        $this->assertSame('', $records[0]['fixed_version'], 'not a version: never written anywhere');
        $this->assertSame('skipped', $records[0]['state']);
        $this->assertSame([], IssueParser::parseIssue(self::issue(
            'CVE-2026-9 (High) detected in lib-1.0.0.tgz',
            "<p>Path to dependency file: /../../etc/package.json</p>\n<p>Fix Resolution (lib): 1.0.1</p>\n"
        )), 'a path outside the repository is dropped');
    }
}
