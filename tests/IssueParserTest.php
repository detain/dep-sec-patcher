<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\IssueParser;
use PHPUnit\Framework\TestCase;

/**
 * Mend Bolt issue bodies -> remediation records. The parser is a port of the
 * original shell script's jq program; on a public repository's 6530 open issues the two
 * produced identical output (14828 records). These cases pin each body shape.
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
}
