<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\FixPlanner;
use Detain\DepSecPatcher\VulnDb;
use PHPUnit\Framework\TestCase;

/**
 * The vulnerability database merge/state rules and the auto-fix plan built
 * from it. VulnDb::upsert reproduced the original shell script's jq merge exactly on
 * the real 2359-record database plus a fresh 15280-record collection.
 */
class VulnDbAndPlannerTest extends TestCase
{
    /**
     * @param array<string, mixed> $over
     * @return array<string, mixed>
     */
    private static function rec(array $over = []): array
    {
        return $over + [
            'key' => 'a/package.json|qs|CVE-1', 'source' => 'issue', 'id' => 'CVE-1', 'ref' => 5, 'refs' => [5],
            'ecosystem' => 'npm', 'package' => 'qs', 'manifest' => 'a/package.json',
            'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'],
        ];
    }

    public function testUpsertPreservesStateAndUnionsLists(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [self::rec()], '2026-01-01T00:00:00Z', 'o/r');
        $db = VulnDb::applyStates($db, [['key' => 'a/package.json|qs|CVE-1', 'state' => 'applied', 'note' => 'set']], '2026-01-01T00:00:01Z');
        $db = VulnDb::upsert($db, [self::rec(['ref' => 9, 'refs' => [9], 'fix_versions' => ['6.14.1']])], '2026-02-01T00:00:00Z', '');

        $v = $db['vulns']['a/package.json|qs|CVE-1'];
        $this->assertSame('2026-01-01T00:00:00Z', $v['first_seen']);
        $this->assertSame('2026-02-01T00:00:00Z', $v['last_seen']);
        $this->assertSame('applied', $v['state'], 'a re-collected record keeps its outcome');
        $this->assertSame('2026-01-01T00:00:01Z', $v['applied_at']);
        $this->assertSame([5, 9], $v['refs']);
        $this->assertSame(['6.14.1', '6.15.2'], $v['fix_versions']);
        $this->assertSame(9, $v['ref'], 'scalar fields take the newest values');
        $this->assertSame('o/r', $db['repo'], 'an empty repo does not overwrite');
    }

    public function testSaveLoadRoundTripKeepsObjectShape(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'vulndb');
        try {
            VulnDb::save($file, VulnDb::empty());
            $this->assertStringContainsString('"vulns": {}', (string)file_get_contents($file));
            $this->assertSame(0600, fileperms($file) & 0777);
            $this->assertSame(VulnDb::empty(), VulnDb::load($file));

            file_put_contents($file, '{"schema":1,"vulns":');
            $corrupt = false;
            $this->assertSame(VulnDb::empty(), VulnDb::load($file, $corrupt));
            $this->assertTrue($corrupt);
        } finally {
            @unlink($file);
        }
    }

    public function testPlanCollapsesPerManifestAndPackage(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [
            self::rec(['key' => 'k1', 'id' => 'CVE-1', 'fix_versions' => ['10.1.42', '9.0.106'], 'fixed_version' => '11.0.8', 'package' => 'tomcat', 'ecosystem' => 'maven', 'manifest' => 'p/pom.xml']),
            self::rec(['key' => 'k2', 'id' => 'CVE-2', 'fix_versions' => ['9.0.107'], 'fixed_version' => '9.0.107', 'package' => 'tomcat', 'ecosystem' => 'maven', 'manifest' => 'p/pom.xml']),
            self::rec(['key' => 'k3', 'id' => 'CVE-3', 'fix_versions' => ['2.0'], 'fixed_version' => '2.0', 'package' => 'tomcat', 'ecosystem' => 'pip', 'manifest' => 'q/requirements.txt']),
            self::rec(['key' => 'k4', 'manifest' => '']),                                  // no manifest
            self::rec(['key' => 'k5', 'ecosystem' => 'unknown', 'manifest' => 'z/x']),     // unknown ecosystem
        ], 'now', '');
        $db = VulnDb::applyStates($db, [['key' => 'k3', 'state' => 'applied', 'note' => '']], 'now');
        $db['vulns']['k3']['state'] = 'applied';

        $plan = FixPlanner::plan($db);
        $this->assertCount(1, $plan);
        $this->assertSame('p/pom.xml', $plan[0]['manifest']);
        $this->assertSame(['CVE-1' => ['9.0.106', '10.1.42', '11.0.8'], 'CVE-2' => ['9.0.107']], $plan[0]['spec']);
        $this->assertSame(['k1', 'k2'], $plan[0]['keys']);
        // Per ecosystem: the applied pip record named "tomcat" does not leak in
        $this->assertSame('11.0.8', $plan[0]['pkg_max']);
    }

    public function testIssueRequirementsExpandRefs(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [
            self::rec(['key' => 'k1', 'refs' => [3, 4]]),
            self::rec(['key' => 'k2', 'source' => 'dependabot', 'refs' => [3]]),
        ], 'now', '');
        $req = FixPlanner::issueRequirements($db);
        $this->assertSame([3, 4], array_keys($req));
        $this->assertSame('qs', $req[3][0]['package']);
        $this->assertCount(1, $req[3], 'dependabot records are not issues');
    }

    public function testRequirementMet(): void
    {
        $need = ['fixed_version' => '11.0.8', 'fix_versions' => ['9.0.106', '10.1.42', '11.0.8']];
        $this->assertTrue(FixPlanner::requirementMet('11.0.9', $need));
        $this->assertTrue(FixPlanner::requirementMet('9.0.110', $need), 'own release line is fixed');
        $this->assertFalse(FixPlanner::requirementMet('9.0.50', $need));
        $this->assertFalse(FixPlanner::requirementMet('${x}', $need));
        // Conservative for ranges: judged by the lower bound
        $this->assertFalse(FixPlanner::requirementMet('[2.8.3,3)', ['fixed_version' => '2.21.3', 'fix_versions' => ['2.21.3']]));
    }

    public function testARequirementIsMetOnTheDeclaredVersionsOwnReleaseLine(): void
    {
        // The recorded fix is whichever branch's fix the issue listed last
        $need = ['fixed_version' => '4.1.137.Final', 'fix_versions' => ['4.2.17.Final', '4.1.137.Final']];
        $this->assertFalse(FixPlanner::requirementMet('4.2.5.Final', $need), 'above the 4.1 fix, below the 4.2 one');
        $this->assertTrue(FixPlanner::requirementMet('4.2.17.Final', $need));
        $this->assertTrue(FixPlanner::requirementMet('4.1.140.Final', $need));
        $this->assertFalse(FixPlanner::requirementMet('5.0.0.Alpha2', $need), 'a 2015 alpha has none of the fixes');
        $this->assertFalse(FixPlanner::requirementMet('7.1.0-M2', ['fixed_version' => '7.0.8', 'fix_versions' => ['6.2.19', '7.0.8']]));
        $this->assertSame(['4.1.137.Final', '4.2.17.Final'], FixPlanner::fixes($need));
        $this->assertSame(['2.0'], FixPlanner::fixes(['fixed_version' => '2.0', 'fix_versions' => []]));
        $this->assertTrue(FixPlanner::requirementMet('4.2.0-M2', ['fixed_version' => '3.0.0', 'fix_versions' => ['3.0.0']]), 'a milestone of a later line');

        $this->assertSame('needs >= 4.1.137.Final or 4.2.17.Final', FixPlanner::shortfall(['4.2.5.Final'], $need));
        $this->assertSame(
            'needs >= 4.1.137.Final or 4.2.17.Final (a prerelease above every fix is not known to include one)',
            FixPlanner::shortfall(['5.0.0.Alpha2'], $need)
        );
        $this->assertSame('needs >= 1.0.0', FixPlanner::shortfall(['1.0.0-beta'], ['fixed_version' => '1.0.0', 'fix_versions' => []]));
    }

    public function testRetireOnlyPendingRecordsGithubNoLongerReports(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [
            ['key' => 'gone', 'source' => 'dependabot', 'refs' => [1]],
            ['key' => 'open', 'source' => 'dependabot', 'refs' => [2]],
            ['key' => 'done', 'source' => 'dependabot', 'refs' => [3]],
            ['key' => 'iss-closed', 'source' => 'issue', 'refs' => [10]],
            ['key' => 'iss-open', 'source' => 'issue', 'refs' => [10, 11]],
        ], 't0', '');
        $db = VulnDb::applyStates($db, [['key' => 'done', 'state' => 'applied', 'note' => '']], 't0');
        $db = VulnDb::retire($db, 'dependabot', ['open' => true], 't1');
        $this->assertSame('resolved', $db['vulns']['gone']['state']);
        $this->assertSame('pending', $db['vulns']['open']['state']);
        $this->assertSame('applied', $db['vulns']['done']['state'], 'settled records keep their outcome');
        $this->assertSame('pending', $db['vulns']['iss-closed']['state'], 'other sources untouched');

        $db = VulnDb::retire($db, 'issue', [], 't1', [11 => true]);
        $this->assertSame('resolved', $db['vulns']['iss-closed']['state']);
        $this->assertSame('pending', $db['vulns']['iss-open']['state'], 'one of its issues is still open');
    }

    public function testIssuesJustReadSupersedeWhatTheyReportedBefore(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [
            ['key' => 'm|babel|CVE-1', 'source' => 'issue', 'ref' => 7, 'refs' => [7], 'state' => 'applied'],
            ['key' => 'm|net|CVE-2', 'source' => 'issue', 'ref' => 7, 'refs' => [7, 9]],
            ['key' => 'm|qs|CVE-3', 'source' => 'issue', 'ref' => 8, 'refs' => [8]],
            ['key' => 'm|qs|GHSA', 'source' => 'dependabot', 'ref' => 7, 'refs' => [7]],
        ], 't0', '');
        $now = [['key' => 'm|@babel/core|CVE-1', 'source' => 'issue', 'ref' => 7, 'refs' => [7]]];
        $db  = VulnDb::supersede(VulnDb::upsert($db, $now, 't1', ''), $now, [7 => true]);

        $this->assertArrayNotHasKey('m|babel|CVE-1', $db['vulns'], 'issue 7 no longer yields it');
        $this->assertArrayHasKey('m|@babel/core|CVE-1', $db['vulns']);
        $this->assertSame([9], $db['vulns']['m|net|CVE-2']['refs'], 'issue 9 was not read, so it still stands');
        $this->assertSame(9, $db['vulns']['m|net|CVE-2']['ref']);
        $this->assertSame([8], $db['vulns']['m|qs|CVE-3']['refs'], 'issue 8 was not read');
        $this->assertArrayHasKey('m|qs|GHSA', $db['vulns'], 'other sources untouched');
    }

    public function testUpsertKeepsAnArrivingState(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [['key' => 'k', 'state' => 'skipped', 'note' => 'no fixed version known']], 't', '');
        $this->assertSame('skipped', $db['vulns']['k']['state']);
        $this->assertSame('no fixed version known', $db['vulns']['k']['note']);
    }

    public function testAdvisoriesAreKeyedByTheExactCoordinate(): void
    {
        $mk = static fn (array $over): array => $over + [
            'key' => 'k1', 'id' => 'CVE-1', 'ecosystem' => 'maven', 'package' => 'io.netty:netty-codec-http2',
            'manifest' => 'pom.xml', 'fixed_version' => '4.1.135.Final', 'fix_versions' => ['4.1.135.Final'],
            'vulnerable_range' => '< 4.1.135.Final',
        ];
        $db = VulnDb::upsert(VulnDb::empty(), [
            $mk([]),
            // The same artifactId under another groupId: a plexus-utils-style
            // version must never be able to answer for netty
            $mk(['key' => 'k2', 'id' => 'CVE-2', 'package' => 'com.acme:netty-codec-http2',
                'fixed_version' => '7.0.12', 'fix_versions' => ['7.0.12'], 'vulnerable_range' => '']),
            // An already-applied record still says which versions were affected
            $mk(['key' => 'k3', 'id' => 'CVE-3', 'ecosystem' => 'npm', 'package' => 'qs', 'state' => 'applied',
                'fixed_version' => '6.15.2', 'fix_versions' => ['6.15.2'], 'vulnerable_range' => '>= 6.0.0, < 6.15.2']),
            $mk(['key' => 'k4', 'id' => 'CVE-4', 'ecosystem' => '', 'package' => 'x']),
        ], 't', '');
        $known = FixPlanner::advisories($db);

        $this->assertSame(['maven|com.acme:netty-codec-http2', 'maven|io.netty:netty-codec-http2', 'npm|qs'], array_keys($known));
        $this->assertSame(['4.1.135.Final'], $known['maven|io.netty:netty-codec-http2']['CVE-1']['fixes']);
        $this->assertSame(['7.0.12'], $known['maven|com.acme:netty-codec-http2']['CVE-2']['fixes'], 'one groupId does not speak for the other');
        $this->assertSame(['>= 6.0.0, < 6.15.2'], $known['npm|qs']['CVE-3']['ranges'], 'applied records still count');
        $this->assertSame([], FixPlanner::vulnerableTarget('7.0.12', $known['maven|io.netty:netty-codec-http2']),
            'the other group\'s version is not in netty\'s range');
    }

    public function testATargetInsideAKnownAffectedRangeIsNotAFix(): void
    {
        $known = ['GHSA-t' => ['fixes' => ['9.0.119', '10.1.55', '11.0.25'], 'ranges' => ['>= 11.0.0, < 11.0.25']]];
        $this->assertSame(['GHSA-t'], FixPlanner::vulnerableTarget('11.0.17', $known), 'the version that opened ten fresh alerts');
        $this->assertSame(['GHSA-t'], FixPlanner::vulnerableTarget('9.0.118', $known), 'below the fix on its own line');
        $this->assertSame([], FixPlanner::vulnerableTarget('11.0.25', $known));
        $this->assertSame([], FixPlanner::vulnerableTarget('9.0.119', $known));

        // With no range recorded, "below a fix on the same branch" is the shape of still-affected
        $fixesOnly = ['GHSA-j' => ['fixes' => ['11.0.25'], 'ranges' => []]];
        $this->assertSame(['GHSA-j'], FixPlanner::vulnerableTarget('11.0.17', $fixesOnly));
        $this->assertSame([], FixPlanner::vulnerableTarget('10.0.5', $fixesOnly), 'a line the advisory does not speak of');
    }

    public function testSafeTargetWalksAwayFromVersionsThatFailTheirGuards(): void
    {
        $from = static fn (array $published): callable => static fn (string $v): bool => in_array($v, $published, true);

        // minimatch: the record named 3.1.4, npm's newest on the line is 3.1.2
        $got = FixPlanner::safeTarget('npm', '3.0.4', '3.1.4', ['CVE-m' => ['3.1.2', '3.1.4']], [],
            ['3.0.4', '3.1.2', '5.1.2'], $from(['3.0.4', '3.1.2', '5.1.2']));
        $this->assertSame('3.1.2', $got['version']);
        $this->assertStringContainsString('is not published on the npm registry', $got['why']);

        // lodash 4.18.0: nothing publishes it and nothing lower clears it - no pin beats a broken one
        $got = FixPlanner::safeTarget('npm', '^4.17.20', '4.18.0', ['CVE-l' => ['4.18.0']], [],
            ['4.0.0', '4.17.20', '4.17.21'], $from(['4.0.0', '4.17.20', '4.17.21']));
        $this->assertSame('', $got['version'], 'the no-fix-yet answer');
        $this->assertStringContainsString('is not published on the npm registry', $got['why']);

        // tomcat-embed-core 11.0.17 exists and is itself affected; 11.0.25 is the fix
        $got = FixPlanner::safeTarget('maven', '11.0.12', '11.0.17', ['CVE-t' => ['11.0.17']],
            ['GHSA-t' => ['fixes' => ['11.0.25'], 'ranges' => ['>= 11.0.0, < 11.0.25']]],
            ['11.0.12', '11.0.17', '11.0.25'], $from(['11.0.12', '11.0.17', '11.0.25']));
        $this->assertSame('11.0.25', $got['version']);
        $this->assertStringContainsString('is itself affected by GHSA-t', $got['why']);

        // guava: r09 does not outrank 28.1-jre, and the -jre family is kept
        $published = ['r09', 'r10', '28.1-jre', '28.2-jre', '28.2-android', '33.4.8-jre'];
        $got       = FixPlanner::safeTarget('maven', '28.1-jre', 'r09', ['CVE-g' => ['r09', '28.2-jre']], [],
            $published, $from($published));
        $this->assertSame('28.2-jre', $got['version'], 'stays on the line in use and on the family in use');
        $this->assertStringContainsString('would downgrade from 28.1-jre', $got['why']);

        // The deliberate prerelease-to-release channel may move down
        $got = FixPlanner::safeTarget('maven', '5.0.0.Alpha2', '4.2.17.Final',
            ['CVE-n' => ['4.1.137.Final', '4.2.17.Final']], [], null, null, true);
        $this->assertSame('4.2.17.Final', $got['version']);
        $this->assertSame('', $got['why'], 'the channel passes unmoved');

        // A registry that cannot answer must not block the fix
        $got = FixPlanner::safeTarget('npm', '^6.15.1', '6.15.2', ['CVE-q' => ['6.15.2']], [], null, null);
        $this->assertSame('6.15.2', $got['version']);
        $this->assertSame('', $got['why']);
    }

    public function testIssueMetaReadsEachIssueThroughItsRecords(): void
    {
        $db = VulnDb::upsert(VulnDb::empty(), [
            self::rec(['key' => 'k1', 'refs' => [5], 'ref' => 5, 'summary' => 'CVE-1 in qs', 'cve' => 'CVE-1', 'package' => 'qs']),
            self::rec(['key' => 'k2', 'refs' => [6, 5], 'ref' => 6, 'summary' => 'CVE-2 in qs', 'cve' => 'CVE-2', 'package' => 'lodash']),
            self::rec(['key' => 'k3', 'source' => 'dependabot', 'refs' => [9], 'ref' => 9, 'summary' => 'not an issue']),
        ], 'now', '');
        $meta = FixPlanner::issueMeta($db);
        $this->assertSame(['title' => 'CVE-1 in qs', 'cve' => 'CVE-1', 'package' => 'qs'], $meta[5], 'the first record to say something wins');
        $this->assertSame(['title' => 'CVE-2 in qs', 'cve' => 'CVE-2', 'package' => 'lodash'], $meta[6], 'a multi-issue record describes every issue it names');
        $this->assertSame([], $meta[9] ?? [], 'dependabot records are not issues');
    }

    public function testDuplicateTitlesCountsOnlyTitlesWithMoreThanTwoIssues(): void
    {
        $need = static fn (string $p): array => [[
            'ecosystem' => 'npm', 'package' => $p, 'fixed_version' => '1.0',
            'fix_versions' => ['1.0'], 'manifest' => 'a/package.json',
        ]];
        $byIssue = [1 => $need('a'), 2 => $need('a'), 3 => $need('a'), 4 => $need('a'),
                    5 => $need('b'), 6 => $need('b'), 7 => $need('c'), 8 => $need('')];
        $meta = [1 => ['title' => 'Title A', 'cve' => '', 'package' => ''],
                 2 => ['title' => 'Title A', 'cve' => '', 'package' => ''],
                 3 => ['title' => 'Title A', 'cve' => '', 'package' => ''],
                 4 => ['title' => 'Title A', 'cve' => '', 'package' => ''],
                 5 => ['title' => 'Title B', 'cve' => '', 'package' => ''],
                 6 => ['title' => 'Title B', 'cve' => '', 'package' => ''],
                 7 => ['title' => '', 'cve' => '', 'package' => '']];
        $got = FixPlanner::duplicateTitles($byIssue, $meta);
        $this->assertSame(4, $got['issues'], 'only Title A crossed the more-than-two bar, and it counts its issues');
        $this->assertSame([['title' => 'Title A', 'count' => 4]], $got['titles']);
        $this->assertSame(0, FixPlanner::duplicateTitles([1 => $need('a')], $meta)['issues']);
    }

    public function testAlertNeedsMajorComparesTheFixToTheRangesFloor(): void
    {
        $this->assertTrue(FixPlanner::alertNeedsMajor('>= 4.0.0, < 5.0.0', '5.0.0'), 'the only fix is on the next major');
        $this->assertTrue(FixPlanner::alertNeedsMajor('>= 1.0.0, < 1.9.0', '2.0.1'));
        $this->assertTrue(FixPlanner::alertNeedsMajor('< 4.0.0', '5.0.0'), 'conservative when the range has one token');
        $this->assertFalse(FixPlanner::alertNeedsMajor('>= 4.0.0, < 4.1.100', '4.1.100'), 'the ordinary case: a patch-line fix');
        $this->assertFalse(FixPlanner::alertNeedsMajor('>= 1.0.0, < 1.9.0', '1.5.0'));
        $this->assertFalse(FixPlanner::alertNeedsMajor('>= 2.0.0, < 3.0.0', '2.9.9'));
        $this->assertFalse(FixPlanner::alertNeedsMajor('', '5.0.0'), 'no range claims nothing');
        $this->assertFalse(FixPlanner::alertNeedsMajor('>= 4.0.0', ''), 'no fix means no fix line to compare');
        $this->assertFalse(FixPlanner::alertNeedsMajor('all versions', '3.0.0'), 'a range without version tokens says nothing');
    }
}
