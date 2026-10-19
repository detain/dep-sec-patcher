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
}
