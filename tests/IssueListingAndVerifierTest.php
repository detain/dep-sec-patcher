<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\CloseState;
use Detain\DepSecPatcher\FixPlanner;
use Detain\DepSecPatcher\GitHub;
use Detain\DepSecPatcher\IssueVerifier;
use Detain\DepSecPatcher\SecurityRun;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * Paging through every open issue, what auto-fix counts, close-fixed's
 * per-issue verdict and the summary row it leaves.
 */
class IssueListingAndVerifierTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    /**
     * A fake GraphQL listing of $total issues, newest first.
     *
     * @param list<string> $failures errors to return, in order, before pages
     * @param list<array{0: ?string, 1: int}> $calls
     * @return callable(?string, int): (array<string, mixed>|string)
     */
    private static function listing(int $total, array $failures = [], array &$calls = [], int $remaining = 4000): callable
    {
        return static function (?string $after, int $first) use ($total, &$failures, &$calls, $remaining): array|string {
            $calls[] = [$after, $first];
            if ($failures !== []) {
                return array_shift($failures);
            }
            $start = $after === null ? 0 : (int)$after;
            $nodes = [];
            for ($i = $start; $i < min($total, $start + $first); $i++) {
                $nodes[] = [
                    'number' => $total - $i, 'title' => "CVE-{$i}", 'body' => 'b', 'url' => 'u',
                    'author' => ['login' => $i % 2 === 0 ? 'mend-bolt-for-github' : 'someone', '__typename' => $i % 2 === 0 ? 'Bot' : 'User'],
                ];
            }
            $end = $start + count($nodes);
            return ['data' => [
                'repository' => ['issues' => ['nodes' => $nodes, 'pageInfo' => ['hasNextPage' => $end < $total, 'endCursor' => (string)$end]]],
                'rateLimit'  => ['remaining' => $remaining, 'resetAt' => gmdate('Y-m-d\TH:i:s\Z', time() + 120)],
            ]];
        };
    }

    public function testReadsEveryPageAndMarksTheListingComplete(): void
    {
        $calls  = [];
        $issues = GitHub::collectIssues(self::listing(6343, [], $calls), 0, static function (int $s): void {
        }, null, $complete);
        $this->assertNotNull($issues);
        $this->assertCount(6343, $issues);
        $this->assertTrue($complete);
        $this->assertCount(64, $calls, '100 per page');
        $this->assertSame(['number' => 6343, 'title' => 'CVE-0', 'body' => 'b', 'url' => 'u', 'author' => ['login' => 'mend-bolt-for-github', 'is_bot' => true]], $issues[0]);
        $this->assertFalse($issues[1]['author']['is_bot']);
    }

    public function testALimitStopsEarlyAndIsNotComplete(): void
    {
        $calls  = [];
        $issues = GitHub::collectIssues(self::listing(500, [], $calls), 250, static function (int $s): void {
        }, null, $complete);
        $this->assertCount(250, $issues ?? []);
        $this->assertFalse($complete, 'a listing cut short must not retire records');
        $this->assertSame(50, $calls[2][1], 'the last page asks only for what is left');

        GitHub::collectIssues(self::listing(250), 250, static function (int $s): void {
        }, null, $complete);
        $this->assertTrue($complete, 'exactly the limit, with no page after it, is everything');
    }

    public function testAFailedPageIsRetriedSmallerAndARateLimitWaits(): void
    {
        $calls  = [];
        $sleeps = [];
        $issues = GitHub::collectIssues(
            self::listing(150, ['HTTP 502: Bad Gateway', 'API rate limit exceeded'], $calls),
            0,
            static function (int $s) use (&$sleeps): void {
                $sleeps[] = $s;
            },
            null,
            $complete
        );
        $this->assertCount(150, $issues ?? []);
        $this->assertTrue($complete);
        $this->assertSame([[null, 100], [null, 50], [null, 50]], array_slice($calls, 0, 3), 'a 502 halves the page');
        $this->assertSame(60 * 2, $sleeps[1], 'rate limited with no reset known yet: back off');
        $this->assertSame([150, 149], array_column(array_slice($issues ?? [], 0, 2), 'number'));
    }

    public function testANearlySpentQuotaWaitsForTheReset(): void
    {
        $sleeps = [];
        $calls  = [];
        GitHub::collectIssues(self::listing(150, [], $calls, 3), 0, static function (int $s) use (&$sleeps): void {
            $sleeps[] = $s;
        });
        $this->assertCount(1, $sleeps);
        $this->assertGreaterThan(100, $sleeps[0]);
    }

    public function testAPageThatKeepsFailingFailsTheListing(): void
    {
        $this->assertNull(GitHub::collectIssues(self::listing(10, array_fill(0, 7, 'boom')), 0, static function (int $s): void {
        }, null, $complete));
        $this->assertFalse($complete);
    }

    public function testPendingRecordsAutoFixCannotPlanAreCounted(): void
    {
        $db = ['vulns' => [
            'a' => ['key' => 'a', 'state' => 'pending', 'manifest' => 'p/package-lock.json', 'ecosystem' => 'npm', 'package' => 'braces', 'fixed_version' => ''],
            'b' => ['key' => 'b', 'state' => 'pending', 'manifest' => 'p/package-lock.json', 'ecosystem' => 'npm', 'package' => 'braces', 'fixed_version' => '3.0.3'],
            'c' => ['key' => 'c', 'state' => 'pending', 'manifest' => '', 'ecosystem' => 'npm', 'package' => 'x', 'fixed_version' => '1.0.0'],
            'd' => ['key' => 'd', 'state' => 'skipped', 'manifest' => 'p/package.json', 'ecosystem' => 'npm', 'package' => 'y', 'fixed_version' => ''],
        ]];
        $this->assertSame(['no-fix' => 1, 'unplaceable' => 1], FixPlanner::unplanned($db));
        $this->assertCount(1, FixPlanner::plan($db), 'the two unplanned records are the ones plan() leaves out');
    }

    /**
     * @return array{ecosystem: string, package: string, fixed_version: string, fix_versions: list<string>, manifest: string}
     */
    private static function need(string $manifest, string $package, string $fixed): array
    {
        return ['ecosystem' => '', 'package' => $package, 'fixed_version' => $fixed, 'fix_versions' => [$fixed], 'manifest' => $manifest];
    }

    private function verifier(string $root, ?callable $removedIn = null): IssueVerifier
    {
        return new IssueVerifier($root, static fn (string $d): array => [], static fn (string $m): bool => true, '', $removedIn);
    }

    public function testVerdicts(): void
    {
        $root = $this->scratchDir('verify');
        mkdir("{$root}/app");
        file_put_contents("{$root}/app/requirements.txt", "connexion >= 2.6.0\nurllib3==2.6.3\n");
        $v = $this->verifier($root);

        $ok = $v->verify([self::need('app/requirements.txt', 'urllib3', '2.5.0')]);
        $this->assertTrue($ok['ok']);
        $this->assertStringContainsString('**==2.6.3**', $ok['evidence']);

        $this->assertSame('unresolved', $v->verify([self::need('app/requirements.txt', 'urllib3', '2.7.0')])['reason']);

        $transitive = $v->verify([self::need('app/requirements.txt', 'starlette', '0.49.1')]);
        $this->assertSame('unverifiable', $transitive['reason']);
        $this->assertSame('starlette not declared in app/requirements.txt (transitive, and no lockfile to check)', $transitive['detail']);

        $this->assertSame('unverifiable', $v->verify([self::need('app/requirements.txt', 'urllib3', '')])['reason'], 'no fix known');
    }

    public function testAManifestDeletedFromTheBranchResolvesItsIssue(): void
    {
        $root = $this->scratchDir('verify');
        mkdir("{$root}/kept");
        file_put_contents("{$root}/kept/pom.xml", '<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>2.0</version></dependency></dependencies></project>');
        $needs = [self::need('gone/pom.xml', 'g:a', '1.5'), self::need('kept/pom.xml', 'g:a', '1.5')];

        $missing = $this->verifier($root)->verify($needs);
        $this->assertSame(['unverifiable', 'manifest missing: gone/pom.xml'], [$missing['reason'], $missing['detail']], 'no history to say it was ever there');

        $asked = [];
        $removed = $this->verifier($root, static function (string $rel) use (&$asked): ?string {
            $asked[] = $rel;
            return $rel === 'gone/pom.xml' ? str_repeat('ab', 20) : null;
        })->verify($needs);
        $this->assertTrue($removed['ok']);
        $this->assertSame(['gone/pom.xml'], $asked);
        $this->assertStringContainsString('**manifest removed** in abababababab', $removed['evidence']);
        $this->assertStringContainsString('**2.0**', $removed['evidence'], 'the manifests still there are checked as usual');

        $never = $this->verifier($root, static fn (string $rel): ?string => null)->verify($needs);
        $this->assertFalse($never['ok'], 'a path never on the branch proves nothing');
    }

    public function testSummaryNotesAreNotCountedAsOutdatedPackages(): void
    {
        $m    = new ReflectionMethod(SecurityRun::class, 'summaryLine');
        $line = $m->invoke(null, 'close-fixed', ['status' => 'PASS', 'vulns' => 0, 'outdated' => 0, 'note' => 'would close 58 (not closed)']);
        $this->assertSame('close-fixed       PASS     0                0          would close 58 (not closed)', $line);
        $this->assertSame('maven             FAIL     206              3', $m->invoke(null, 'maven', ['status' => 'FAIL', 'vulns' => 206, 'outdated' => 3, 'note' => '']));
    }

    public function testTheUnverifiableNoteSpellsOutWhatTheRepositoryIsMissing(): void
    {
        $transitive = SecurityRun::unverifiableNote([
            'verdict' => 'unverifiable', 'why' => CloseState::TRANSITIVE_WHY, 'package' => 'qs',
            'paths' => ['web/package.json', 'api/package.json', 'web/package.json'],
        ], 9);
        $this->assertStringContainsString('has not been able to verify this issue for 9 days', $transitive);
        $this->assertStringContainsString('`qs` is transitive', $transitive);
        $this->assertStringContainsString('`/api`, `/web` hold no lockfile', $transitive, 'directories dedup and sort');
        $this->assertStringContainsString('commit a lockfile', $transitive);
        $this->assertStringContainsString('<!-- security-update:unverifiable-note -->', $transitive, 'the marker says who spoke and stops a repeat');

        $noFix = SecurityRun::unverifiableNote(['verdict' => 'unverifiable', 'why' => 'no fix known', 'package' => 'old-lib'], 30);
        $this->assertStringContainsString('no fixed version is known upstream for `old-lib`', $noFix);

        $unknown = SecurityRun::unverifiableNote(['verdict' => 'unverifiable', 'why' => 'quite peculiar', 'detail' => 'the resolver shrugged'], 8);
        $this->assertStringContainsString('the resolver shrugged', $unknown, 'an unclassified reason quotes the verifier');

        $noPackage = SecurityRun::unverifiableNote(['verdict' => 'unverifiable', 'why' => CloseState::TRANSITIVE_WHY, 'paths' => []], 7);
        $this->assertStringContainsString('This dependency is transitive', $noPackage);
        $this->assertStringContainsString('the project hold no lockfile', $noPackage, 'no known directory still reads as a sentence');
    }

    /**
     * A fake paged listing: $pages holds the rows of each page (null = the
     * call failed); beyond the end every page comes back short and empty.
     *
     * @param list<list<array<string, mixed>>|null> $pages
     * @param list<int>                             $calls
     * @return callable(int): (list<array<string, mixed>>|null)
     */
    private static function pullPages(array $pages, array &$calls): callable
    {
        return static function (int $page) use ($pages, &$calls): ?array {
            $calls[] = $page;
            if ($page > count($pages)) {
                return [];
            }
            return $pages[$page - 1];
        };
    }

    public function testPullsAreReadUntilAShortPageEndsTheListing(): void
    {
        $calls = [];
        $rows  = GitHub::collectPulls(self::pullPages([
            array_fill(0, 100, ['number' => 1]),
            array_fill(0, 100, ['number' => 2]),
            [['number' => 3], ['number' => 4]],
        ], $calls), $complete);
        $this->assertCount(202, $rows);
        $this->assertTrue($complete);
        $this->assertSame([1, 2, 3], $calls);
    }

    public function testExactlyFullPagesEndWithAnEmptyOne(): void
    {
        $calls = [];
        $rows  = GitHub::collectPulls(self::pullPages([array_fill(0, 100, ['number' => 1])], $calls), $complete);
        $this->assertCount(100, $rows);
        $this->assertTrue($complete, 'the empty page says there was nothing more');
        $this->assertSame([1, 2], $calls);
    }

    public function testAFailedListingIsNothingAndIncomplete(): void
    {
        $calls = [];
        $rows  = GitHub::collectPulls(self::pullPages([null], $calls), $complete);
        $this->assertSame([], $rows);
        $this->assertFalse($complete, 'triage must not prune its memory against this');
    }

    public function testAMidListingFailureKeepsWhatWasRead(): void
    {
        $calls = [];
        $rows  = GitHub::collectPulls(self::pullPages([array_fill(0, 100, ['number' => 1]), null, []], $calls), $complete);
        $this->assertCount(100, $rows);
        $this->assertFalse($complete, 'the rest is unread, not absent');
        $this->assertSame([1, 2], $calls, 'a failed page ends the pass');
    }

    public function testThePageCapStopsWithoutClaimingCompletion(): void
    {
        $calls = [];
        $rows  = GitHub::collectPulls(self::pullPages([
            array_fill(0, 100, ['number' => 1]),
            array_fill(0, 100, ['number' => 2]),
            array_fill(0, 100, ['number' => 3]),
        ], $calls), $complete, 2);
        $this->assertCount(200, $rows);
        $this->assertFalse($complete);
        $this->assertSame([1, 2], $calls);
    }
}
