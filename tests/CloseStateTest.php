<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\CloseState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The cross-run memory of close-fixed: what survives a round trip, what
 * retain() forgets, and the pure predicates that decide when a remembered
 * verdict may stand in for re-verifying, and when an issue that has been
 * unverifiable for a week earns its one annotation.
 */
class CloseStateTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    private function statePath(string $name = 'close-state.json'): string
    {
        return $this->scratchDir('close') . '/' . $name;
    }

    /**
     * One requirement list, in the shape FixPlanner hands the verifier.
     *
     * @return list<array{ecosystem: string, package: string, fixed_version: string, fix_versions: list<string>, manifest: string}>
     */
    private static function needs(string $package = 'qs', string $fix = '6.15.2', string $manifest = 'a/package.json'): array
    {
        return [[
            'ecosystem'     => 'npm',
            'package'       => $package,
            'fixed_version' => $fix,
            'fix_versions'  => [$fix],
            'manifest'      => $manifest,
        ]];
    }

    public function testRoundTripAndEnvelopeShape(): void
    {
        $path = $this->statePath();
        $s    = CloseState::load($path, '2026-10-18T10:00:00Z', 'o/r');
        $s->remember('125', CloseState::VERDICTS[0], [
            'key'     => CloseState::key(self::needs()),
            'detail'  => 'every requirement verified',
            'paths'   => ['a/package.json'],
            'cve'     => 'CVE-1',
            'package' => 'qs',
        ]);
        $s->save();

        $data = json_decode((string)file_get_contents($path), true);
        $this->assertSame(1, $data['schema']);
        $this->assertSame('o/r', $data['repo']);
        $this->assertSame('2026-10-18T10:00:00Z', $data['updated']);
        $this->assertArrayHasKey('125', $data['issues']);

        $s2      = CloseState::load($path, '2026-10-20T10:00:00Z', 'o/r', $corrupt);
        $this->assertFalse($corrupt);
        $entry   = $s2->get('125');
        $this->assertSame('fixed', $entry['verdict']);
        $this->assertSame('2026-10-18T10:00:00Z', $entry['checked_at']);
        $this->assertSame('2026-10-18T10:00:00Z', $entry['since']);
        $this->assertSame(['a/package.json'], $entry['paths']);
        $this->assertSame('CVE-1', $entry['cve']);
        $this->assertSame([], $s2->get('126'), 'an issue never verified reads as empty');
    }

    public function testMissingFileIsFreshAndUnreadableOneIsReported(): void
    {
        $path = $this->statePath();
        $f    = CloseState::load($path, '2026-10-20T10:00:00Z', '', $corrupt);
        $this->assertFalse($corrupt);
        $this->assertSame([], $f->get('7'));

        file_put_contents($path, '{"issues": "not even an object"');
        CloseState::load($path, '2026-10-20T10:00:00Z', '', $corrupt);
        $this->assertTrue($corrupt, 'a corrupt memory says so instead of failing the run');
    }

    public function testLoadDiscardsRowsThatAreNotIssueEntries(): void
    {
        $path = $this->statePath();
        file_put_contents($path, (string)json_encode([
            'schema'  => 1,
            'issues'  => ['7' => ['verdict' => 'fixed'], 'abc' => ['verdict' => 'fixed'], '9' => 'nope'],
        ]));
        $s = CloseState::load($path, 'now', '', $corrupt);
        $this->assertFalse($corrupt);
        $this->assertSame('fixed', $s->get('7')['verdict']);
        $this->assertSame([], $s->get('abc'));
        $this->assertSame([], $s->get('9'));
    }

    public function testEmptyMemorySavesAsAnObjectNotAnArray(): void
    {
        $path = $this->statePath();
        CloseState::load($path, 'now', 'o/r')->save();
        $this->assertStringContainsString('"issues": {}', (string)file_get_contents($path));
    }

    public function testSaveThroughANewlyCreatedDirectory(): void
    {
        $path = $this->scratchDir('deep') . '/nested/deeper/close-state.json';
        $s    = CloseState::load($path, '2026-10-20T10:00:00Z', 'o/r');
        $s->remember('5', 'fixed', ['key' => 'k']);
        $s->save();
        $this->assertFileExists($path);
    }

    public function testAnUnchangedVerdictKeepsItsAgeAndItsAnnotation(): void
    {
        $path = $this->statePath();
        $s    = CloseState::load($path, '2026-10-18T10:00:00Z', 'o/r');
        $s->remember('9', 'unverifiable', ['key' => 'k', 'why' => CloseState::TRANSITIVE_WHY]);
        $s->markAnnotated('9');
        $s->save();

        $s2 = CloseState::load($path, '2026-10-19T10:00:00Z', 'o/r');
        $s2->remember('9', 'unverifiable', ['key' => 'k', 'why' => CloseState::TRANSITIVE_WHY]);
        $again = $s2->get('9');
        $this->assertSame('2026-10-18T10:00:00Z', $again['since'], 're-verifying does not restart the age of a standing verdict');
        $this->assertSame('2026-10-19T10:00:00Z', $again['checked_at']);
        $this->assertSame('2026-10-18T10:00:00Z', $again['annotated_at'], 'the one-shot record survives re-verification');

        $s2->remember('9', 'fixed', ['key' => 'k2']);
        $turned = $s2->get('9');
        $this->assertSame('2026-10-19T10:00:00Z', $turned['since'], 'a changed verdict starts a new age');
        $this->assertArrayNotHasKey('annotated_at', $turned, 'a future unverifiable phase may be explained once more');
        $this->assertArrayNotHasKey('why', $turned, 'empty optionals are not stored');
    }

    public function testMarkAnnotatedIgnoresAnUnknownIssue(): void
    {
        $s = CloseState::load($this->statePath(), 'now', 'o/r');
        $s->markAnnotated('ghost');
        $this->assertSame([], $s->get('ghost'));
    }

    public function testRetainForgetsClosedIssuesAndAgedVerdictsButNotAnAnnotatedOne(): void
    {
        $now = '2026-10-20T12:00:00Z';
        $s   = CloseState::load($this->statePath(), $now);
        $this->put($s, '1', ['verdict' => 'fixed', 'checked_at' => '2026-10-18T12:00:00Z']);
        $this->put($s, '2', ['verdict' => 'fixed', 'checked_at' => '2026-10-18T12:00:00Z']);
        $this->put($s, '3', ['verdict' => 'unverifiable', 'checked_at' => '2026-09-19T12:00:00Z']);
        $this->put($s, '4', ['verdict' => 'unverifiable', 'checked_at' => '2025-01-01T12:00:00Z', 'annotated_at' => '2025-01-08T12:00:00Z']);
        $this->put($s, '5', ['verdict' => 'fixed', 'checked_at' => 'not a time']);
        $s->retain(['1', '3', '4', '5']);
        $this->assertNotSame([], $s->get('1'), 'a fresh verdict on an open issue is exactly what memory is for');
        $this->assertSame([], $s->get('2'), 'a closed issue is no longer anyone\'s question');
        $this->assertSame([], $s->get('3'), 'even a reusable verdict gets a month at most before a fresh look');
        $this->assertNotSame([], $s->get('4'), 'the memory of an annotation must outlive retention, or the comment would be written twice');
        $this->assertSame([], $s->get('5'), 'an unreadable age means no usable memory');
    }

    public function testOldestCheck(): void
    {
        $s = CloseState::load($this->statePath(), 'now');
        $this->assertSame('', $s->oldestCheck(), 'empty memory asks no git question');
        $this->put($s, '1', ['checked_at' => '2026-10-18T10:00:00Z']);
        $this->put($s, '2', ['checked_at' => '2026-10-16T09:00:00Z']);
        $this->put($s, '3', ['verdict' => 'fixed']);
        $this->assertSame('2026-10-16T09:00:00Z', $s->oldestCheck());
    }

    public function testRememberedHeadsAreDistinctAndSayWhichEntriesPredateThem(): void
    {
        $s = CloseState::load($this->statePath(), 'now');
        $this->assertSame([], $s->rememberedHeads(), 'nothing remembered, nothing to diff');
        $this->put($s, '1', ['head' => 'aaaa']);
        $this->put($s, '2', ['head' => 'bbbb']);
        $this->put($s, '3', ['head' => 'aaaa']);
        $this->assertSame(['aaaa', 'bbbb'], $s->rememberedHeads());
        $this->put($s, '4', ['checked_at' => 'now']); // an entry from before SHAs were recorded
        $this->assertContains('', $s->rememberedHeads(), 'the caller falls back to the date scan for these');
        $this->assertCount(3, $s->rememberedHeads(), 'still one answer per distinct state, not per entry');
    }

    public function testTheKeyFollowsTheRequirementsNotTheirArrayKeys(): void
    {
        $this->assertSame(CloseState::key(self::needs()), CloseState::key(self::needs()), 'the same requirements, the same identity');
        $this->assertNotSame(CloseState::key(self::needs()), CloseState::key(self::needs('qs', '6.15.3')), 'a new fix version invalidates');
        $this->assertNotSame(CloseState::key(self::needs()), CloseState::key(self::needs('lodash')), 'a different package was never verified by this verdict');
        $this->assertNotSame(
            CloseState::key(self::needs()),
            CloseState::key([[
                'ecosystem' => 'npm', 'package' => 'qs', 'fixed_version' => '6.15.2',
                'fix_versions' => ['6.14.0', '6.15.2'], 'manifest' => 'a/package.json',
            ]]),
            'a second fix branch changes the question'
        );
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function put(CloseState $s, string $num, array $entry): void
    {
        (function () use ($num, $entry): void {
            $this->issues[$num] = $entry;
        })->call($s);
    }

    /**
     * @return array<string, mixed>
     */
    private static function cacheable(string $verdict = 'fixed', string $why = ''): array
    {
        return [
            'verdict'    => $verdict,
            'key'        => CloseState::key(self::needs()),
            'checked_at' => '2026-10-18T10:00:00Z',
            'why'        => $why,
        ];
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string, 2: int|null, 3: bool, 4: bool, 5: bool, 6: string}>
     */
    public static function reuseRows(): array
    {
        $week     = CloseState::REUSE_WINDOW;
        $live     = 518400;                                        // six days
        $key      = CloseState::key(self::needs());
        $trans    = self::cacheable('unverifiable', CloseState::TRANSITIVE_WHY);
        return [
            'nothing remembered'              => [[], $key, $live, false, false, false, 'an issue never verified is verified now'],
            'verdict not a verdict'           => [['verdict' => 'solved', 'key' => $key], $key, $live, false, false, false, 'an unknown verdict fails toward re-verifying, never toward reuse'],
            'requirements moved'              => [self::cacheable(), 'another-key', $live, false, false, false, 'a different needs key invalidates the verdict'],
            'no key at all'                   => [['verdict' => 'fixed'], $key, $live, false, false, false, 'without an identity the verdict proves nothing'],
            'unreadable age'                  => [self::cacheable(), $key, null, false, false, false, 'a corrupt clock means a fresh look'],
            'a file changed'                  => [self::cacheable(), $key, $live, true, false, false, 'the verdict leaned on files someone edited since'],
            'fixed at exactly the window'     => [self::cacheable(), $key, $week, false, false, true, 'the week is inclusive'],
            'fixed past the window'           => [self::cacheable(), $key, $week + 1, false, false, false, 'a week is how long ordinary verdicts live'],
            'unresolved past the window'      => [self::cacheable('unresolved'), $key, $week + 1, false, false, false, 'a still-vulnerable verdict is re-checked on the ordinary clock'],
            'transitive, a month old'         => [$trans, $key, 2592000, false, false, true, 'this verdict can only change when a lockfile appears'],
            'transitive, lockfile appeared'   => [$trans, $key, 2592000, false, true, false, 'the cure arrived: re-verify against the lockfile'],
            'transitive, a file changed'      => [$trans, $key, 2592000, true, false, false, 'a manifest edit could declare the package directly'],
            'transitive, unreadable age'      => [$trans, $key, null, false, false, false, 'even the aggressive rule needs to read the clock'],
            'other unverifiable, a month old' => [self::cacheable('unverifiable', 'no fix known'), $key, 2592000, false, false, false, 'no-fix-known is re-checked on the ordinary clock'],
            'out of scope, inside the week'   => [self::cacheable('out-of-scope'), $key, $live, false, false, true, ''],
        ];
    }

    /**
     * The reuse decision as the pure predicate it is: age × requirements key ×
     * file changes × lockfile appearing.
     *
     * @param array<string, mixed> $entry
     */
    #[DataProvider('reuseRows')]
    public function testReuseVerdictIsADecisionTable(array $entry, string $needsKey, ?int $age, bool $pathChanged, bool $lockfileAppeared, bool $want, string $why): void
    {
        $this->assertSame($want, CloseState::reuseVerdict($entry, $needsKey, $age, $pathChanged, $lockfileAppeared), $why);
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: int|null, 2: bool, 3: string}>
     */
    public static function annotateRows(): array
    {
        $week  = CloseState::REUSE_WINDOW;
        $unver = ['verdict' => 'unverifiable', 'since' => 'x'];
        return [
            'nothing remembered'       => [[], 30 * 86400, false, 'never verified means no standing age'],
            'unreadable age'           => [$unver, null, false, 'a corrupt since is not a week of anything'],
            'fixed is not missing'     => [['verdict' => 'fixed'], $week + 1, false, 'a fixed verdict is on its way out, not waiting on anyone'],
            'unresolved is not missing' => [['verdict' => 'unresolved'], $week + 1, false, 'that one is waiting on a release, not on a lockfile'],
            'one week young'           => [$unver, $week, false, 'the window must actually pass'],
            'one week and a second old' => [$unver, $week + 1, true, ''],
            'already told'             => [['verdict' => 'unverifiable', 'annotated_at' => 'y'], $week + 1, false, 'the comment is once per phase, not once per run'],
        ];
    }

    /**
     * @param array<string, mixed> $entry
     */
    #[DataProvider('annotateRows')]
    public function testNeedsAnnotationIsOneShotPerUnverifiablePhase(array $entry, ?int $age, bool $want, string $why): void
    {
        $this->assertSame($want, CloseState::needsAnnotation($entry, $age), $why);
    }

    public function testVerdictFromMapsRememberedFieldsBack(): void
    {
        $this->assertSame(
            ['ok' => true, 'reason' => '', 'detail' => 'done', 'evidence' => 'table'],
            CloseState::verdictFrom(['verdict' => 'fixed', 'detail' => 'done', 'evidence' => 'table'])
        );
        $this->assertSame(
            ['ok' => false, 'reason' => 'unverifiable', 'detail' => 'no lockfile', 'evidence' => ''],
            CloseState::verdictFrom(['verdict' => 'unverifiable', 'detail' => 'no lockfile'])
        );
        $this->assertFalse(CloseState::verdictFrom([])['ok'], 'no memory never means fixed');
        $this->assertSame('out-of-scope', CloseState::verdictFrom(['verdict' => 'out-of-scope'])['reason']);
    }

    public function testResolveSharesOneVerificationAcrossIdenticalRequirements(): void
    {
        $calls  = 0;
        $verify = static function (array $needs) use (&$calls): array {
            $calls++;
            return ['ok' => true, 'reason' => '', 'detail' => "call {$calls}", 'evidence' => ''];
        };
        /** @var array<string, array{ok: bool, reason: string, detail: string, evidence: string}> $batch */
        $batch = [];
        [$first, $origin]   = CloseState::resolve(self::needs('a'), [], 0, false, false, $verify, $batch);
        [$twin, $twinOrigin] = CloseState::resolve(self::needs('a'), [], 0, false, false, $verify, $batch);
        $this->assertSame('verified', $origin);
        $this->assertSame('shared', $twinOrigin, 'the duplicate title shares the check, which is the whole amortisation');
        $this->assertSame(1, $calls, 'the verifier runs once per requirement list, not once per issue');
        $this->assertSame($first, $twin);

        [, $otherOrigin] = CloseState::resolve(self::needs('b'), [], 0, false, false, $verify, $batch);
        $this->assertSame('verified', $otherOrigin);
        $this->assertSame(2, $calls, 'different requirements are a different question');
    }

    public function testResolvePrefersMemoryOverTheVerifier(): void
    {
        $entry  = self::cacheable('fixed') + ['detail' => 'verified last week', 'evidence' => '|qs|'];
        $calls  = 0;
        $verify = static function (array $needs) use (&$calls): array {
            $calls++;
            return ['ok' => false, 'reason' => 'unresolved', 'detail' => '', 'evidence' => ''];
        };
        $batch  = [];
        [$verdict, $origin] = CloseState::resolve(self::needs(), $entry, 518400, false, false, $verify, $batch);
        $this->assertSame('cached', $origin);
        $this->assertSame(0, $calls);
        $this->assertTrue($verdict['ok'], 'the remembered fixed verdict closes the issue');
        $this->assertSame('|qs|', $verdict['evidence'], 'and brings its closing table along');
    }

    public function testResolveReverifiesWhenMemoryHasExpired(): void
    {
        $entry  = self::cacheable('fixed');
        $calls  = 0;
        $verify = static function (array $needs) use (&$calls): array {
            $calls++;
            return ['ok' => false, 'reason' => 'unresolved', 'detail' => '', 'evidence' => ''];
        };
        $batch  = [];
        [, $origin] = CloseState::resolve(self::needs(), $entry, 8 * 86400, false, false, $verify, $batch);
        $this->assertSame('verified', $origin);
        $this->assertSame(1, $calls, 'a verdict older than the window is a question asked again');
    }
}
