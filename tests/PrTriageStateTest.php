<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\PrTriageState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The per-repository memory of PR triage: what survives a round trip, what
 * pruning forgets, and the pure throttle arithmetic that decides whether a
 * conflicting PR gets another rebase request, must wait, or is left alone.
 */
class PrTriageStateTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    private function statePath(string $name = 'triage-state.json'): string
    {
        return $this->scratchDir('triage') . '/' . $name;
    }

    public function testRoundTripPreservesBookkeepingAndMergesFields(): void
    {
        $path = $this->statePath();
        $s1   = PrTriageState::load($path, '2026-10-18T10:00:00Z', 'o/r');
        $s1->record('7475', ['outcome' => 'merged', 'merge_commit' => 'abc123']);
        $s1->save();

        $s2      = PrTriageState::load($path, '2026-10-20T10:00:00Z', 'o/r', $corrupt);
        $this->assertFalse($corrupt);
        $entry   = $s2->get('7475');
        $this->assertSame('2026-10-18T10:00:00Z', $entry['first_seen']);
        $this->assertSame('2026-10-18T10:00:00Z', $entry['last_seen'], 'loading does not count as a sighting');
        $this->assertSame(1, $entry['sightings']);
        $this->assertSame('abc123', $entry['merge_commit']);

        $s2->record('7475', ['outcome' => 'rebase-requested']);
        $s2->save();
        $entry = PrTriageState::load($path, 'x', 'o/r')->get('7475');
        $this->assertSame('2026-10-18T10:00:00Z', $entry['first_seen'], 'a re-sighting keeps the first');
        $this->assertSame('2026-10-20T10:00:00Z', $entry['last_seen']);
        $this->assertSame(2, $entry['sightings']);
        $this->assertSame('rebase-requested', $entry['outcome'], 'the newest verdict wins');
        $this->assertSame('abc123', $entry['merge_commit'], 'fields an earlier pass left survive');
    }

    public function testFileShapeIsTheDocumentedEnvelope(): void
    {
        $path = $this->statePath();
        $s    = PrTriageState::load($path, '2026-10-20T10:00:00Z', 'o/r');
        $s->record('2878', ['outcome' => 'superseded-closed']);
        $s->save();
        $data = json_decode((string)file_get_contents($path), true);
        $this->assertSame(1, $data['schema']);
        $this->assertSame('o/r', $data['repo']);
        $this->assertSame('2026-10-20T10:00:00Z', $data['updated']);
        $this->assertArrayHasKey('2878', $data['prs']);
    }

    public function testUnknownPrReadsAsEmpty(): void
    {
        $this->assertSame([], PrTriageState::load($this->statePath(), 'now')->get('1'));
    }

    public function testMissingFileIsFreshAndUnreadableOneIsReported(): void
    {
        $path = $this->statePath();
        $f    = PrTriageState::load($path, '2026-10-20T10:00:00Z', '', $corrupt);
        $this->assertFalse($corrupt);
        $this->assertSame([], $f->get('7'));

        file_put_contents($path, '{"prs": "not even an object"');
        PrTriageState::load($path, '2026-10-20T10:00:00Z', '', $corrupt);
        $this->assertTrue($corrupt, 'a corrupt memory says so instead of failing the run');
    }

    public function testLoadDiscardsRowsThatAreNotPrEntries(): void
    {
        $path = $this->statePath();
        file_put_contents($path, (string)json_encode([
            'schema' => 1,
            'prs'    => ['7' => ['outcome' => 'merged'], 'abc' => ['outcome' => 'merged'], '9' => 'nope'],
        ]));
        $s = PrTriageState::load($path, 'now', '', $corrupt);
        $this->assertFalse($corrupt);
        $this->assertSame('merged', $s->get('7')['outcome']);
        $this->assertSame([], $s->get('abc'));
        $this->assertSame([], $s->get('9'));
    }

    public function testSaveThroughANewlyCreatedDirectory(): void
    {
        $path = $this->scratchDir('deep') . '/nested/deeper/triage-state.json';
        $s    = PrTriageState::load($path, '2026-10-20T10:00:00Z', 'o/r');
        $s->record('5', ['outcome' => 'merged']);
        $s->save();
        $this->assertFileExists($path);
    }

    public function testRetainKeepsOpenAndFreshTerminalEntriesAndForgetsTheRest(): void
    {
        $now     = '2026-10-20T12:00:00Z';
        $recent  = '2026-10-18T12:00:00Z';
        $s       = PrTriageState::load($this->statePath(), $now);
        $this->seed($s, '1', 'merged', $recent);
        $this->seed($s, '2', 'blocked-ci', $recent);
        $this->seed($s, '3', 'auto-merge', $recent);
        $this->seed($s, '6', 'needs-major', $recent);
        $s->retain(['6']);
        $this->assertSame('merged', $s->get('1')['outcome'], 'the log of what was done survives a while');
        $this->assertSame([], $s->get('2'), 'a vanished PR that only waited starts fresh if it returns');
        $this->assertNotSame([], $s->get('3'), 'auto-merge is a final verdict too');
        $this->assertSame('needs-major', $s->get('6')['outcome'], 'open PRs are never pruned');
    }

    /**
     * Record a sighting, then wind its last_seen back to $lastSeen.
     */
    private function seed(PrTriageState $s, string $num, string $outcome, string $lastSeen): void
    {
        $s->record($num, ['outcome' => $outcome]);
        (function () use ($num, $lastSeen): void {
            $this->prs[$num]['last_seen'] = $lastSeen;
        })->call($s);
    }

    public function testRetainDecaysTerminalVerdictsPastTheWindow(): void
    {
        $now = '2026-10-20T12:00:00Z';
        $s   = PrTriageState::load($this->statePath(), $now);
        $this->seed($s, '1', 'merged', '2026-09-01T12:00:00Z');
        $this->seed($s, '2', 'merged', '2026-10-18T12:00:00Z');
        $s->retain([]);
        $this->assertSame([], $s->get('1'), 'a month-old verdict is no longer worth keeping');
        $this->assertNotSame([], $s->get('2'));
    }

    /**
     * @return list<array{0: int, 1: int, 2: string}>
     */
    public static function throttleRows(): array
    {
        $day = PrTriageState::NUDGE_INTERVAL;
        return [
            [1, 3600, 'wait'],                       // asked today: no second comment yet
            [1, $day, 'nudge'],                      // exactly a day: ask again
            [1, $day - 1, 'wait'],
            [2, $day * 3, 'nudge'],                  // under the maximum: keep pace at most daily
            [3, $day, 'stop'],                       // asked the maximum: leave it alone
            [3, $day - 1, 'wait'],                   // but not before the interval even to stop
            [9, $day * 30, 'stop'],                  // history from an older tool version: still stops
        ];
    }

    #[DataProvider('throttleRows')]
    public function testRebaseActionThrottlesToADailyNudgeOfAtMostThree(int $requests, int $since, string $want): void
    {
        $this->assertSame($want, PrTriageState::rebaseAction($requests, $since));
    }

    public function testMaximumIsThreeRequestsInAll(): void
    {
        $this->assertSame(3, PrTriageState::MAX_REBASE_REQUESTS);
    }

    public function testSecondsSince(): void
    {
        $this->assertSame(90061, PrTriageState::secondsSince('2026-10-18T10:00:00Z', '2026-10-19T11:01:01Z'));
        $this->assertSame(0, PrTriageState::secondsSince('2026-10-20T12:00:00Z', '2026-10-20T10:00:00Z'),
            'a clock backwards never reads as negative age');
        $this->assertNull(PrTriageState::secondsSince('', '2026-10-20T10:00:00Z'));
        $this->assertNull(PrTriageState::secondsSince('2026-10-18T10:00:00Z', 'xx:xx'));
        $this->assertNull(PrTriageState::secondsSince('9999-99-99', '2026-10-20T10:00:00Z'));
    }
}
