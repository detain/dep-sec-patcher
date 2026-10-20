<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\NotFixedReport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The "not fixed and why" diagnostic: notes land in the right bucket,
 * identical items collapse to a count, the report stays bounded, and the
 * console text keeps its documented shape.
 */
class NotFixedReportTest extends TestCase
{
    /**
     * @return array{package: string, ecosystem: string, version: string}
     */
    private static function item(string $package, string $version = '', string $ecosystem = 'npm'): array
    {
        return ['package' => $package, 'ecosystem' => $ecosystem, 'version' => $version];
    }

    /**
     * @return list<array{0: string, 1: string}>
     */
    public static function noteRows(): array
    {
        return [
            ['', 'other'],
            ['no valid fix: 6.15.2 is gone', 'no-valid-fix'],
            ['lodash needs a major upgrade to 5.0', 'needs-major'],
            ['manifest not found: a/package.json', 'manifest-missing'],
            ['cannot edit composer.lock', 'cannot-edit'],
            ['package not declared in a/package.json', 'not-declared'],
            ['qs is neither declared in a/package.json nor in its lockfile', 'not-declared'],
            ['workspace specifier ^2.0', 'not-declared'],
            ['no fixed version known', 'no-fix-yet'],
            ['would set qs to 6.15.2', 'would-set'],
            ['override written but lock still resolves braces@2.3.2', 'override-did-not-evict'],
            ['lock unreadable, not verified', 'lock-unreadable'],
            ['already satisfied: 6.15.2', 'other'],
            ['refused: pinned elsewhere', 'other'],
        ];
    }

    #[DataProvider('noteRows')]
    public function testEveryAutoFixNoteFindsItsBucket(string $note, string $want): void
    {
        $this->assertSame($want, NotFixedReport::noteReason($note));
    }

    public function testTheUnreadableLockHasItsPlaceInTheDatabaseOrder(): void
    {
        $this->assertContains('lock-unreadable', NotFixedReport::DATABASE_BUCKETS, 'a named bucket, not a castaway in "other"');
    }

    public function testAggregateCollapsesIdenticalItemsHighestFirst(): void
    {
        $bucket = NotFixedReport::aggregate([
            self::item('qs', '6.15.2'),
            self::item('qs', '6.15.2'),
            self::item('qs', '6.15.2'),
            self::item('lodash', ''),
            self::item('left-pad', '1.0.1'),
            self::item('left-pad', '1.0.1'),
        ]);
        $this->assertSame(6, $bucket['total'], 'the total counts records, not distinct packages');
        $this->assertSame(
            [['ecosystem' => 'npm', 'package' => 'qs', 'version' => '6.15.2', 'count' => 3],
             ['ecosystem' => 'npm', 'package' => 'left-pad', 'version' => '1.0.1', 'count' => 2],
             ['ecosystem' => 'npm', 'package' => 'lodash', 'version' => '', 'count' => 1]],
            $bucket['items']
        );
        $this->assertSame(0, $bucket['more']);
    }

    public function testAggregateIsBoundedAndReportsWhatItLeftOut(): void
    {
        $items = [];
        for ($i = 1; $i <= 12; $i++) {
            $items[] = self::item('pkg' . $i, '1.0.' . $i);
        }
        $bucket = NotFixedReport::aggregate($items, 10);
        $this->assertSame(12, $bucket['total']);
        $this->assertCount(10, $bucket['items']);
        $this->assertSame(2, $bucket['more']);
    }

    public function testBuildOrdersSectionsAndDropsEmptyBuckets(): void
    {
        $report = NotFixedReport::build(
            ['covered-by-open-PR' => [self::item('axios', '1.6.8')], 'no-fix-upstream' => [], 'needs-major' => [self::item('old', '')]],
            ['no-valid-fix' => [self::item('qs', '6.15.2'), self::item('qs', '6.15.2')]]
        );
        $this->assertSame(['dependabot_alerts', 'vuln_db_records'], array_keys($report));
        $this->assertSame(2, $report['dependabot_alerts']['total']);
        $this->assertSame(['needs-major', 'covered-by-open-PR'], array_keys($report['dependabot_alerts']['buckets']), 'the declared order holds and empty buckets are absent');
        $this->assertSame(2, $report['vuln_db_records']['total']);
        $this->assertSame(2, $report['vuln_db_records']['buckets']['no-valid-fix']['total'], 'collapsing happens inside the section');
    }

    public function testBuildPlacesUnlistedBucketsAfterTheKnownOnes(): void
    {
        $report = NotFixedReport::build(['a-brand-new-reason' => [self::item('x')]], []);
        $keys   = array_keys($report['dependabot_alerts']['buckets']);
        $this->assertSame('a-brand-new-reason', $keys[count($keys) - 1]);
    }

    public function testEmptyReportPrintsNothing(): void
    {
        $this->assertSame([], NotFixedReport::consoleLines(NotFixedReport::build([], [])));
    }

    public function testConsoleKeepsItsDocumentedShape(): void
    {
        $report = NotFixedReport::build(
            ['no-fix-upstream' => [self::item('lodash', ''), self::item('lodash', ''), self::item('qs', '')]],
            ['needs-major' => [self::item('tomcat-embed-core', '11.0.8', 'maven')]]
        );
        $this->assertSame([
            'not fixed and why:',
            '  open Dependabot alerts (3): no-fix-upstream=3',
            '    no-fix-upstream: npm lodash x2, npm qs x1',
            '  pending database records (1): needs-major=1',
            '    needs-major: maven tomcat-embed-core 11.0.8 x1',
        ], NotFixedReport::consoleLines($report));
    }

    public function testConsoleNamesTheVersionWhenThereIsOne(): void
    {
        $lines = NotFixedReport::consoleLines(NotFixedReport::build(
            ['covered-by-open-PR' => [self::item('axios', '1.6.8')]],
            []
        ));
        $this->assertSame('    covered-by-open-PR: npm axios 1.6.8 x1', $lines[2]);
    }

    public function testConsoleTruncatesABucketAndSaysHowMuchMore(): void
    {
        $items = [];
        foreach (['a', 'b', 'c', 'd', 'e'] as $name) {
            $items[] = self::item($name, '1.0');
        }
        $lines = NotFixedReport::consoleLines(NotFixedReport::build(['needs-major' => $items], []));
        $this->assertSame('    needs-major: npm a 1.0 x1, npm b 1.0 x1, npm c 1.0 x1 (+2 more)', $lines[2], 'the console shows three names per bucket, the JSON shows ten');
    }

    public function testJsonIsSerialisableThroughTheSharedEncoder(): void
    {
        $report = NotFixedReport::build(['no-fix-upstream' => [self::item('x')]], ['other' => [self::item('y', '', 'pip')]]);
        $json   = \Detain\DepSecPatcher\JsonFile::encode($report);
        $decoded = json_decode($json, true);
        $this->assertSame(1, $decoded['dependabot_alerts']['total']);
        $this->assertSame('pip', $decoded['vuln_db_records']['buckets']['other']['items'][0]['ecosystem']);
    }
}
