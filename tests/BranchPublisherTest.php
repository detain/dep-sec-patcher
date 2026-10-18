<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\BranchPublisher;
use PHPUnit\Framework\TestCase;

/**
 * --push: commit to a new branch, push it, and leave the tree as it started.
 */
class BranchPublisherTest extends TestCase
{
    use Fixtures;

    protected function setUp(): void
    {
        $this->hermeticGit();
    }

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testPublishesChangesToANewBranch(): void
    {
        $remote = $this->makeRemote(['package.json' => "{\"dependencies\": {\"qs\": \"^6.11.0\"}}\n"]);
        [$console, $runner, $out] = $this->quietRunner();
        $publisher = new BranchPublisher($runner, $console, $remote['work']);

        $this->assertTrue($publisher->isClean());
        file_put_contents($remote['work'] . '/package.json', "{\"dependencies\": {\"qs\": \"^6.15.2\"}}\n");
        file_put_contents($remote['work'] . '/package-lock.json', "{}\n");
        $this->assertFalse($publisher->isClean());

        $this->assertSame(['package.json', 'package-lock.json'], $publisher->changedFiles());
        $this->assertSame('main', $publisher->currentBranch());

        $this->assertTrue($publisher->publish('dep-sec-patcher/test', "fix qs\n\nbody", 'main'));
        $this->assertSame('main', $this->git($remote['work'], ['rev-parse', '--abbrev-ref', 'HEAD']), 'back on the starting branch');
        $this->assertStringContainsString('^6.11.0', (string)file_get_contents($remote['work'] . '/package.json'));
        $this->assertSame('', $this->git($remote['work'], ['status', '--porcelain']));

        $files = $this->git($remote['bare'], ['show', '--name-only', '--format=%s', 'dep-sec-patcher/test']);
        $this->assertSame("fix qs\n\npackage-lock.json\npackage.json", $files, 'the branch reached the remote with both files');
        $this->assertStringContainsString('pushed branch dep-sec-patcher/test to origin', self::readStream($out));
    }

    public function testBranchIsRebasedOntoWhatOriginGainedDuringTheRun(): void
    {
        $remote = $this->makeRemote(['a.txt' => "a\n", 'b.txt' => "b\n"]);
        $other  = $this->cloneOf($remote);
        [$console, $runner, $out] = $this->quietRunner();
        $publisher = new BranchPublisher($runner, $console, $remote['work']);

        file_put_contents($remote['work'] . '/a.txt', "a2\n");
        $this->commitAndPush($other, 'b.txt', "b2\n");

        $this->assertTrue($publisher->publish('topic', 'm', 'main'));
        $this->assertStringContainsString('rebasing the commit onto it', self::readStream($out));
        $this->assertSame("a2\nb2", $this->git($remote['bare'], ['show', 'topic:a.txt']) . "\n" . $this->git($remote['bare'], ['show', 'topic:b.txt']));
        $this->assertSame('main', $this->git($remote['work'], ['rev-parse', '--abbrev-ref', 'HEAD']));
    }

    public function testDirectPushLandsOnTheCheckedOutBranch(): void
    {
        $remote = $this->makeRemote(['a.txt' => "a\n", 'b.txt' => "b\n"]);
        $other  = $this->cloneOf($remote);
        [$console, $runner, $out] = $this->quietRunner();
        $publisher = new BranchPublisher($runner, $console, $remote['work']);

        file_put_contents($remote['work'] . '/a.txt', "a2\n");
        // origin moves on during the run: the commit is rebased onto it
        $this->commitAndPush($other, 'b.txt', "b2\n");

        $this->assertSame('pushed', $publisher->publishDirect("direct\n\nbody", 'fallback'));
        $this->assertStringContainsString('pushed the changes straight to main on origin', self::readStream($out));
        $this->assertSame('direct', $this->git($remote['bare'], ['log', '-1', '--format=%s', 'main']));
        $this->assertSame('a2', $this->git($remote['bare'], ['show', 'main:a.txt']));
        $this->assertSame('b2', $this->git($remote['bare'], ['show', 'main:b.txt']));
        $this->assertSame('', $this->git($remote['bare'], ['branch', '--list', 'fallback']));
        $this->assertSame('', $this->git($remote['work'], ['status', '--porcelain']));
    }

    public function testDirectPushConflictFallsBackToABranch(): void
    {
        $remote = $this->makeRemote(['a.txt' => "a\n"]);
        $other  = $this->cloneOf($remote);
        [$console, $runner, $out] = $this->quietRunner();
        $publisher = new BranchPublisher($runner, $console, $remote['work']);
        $start     = $this->git($remote['work'], ['rev-parse', 'HEAD']);

        file_put_contents($remote['work'] . '/a.txt', "ours\n");
        $this->commitAndPush($other, 'a.txt', "theirs\n");

        $this->assertSame('fallback', $publisher->publishDirect('m', 'sec/fallback'));
        $log = self::readStream($out);
        $this->assertStringContainsString("conflict with what was merged into origin's main", $log);
        $this->assertStringContainsString('pushed branch sec/fallback instead', $log);
        $this->assertSame('ours', $this->git($remote['bare'], ['show', 'sec/fallback:a.txt']));
        $this->assertSame('theirs', $this->git($remote['bare'], ['show', 'main:a.txt']), 'main on origin untouched');
        $this->assertSame($start, $this->git($remote['work'], ['rev-parse', 'main']), 'local main put back where it started');
        $this->assertSame('', $this->git($remote['work'], ['status', '--porcelain']));
    }

    public function testDirectPushRefusesADetachedHead(): void
    {
        $remote = $this->makeRemote();
        $this->git($remote['work'], ['checkout', '--quiet', '--detach']);
        file_put_contents($remote['work'] . '/README.md', "changed\n");
        [$console, $runner, $out] = $this->quietRunner();
        $this->assertSame('', (new BranchPublisher($runner, $console, $remote['work']))->publishDirect('m', 'f'));
        $this->assertStringContainsString('HEAD is detached', self::readStream($out));
    }

    public function testSyncFastForwardsToOrigin(): void
    {
        $remote = $this->makeRemote(['a.txt' => "a\n"]);
        $other  = $this->cloneOf($remote);
        $this->commitAndPush($other, 'a.txt', "merged by a bot\n");
        [$console, $runner] = $this->quietRunner();
        $this->assertTrue((new BranchPublisher($runner, $console, $remote['work']))->syncWithOrigin('main'));
        $this->assertSame("merged by a bot\n", file_get_contents($remote['work'] . '/a.txt'));
    }

    public function testNothingToPublish(): void
    {
        $remote = $this->makeRemote();
        [$console, $runner, $out] = $this->quietRunner();
        $this->assertFalse((new BranchPublisher($runner, $console, $remote['work']))->publish('b', 'm'));
        $this->assertStringContainsString('nothing changed', self::readStream($out));
        $this->assertSame('', $this->git($remote['bare'], ['branch', '--list', 'b']));
    }

    public function testPushFailureStillRestoresTheBranch(): void
    {
        $remote = $this->makeRemote();
        $this->git($remote['work'], ['remote', 'set-url', 'origin', '/nonexistent/remote.git']);
        [$console, $runner, $out] = $this->quietRunner();
        file_put_contents($remote['work'] . '/README.md', "changed\n");

        $this->assertFalse((new BranchPublisher($runner, $console, $remote['work']))->publish('topic', 'm'));
        $this->assertStringContainsString('push: push topic failed', self::readStream($out));
        $this->assertSame('main', $this->git($remote['work'], ['rev-parse', '--abbrev-ref', 'HEAD']));
        $this->assertSame('changed', $this->git($remote['work'], ['show', 'topic:README.md']), 'the commit is kept locally');
    }

    public function testNotAWorkTree(): void
    {
        [$console, $runner] = $this->quietRunner();
        $this->assertNull((new BranchPublisher($runner, $console, $this->scratchDir('plain')))->isClean());
    }

    public function testDefaultBranchName(): void
    {
        $this->assertSame('dep-sec-patcher/20260102-030405', BranchPublisher::defaultBranch('2026-01-02T03:04:05Z'));
    }

    /**
     * A second clone of the remote, standing in for someone else pushing.
     *
     * @param array{bare: string, work: string, url: string} $remote
     */
    private function cloneOf(array $remote): string
    {
        $dir = $this->scratchDir('other');
        $this->git($dir, ['clone', '--quiet', $remote['bare'], $dir . '/w']);
        return $dir . '/w';
    }

    private function commitAndPush(string $work, string $file, string $content): void
    {
        file_put_contents($work . '/' . $file, $content);
        $this->git($work, ['commit', '--quiet', '-am', "change {$file}"]);
        $this->git($work, ['push', '--quiet', 'origin', 'main']);
    }
}
