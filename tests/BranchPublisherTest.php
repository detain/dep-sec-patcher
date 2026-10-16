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

        $this->assertTrue($publisher->publish('dep-sec-patcher/test', "fix qs\n\nbody", 'o/r'));
        $this->assertSame('main', $this->git($remote['work'], ['rev-parse', '--abbrev-ref', 'HEAD']), 'back on the starting branch');
        $this->assertStringContainsString('^6.11.0', (string)file_get_contents($remote['work'] . '/package.json'));
        $this->assertSame('', $this->git($remote['work'], ['status', '--porcelain']));

        $files = $this->git($remote['bare'], ['show', '--name-only', '--format=%s', 'dep-sec-patcher/test']);
        $this->assertSame("fix qs\n\npackage-lock.json\npackage.json", $files, 'the branch reached the remote with both files');
        $this->assertStringContainsString('gh pr create --repo o/r --head dep-sec-patcher/test', self::readStream($out));
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
}
