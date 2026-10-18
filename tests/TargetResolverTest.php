<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResolver;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * TARGET resolution and the cache clone of a remote. A local bare repository
 * stands in for the remote, so nothing touches the network.
 */
class TargetResolverTest extends TestCase
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

    private function resolver(): TargetResolver
    {
        [$console, $runner] = $this->quietRunner();
        return new TargetResolver($runner, $console, 120);
    }

    public function testClassify(): void
    {
        $cwd = $this->scratchDir('classify');
        mkdir($cwd . '/owner/name', 0775, true);

        $this->assertSame(['kind' => 'local', 'path' => $cwd, 'url' => ''], TargetResolver::classify('', $cwd), 'default: cwd');
        $this->assertSame('local', TargetResolver::classify('owner/name', $cwd)['kind'], 'an existing directory wins over the shorthand');
        $this->assertSame('local', TargetResolver::classify($cwd, '/')['kind']);
        $this->assertSame(
            ['kind' => 'remote', 'path' => '', 'url' => 'https://github.com/detain/dep-sec-patcher.git'],
            TargetResolver::classify('detain/dep-sec-patcher', $cwd)
        );
        $this->assertSame(
            ['kind' => 'remote', 'path' => '', 'url' => 'git@github.com:o/r.git'],
            TargetResolver::classify('git@github.com:o/r.git', $cwd)
        );
        $this->assertSame('remote', TargetResolver::classify('file:///srv/x.git', $cwd)['kind']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('target not found: no/such/dir');
        TargetResolver::classify('no/such/dir', $cwd);
    }

    public function testLocalRootRejectsSymlinksAndFiles(): void
    {
        $dir = $this->scratchDir('local');
        mkdir($dir . '/real');
        symlink($dir . '/real', $dir . '/link');
        file_put_contents($dir . '/file', 'x');
        $this->assertSame($dir . '/real', TargetResolver::localRoot($dir . '/real/'));
        foreach (['link' => 'must not be a symlink', 'file' => 'not a directory'] as $name => $message) {
            try {
                TargetResolver::localRoot($dir . '/' . $name);
                $this->fail("{$name} accepted");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
            }
        }
    }

    public function testCheckSubdir(): void
    {
        $root = $this->scratchDir('subdir');
        mkdir($root . '/a/b', 0775, true);
        mkdir($root . '/outside');
        symlink($root . '/outside', $root . '/a/escape');
        $this->assertSame('', TargetResolver::checkSubdir($root, ''));
        $this->assertSame('a/b', TargetResolver::checkSubdir($root, 'a/b'));
        $this->assertSame('outside', TargetResolver::checkSubdir($root, 'a/escape'), 'a symlink inside the root resolves to its real place');

        $other = $this->scratchDir('elsewhere');
        symlink($other, $root . '/away');
        foreach (['missing' => 'not found', 'away' => 'must stay inside'] as $sub => $message) {
            try {
                TargetResolver::checkSubdir($root, $sub);
                $this->fail("{$sub} accepted");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
            }
        }
    }

    public function testOriginRepoOfLocalCheckout(): void
    {
        $remote = $this->makeRemote();
        $r      = $this->resolver();
        $this->assertSame('', $r->originRepo($remote['work']), 'origin is a local path, not GitHub');

        $this->git($remote['work'], ['remote', 'set-url', 'origin', 'git@github.com:Some-Org/some.repo.git']);
        $this->assertSame('Some-Org/some.repo', $r->originRepo($remote['work']));
        $this->git($remote['work'], ['remote', 'set-url', 'origin', 'https://gitlab.com/o/r.git']);
        $this->assertSame('', $r->originRepo($remote['work']), 'not on github.com');

        mkdir($remote['work'] . '/sub');
        $this->assertSame('', $r->originRepo($remote['work'] . '/sub'), 'only the checkout root reads origin');
        $this->assertSame($remote['work'], $r->gitTopLevel($remote['work'] . '/sub'));
        $this->assertSame('', $r->gitTopLevel($this->scratchDir('plain')));
    }

    public function testCloneThenRefresh(): void
    {
        $remote  = $this->makeRemote(['README.md' => "v1\n", 'pkg/package.json' => "{}\n"]);
        $workdir = $this->scratchDir('state') . '/checkout';
        $r       = $this->resolver();

        $this->assertSame('main', $r->checkout($remote['url'], $workdir));
        $this->assertSame("v1\n", file_get_contents($workdir . '/README.md'));
        $this->assertFileExists($workdir . '/.git/' . TargetResolver::CLONE_MARKER);

        // The remote moves on; leftovers from an earlier run are discarded
        file_put_contents($remote['work'] . '/README.md', "v2\n");
        $this->git($remote['work'], ['commit', '--quiet', '-am', 'second']);
        $this->git($remote['work'], ['push', '--quiet']);
        file_put_contents($workdir . '/pkg/package.json', "{\"dirty\": true}\n");
        file_put_contents($workdir . '/untracked.txt', 'x');
        mkdir($workdir . '/pkg/node_modules');

        $this->assertSame('main', $r->checkout($remote['url'], $workdir));
        $this->assertSame("v2\n", file_get_contents($workdir . '/README.md'));
        $this->assertSame("{}\n", file_get_contents($workdir . '/pkg/package.json'));
        $this->assertFileDoesNotExist($workdir . '/untracked.txt');
        $this->assertDirectoryDoesNotExist($workdir . '/pkg/node_modules');
        $this->assertSame('', $this->git($workdir, ['status', '--porcelain', '--ignored']), 'pristine');
    }

    public function testFollowsDefaultBranchRename(): void
    {
        $remote  = $this->makeRemote();
        $workdir = $this->scratchDir('state') . '/checkout';
        $r       = $this->resolver();
        $r->checkout($remote['url'], $workdir);

        $this->git($remote['bare'], ['branch', '-m', 'main', 'trunk']);
        $this->git($remote['bare'], ['symbolic-ref', 'HEAD', 'refs/heads/trunk']);
        $this->assertSame('trunk', $r->checkout($remote['url'], $workdir));
    }

    public function testRefusesForeignWorkdir(): void
    {
        $remote  = $this->makeRemote();
        $workdir = $this->scratchDir('mine');
        file_put_contents($workdir . '/precious.txt', 'do not delete');

        try {
            $this->resolver()->checkout($remote['url'], $workdir);
            $this->fail('a directory it did not create was reused');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('not a clone made by dep-sec-patcher', $e->getMessage());
        }
        $this->assertSame('do not delete', file_get_contents($workdir . '/precious.txt'));
    }

    public function testCloneFailureIsReported(): void
    {
        $workdir = $this->scratchDir('state') . '/checkout';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('git clone file:///nonexistent/repo.git failed');
        $this->resolver()->checkout('file:///nonexistent/repo.git', $workdir);
    }

    public function testEmptyRemoteHasNoDefaultBranch(): void
    {
        $base = $this->scratchDir('empty');
        $this->git($base, ['init', '--quiet', '--bare', 'e.git']);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('has no default branch');
        $this->resolver()->checkout('file://' . $base . '/e.git', $base . '/checkout');
    }

    public function testGitNeverPrompts(): void
    {
        $env = TargetResolver::gitEnv();
        $this->assertSame('0', $env['GIT_TERMINAL_PROMPT']);
    }

    public function testGitUsesTheGhTokenForGithubHttps(): void
    {
        $this->setEnv('GH_TOKEN', null);
        $this->setEnv('GITHUB_TOKEN', null);
        $this->assertSame([], TargetResolver::gitOptions(), 'no token: the configured credential helpers apply');

        $this->setEnv('GH_TOKEN', 'ghp_test');
        if (!ProcessRunner::has('gh')) {
            $this->assertSame([], TargetResolver::gitOptions());
            return;
        }
        $this->assertSame(
            ['-c', 'credential.https://github.com.helper=', '-c', 'credential.https://github.com.helper=!gh auth git-credential'],
            TargetResolver::gitOptions()
        );
    }
}
