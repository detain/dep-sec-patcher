<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\GitUrl;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Remote URL parsing: which TARGETs are URLs, which GitHub repository a
 * remote points at, and keeping credentials out of output.
 */
class GitUrlTest extends TestCase
{
    /**
     * @return array<string, array{string, ?string}>
     */
    public static function githubProvider(): array
    {
        return [
            'scp ssh with .git'     => ['git@github.com:detain/dep-sec-patcher.git', 'detain/dep-sec-patcher'],
            'scp ssh without .git'  => ['git@github.com:detain/dep-sec-patcher', 'detain/dep-sec-patcher'],
            'scp without user'      => ['github.com:octo-org/my.repo.git', 'octo-org/my.repo'],
            'ssh url'               => ['ssh://git@github.com/owner/name.git', 'owner/name'],
            'ssh url with port'     => ['ssh://git@github.com:22/owner/name', 'owner/name'],
            'https with .git'       => ['https://github.com/owner/name.git', 'owner/name'],
            'https without .git'    => ['https://github.com/owner/name', 'owner/name'],
            'https trailing slash'  => ['https://github.com/owner/name/', 'owner/name'],
            'https with token'      => ['https://x-access-token:abc@github.com/owner/name.git', 'owner/name'],
            'https www'             => ['https://www.github.com/owner/name', 'owner/name'],
            'uppercase host'        => ['https://GitHub.com/Owner/Name.git', 'Owner/Name'],
            'git protocol'          => ['git://github.com/owner/name.git', 'owner/name'],
            'dots and underscores'  => ['git@github.com:a-b/c_d.e-f.git', 'a-b/c_d.e-f'],
            'gitlab'                => ['git@gitlab.com:owner/name.git', null],
            'bitbucket https'       => ['https://bitbucket.org/owner/name.git', null],
            'lookalike host'        => ['https://github.com.evil.example/owner/name', null],
            'github enterprise'     => ['https://github.example.com/owner/name', null],
            'deeper path'           => ['https://github.com/owner/name/tree/main', null],
            'file url'              => ['file:///srv/git/name.git', null],
            'local path'            => ['/srv/git/name', null],
            'empty'                 => ['', null],
        ];
    }

    #[DataProvider('githubProvider')]
    public function testGithubRepo(string $url, ?string $expected): void
    {
        $this->assertSame($expected, GitUrl::githubRepo($url));
    }

    public function testIsUrl(): void
    {
        foreach (['https://github.com/o/r', 'ssh://git@host/x', 'git@github.com:o/r.git', 'file:///tmp/x.git', 'host.example:path/repo'] as $url) {
            $this->assertTrue(GitUrl::isUrl($url), $url);
        }
        foreach (['some/dir', './dir', '/abs/path', 'C:dir', 'owner/name', 'dir'] as $path) {
            $this->assertFalse(GitUrl::isUrl($path), $path);
        }
    }

    public function testShorthand(): void
    {
        $this->assertTrue(GitUrl::isGithubShorthand('detain/dep-sec-patcher'));
        $this->assertTrue(GitUrl::isGithubShorthand('a/b.c_d'));
        $this->assertFalse(GitUrl::isGithubShorthand('a/b/c'));
        $this->assertFalse(GitUrl::isGithubShorthand('-a/b'), 'owners cannot start with a hyphen');
        $this->assertFalse(GitUrl::isGithubShorthand('a/..'));
        $this->assertFalse(GitUrl::isGithubShorthand('justname'));
        $this->assertSame('https://github.com/o/r.git', GitUrl::fromShorthand('o/r'));
        $this->assertSame('https://github.com/o/r.git', GitUrl::fromShorthand('o/r.git'));
    }

    public function testRedact(): void
    {
        $this->assertSame('https://***@github.com/o/r.git', GitUrl::redact('https://x-access-token:ghs_secret@github.com/o/r.git'));
        $this->assertSame('https://***@github.com/o/r', GitUrl::redact('https://ghp_tokenasuser@github.com/o/r'));
        $this->assertSame('ssh://git:***@host/x', GitUrl::redact('ssh://git:pw@host/x'));
        $this->assertSame('ssh://git@host/x', GitUrl::redact('ssh://git@host/x'), 'a bare ssh user is not a secret');
        $this->assertSame('git@github.com:o/r.git', GitUrl::redact('git@github.com:o/r.git'));
        $this->assertSame('--quiet', GitUrl::redact('--quiet'));
    }

    public function testNormalizeAndBasename(): void
    {
        $this->assertSame('https://github.com/o/r', GitUrl::normalize('https://user:tok@GitHub.COM/o/r.git/'));
        $this->assertSame(GitUrl::normalize('https://github.com/o/r'), GitUrl::normalize('https://GITHUB.com/o/r.git'));
        $this->assertSame('file:///srv/x', GitUrl::normalize('file:///srv/x.git'));
        $this->assertSame('r', GitUrl::basename('git@github.com:o/r.git'));
        $this->assertSame('x', GitUrl::basename('file:///srv/x.git/'));
    }
}
