<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\StatePaths;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * Slug and state-directory derivation.
 */
class StatePathsTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testSlugFromGithubRepo(): void
    {
        $this->assertSame('detain__dep-sec-patcher', StatePaths::slug('detain/dep-sec-patcher', '/ignored'));
        $this->assertSame('owner__my.repo', StatePaths::slug('Owner/My.Repo', '/ignored'), 'GitHub names are case-insensitive');
    }

    public function testSlugFromIdentityHash(): void
    {
        $a = StatePaths::slug('', '/srv/projects/My App');
        $this->assertMatchesRegularExpression('/^my-app-[0-9a-f]{8}$/', $a);
        $this->assertSame($a, StatePaths::slug('', '/srv/projects/My App'), 'stable');
        $this->assertNotSame($a, StatePaths::slug('', '/other/My App'), 'same name elsewhere is a different target');
        $this->assertSame('x-' . substr(sha1('file:///srv/x'), 0, 8), StatePaths::slug('', 'file:///srv/x', 'x'));
        $this->assertMatchesRegularExpression('/^target-[0-9a-f]{8}$/', StatePaths::slug('', '/'));
    }

    public function testBaseDir(): void
    {
        $this->assertSame('/xdg/state/dep-sec-patcher', StatePaths::baseDir(['XDG_STATE_HOME' => '/xdg/state/', 'HOME' => '/home/u']));
        $this->assertSame('/home/u/.local/state/dep-sec-patcher', StatePaths::baseDir(['HOME' => '/home/u']));
        $this->assertSame('/home/u/.local/state/dep-sec-patcher', StatePaths::baseDir(['XDG_STATE_HOME' => 'relative', 'HOME' => '/home/u']), 'relative XDG_STATE_HOME is ignored');
        $this->expectException(InvalidArgumentException::class);
        StatePaths::baseDir([]);
    }

    public function testResolveDefaultsAndOverrides(): void
    {
        $env = ['XDG_STATE_HOME' => '/xdg'];
        $s   = StatePaths::resolve(Options::parse([], []), 'o__r', $env, '/cwd');
        $this->assertSame('/xdg/dep-sec-patcher/o__r', $s->stateDir);
        $this->assertSame('/xdg/dep-sec-patcher/vulns/o__r.json', $s->vulnDb, 'outside the per-target directory');
        $this->assertSame('/xdg/dep-sec-patcher/o__r/vulns.json', $s->legacyVulnDb);
        $this->assertSame('/xdg/dep-sec-patcher/o__r/reports', $s->reportDir);
        $this->assertSame('/xdg/dep-sec-patcher/o__r/checkout', $s->workdir);
        $this->assertSame('/xdg/dep-sec-patcher/o__r/run.lock', $s->lockFile);

        $s = StatePaths::resolve(Options::parse(['--state-dir', 'st', '--vuln-db', '../db.json', '--report-dir', '/r', '--workdir', 'w'], []), 'o__r', $env, '/cwd/sub');
        $this->assertSame('/cwd/sub/st', $s->stateDir);
        $this->assertSame('/cwd/db.json', $s->vulnDb);
        $this->assertSame('', $s->legacyVulnDb, 'a database given explicitly is never moved');
        $this->assertSame('/r', $s->reportDir);
        $this->assertSame('/cwd/sub/w', $s->workdir);
        $this->assertSame('/cwd/sub/st/run.lock', $s->lockFile);

        $s = StatePaths::resolve(Options::parse(['--state-dir', '/st'], []), 'o__r', $env, '/');
        $this->assertSame('/st/vulns.json', $s->vulnDb, '--state-dir keeps the database with the rest');
        $this->assertSame('', $s->legacyVulnDb);

        $s = StatePaths::resolve(Options::parse([], ['VULN_DB' => '/env/db.json']), 's', $env, '/');
        $this->assertSame('/env/db.json', $s->vulnDb, 'VULN_DB still works');
        $this->assertSame('', $s->legacyVulnDb);
    }

    public function testAbsoluteAndInside(): void
    {
        $this->assertSame('/a/c', StatePaths::absolute('b/../c/.', '/a'));
        $this->assertSame('/', StatePaths::absolute('../..', '/a'));

        $root = $this->scratchDir('inside');
        mkdir($root . '/tree');
        mkdir($root . '/elsewhere');
        symlink($root . '/tree', $root . '/link');
        $this->assertTrue(StatePaths::inside($root . '/tree/state/new/vulns.json', $root . '/tree'), 'not-yet-existing paths');
        $this->assertTrue(StatePaths::inside($root . '/tree', $root . '/tree'));
        $this->assertTrue(StatePaths::inside($root . '/link/x', $root . '/tree'), 'symlinks resolved');
        $this->assertFalse(StatePaths::inside($root . '/elsewhere/x', $root . '/tree'));
        $this->assertFalse(StatePaths::inside($root . '/tree-sibling', $root . '/tree'), 'prefix is not containment');
    }
}
