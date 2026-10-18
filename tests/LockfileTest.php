<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Lockfile;
use PHPUnit\Framework\TestCase;

/**
 * Resolved versions from each lockfile format.
 */
class LockfileTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testYarnV1AndBerry(): void
    {
        $v1 = "# yarn lockfile v1\n\n\"@xmldom/xmldom@^0.8.3\":\n  version \"0.8.13\"\n  resolved \"x\"\n\n"
            . "brace-expansion@^1.1.7, brace-expansion@^1.1.8:\n  version \"1.1.14\"\n\nbrace-expansion@^2.0.1:\n  version \"2.0.1\"\n\n"
            . "brace-expansion-extra@^1.0.0:\n  version \"9.9.9\"\n";
        $this->assertSame(['0.8.13'], Lockfile::parse('yarn.lock', $v1, '@xmldom/xmldom'));
        $this->assertSame(['1.1.14', '2.0.1'], Lockfile::parse('yarn.lock', $v1, 'brace-expansion'));

        $berry = "__metadata:\n  version: 6\n\n\"qs@npm:^6.11.0, qs@npm:^6.5.0\":\n  version: 6.11.2\n  resolution: \"qs@npm:6.11.2\"\n";
        $this->assertSame(['6.11.2'], Lockfile::parse('yarn.lock', $berry, 'qs'));
    }

    public function testPackageLockV1AndV3(): void
    {
        $v3 = json_encode(['lockfileVersion' => 3, 'packages' => [
            ''                                => ['name' => 'app'],
            'node_modules/qs'                 => ['version' => '6.11.0'],
            'node_modules/body/node_modules/qs' => ['version' => '6.5.2'],
            'node_modules/qs-extra'           => ['version' => '1.0.0'],
        ]]);
        $this->assertSame(['6.11.0', '6.5.2'], Lockfile::parse('package-lock.json', (string)$v3, 'qs'));

        $v1 = json_encode(['lockfileVersion' => 1, 'dependencies' => [
            'qs'   => ['version' => '6.11.0'],
            'body' => ['version' => '1.0.0', 'dependencies' => ['qs' => ['version' => '6.5.2']]],
        ]]);
        $this->assertSame(['6.11.0', '6.5.2'], Lockfile::parse('package-lock.json', (string)$v1, 'qs'));
    }

    public function testPnpmAndComposer(): void
    {
        $pnpm = "packages:\n\n  qs@6.11.2:\n    resolution: {}\n\n  /qs@6.5.3(peer@1.0.0):\n    resolution: {}\n\n  /qs/6.1.0:\n    x: y\n";
        $this->assertSame(['6.11.2', '6.5.3', '6.1.0'], Lockfile::parse('pnpm-lock.yaml', $pnpm, 'qs'));

        $lock = (string)json_encode(['packages' => [['name' => 'twig/twig', 'version' => 'v3.5.1']], 'packages-dev' => []]);
        $this->assertSame(['3.5.1'], Lockfile::parse('composer.lock', $lock, 'Twig/Twig'));
    }

    public function testVersionsReadsTheDirectory(): void
    {
        $dir = $this->scratchDir('lock');
        $this->assertNull(Lockfile::versions($dir, 'npm', 'qs'), 'no lockfile');
        file_put_contents($dir . '/yarn.lock', "qs@^6.0.0:\n  version \"6.11.0\"\n");
        $this->assertSame(['6.11.0'], Lockfile::versions($dir, 'npm', 'qs'));
        $this->assertSame([], Lockfile::versions($dir, 'npm', 'axios'), 'lockfile without the package');
        $this->assertNull(Lockfile::versions($dir, 'composer', 'qs'));
    }
}
