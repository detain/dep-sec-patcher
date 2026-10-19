<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\NpmOverrides;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class NpmOverridesTest extends TestCase
{
    /**
     * @return list<array{string, string, bool}>
     */
    public static function ranges(): array
    {
        return [
            ['3.0.4', '<=3.1.3', true], ['3.1.4', '<=3.1.3', false], ['5.2.1', '5.0.0 - 5.2.1', true],
            ['5.2.2', '5.0.0 - 5.2.1', false], ['4.9.9', '5.0.0 - 5.2.1', false],
            ['2.0.1', '>=2.0.0 <2.0.2 || >=3.0.0 <3.0.5', true], ['3.0.5', '>=2.0.0 <2.0.2 || >=3.0.0 <3.0.5', false],
            ['1.7.3', '<2.6.7', true], ['5.2.9', '<=5.2', true], ['5.3.0', '<=5.2', false],
            ['1.2.9', '~1.2.3', true], ['1.3.0', '~1.2.3', false], ['0.2.9', '^0.2.3', true], ['0.3.0', '^0.2.3', false],
            ['1.9.0', '^1.2', true], ['2.0.0', '^1.2', false], ['1.2.5', '1.2.x', true], ['1.3.0', '1.2', false],
            ['9.9.9', '*', true], ['1.0.1', '1.0.0', false], ['2.0.0', '>1.0', true], ['1.0.5', '>1.0', false],
            ['1.0.0-rc.1', '<1.0.0', true], ['4.0.5', '>= 4.0.0 < 4.0.6', true],
        ];
    }

    #[DataProvider('ranges')]
    public function testAdvisoryRangesReadAsNodeSemverReadsThem(string $version, string $range, bool $expected): void
    {
        $this->assertSame($expected, NpmOverrides::satisfies($version, $range));
    }

    /**
     * zapier-platform-core pins form-data 4.0.5 exactly; mocha 8 pins
     * minimatch 3.0.4 beside a safe 10.x; braces has no unaffected release.
     */
    public function testWhatAuditFixLeavesIsPinnedOnTheLineInUse(): void
    {
        $audit = ['vulnerabilities' => [
            'form-data' => ['via' => [['source' => 1, 'name' => 'form-data', 'range' => '4.0.0 - 4.0.5']]],
            'zapier-platform-core' => ['via' => ['form-data']],
            'minimatch' => ['via' => [['range' => '<=3.1.3'], ['range' => '<3.0.5']]],
            'braces' => ['via' => [['range' => '<=3.0.3']]],
            'sprintf-js' => ['via' => [['range' => '*']]],
        ]];
        $locked = ['form-data' => ['4.0.5', '4.0.6'], 'minimatch' => ['3.0.4', '10.2.6'], 'braces' => ['3.0.3'], 'sprintf-js' => ['1.0.3']];
        $registry = [
            'form-data' => ['4.0.4', '4.0.5', '4.0.6', '4.0.7', '5.0.0-rc.1'],
            'minimatch' => ['3.0.4', '3.1.3', '3.1.4', '3.1.5', '10.2.6'],
            'braces'    => ['2.3.2', '3.0.3'],
        ];
        $plan = NpmOverrides::plan(
            $audit,
            static fn (string $p): array => $locked[$p] ?? [],
            static fn (string $p): ?array => $registry[$p] ?? null,
            [],
            ['form-data' => true],
            false
        );
        // A direct dependency gets a line-qualified key: npm refuses a plain
        // override that differs from the declared spec
        $this->assertSame(['form-data@4' => '^4.0.6', 'minimatch@3' => '^3.1.4'], $plan['overrides']);
        $this->assertSame([], $plan['notes']);
    }

    public function testCrossingAMajorLineNeedsAllowMajor(): void
    {
        $audit    = ['vulnerabilities' => ['node-fetch' => ['via' => [['range' => '<2.6.7']]]]];
        $locked   = static fn (string $p): array => ['1.7.3'];
        $registry = static fn (string $p): array => ['1.7.3', '2.6.6', '2.6.7', '3.3.2'];

        $plan = NpmOverrides::plan($audit, $locked, $registry, [], [], false);
        $this->assertSame([], $plan['overrides']);
        $this->assertSame(['node-fetch 1.7.3 has no fixed release on its 1.x line; overriding it needs --allow-major'], $plan['notes']);

        $plan = NpmOverrides::plan($audit, $locked, $registry, [], [], true);
        $this->assertSame(['node-fetch' => '^2.6.7'], $plan['overrides']);
        $this->assertSame(['node-fetch 1.7.3 -> 2.6.7 crosses a major version (--allow-major)'], $plan['notes']);
    }

    public function testNothingIsPinnedWithoutTheRegistryOrOverANestedOverride(): void
    {
        $audit  = ['vulnerabilities' => ['qs' => ['via' => [['range' => '<6.14.1']]]]];
        $locked = static fn (string $p): array => ['6.11.0'];
        $this->assertSame([], NpmOverrides::plan($audit, $locked, static fn (string $p): ?array => null, [], [], true)['overrides'], 'offline');
        $nested = ['qs' => (object)['.' => '6.11.0']];
        $this->assertSame([], NpmOverrides::plan($audit, $locked, static fn (string $p): array => ['6.14.1'], $nested, [], true)['overrides']);
    }
}
