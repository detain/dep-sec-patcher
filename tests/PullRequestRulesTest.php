<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\SecurityRun;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * Which bot pull requests the triage step may merge.
 */
class PullRequestRulesTest extends TestCase
{
    private static function call(string $method, mixed ...$args): mixed
    {
        $m = new ReflectionMethod(SecurityRun::class, $method);
        return $m->invoke(null, ...$args);
    }

    public function testOnlyGithubAppBotsCount(): void
    {
        $this->assertTrue(self::call('isBot', ['login' => 'app/dependabot', 'is_bot' => true]));
        $this->assertTrue(self::call('isBot', ['login' => 'app/mend-bolt-for-github', 'is_bot' => true]));
        $this->assertTrue(self::call('isBot', ['login' => 'renovate[bot]', 'is_bot' => true]));
        $this->assertFalse(self::call('isBot', ['login' => 'amendoza', 'is_bot' => false]), 'a person whose login contains "mend"');
        $this->assertFalse(self::call('isBot', ['login' => 'renovate-fan', 'is_bot' => false]));
        $this->assertFalse(self::call('isBot', ['login' => 'app/some-other-app', 'is_bot' => true]));
        $this->assertFalse(self::call('isBot', null));
    }

    public function testMajorBumpsFromDependabotAndRenovate(): void
    {
        $body = "Bumps the npm_and_yarn group with 2 updates:\nUpdates `bootstrap` from 3.4.1 to 5.0.0\nUpdates `qs` from 6.11.0 to 6.15.2\n"
            . "<li>Bump rollup from 2.46.0 to 3.0.0</li>\n";
        $this->assertSame(
            ['bootstrap 3.4.1 -> 5.0.0'],
            self::call('majorBumps', 'Bump the npm_and_yarn group across 1 directory with 2 updates', $body),
            'the quoted changelog is not read'
        );
        $this->assertSame(['axios 0.27.2 -> 0.28.0'], self::call('majorBumps', 'Bump axios from 0.27.2 to 0.28.0', ''), 'below 1.0 a minor bump is major');
        $this->assertSame([], self::call('majorBumps', 'Bump qs from 6.11.0 to 6.15.2', ''));
        $renovate = "| Package | Change |\n|---|---|\n| [vue](https://x) | `2.7.16` -> `3.5.13` |\n";
        $this->assertSame(['vue 2.7.16 -> 3.5.13'], self::call('majorBumps', 'Update dependency vue to v3', $renovate));
    }
}
