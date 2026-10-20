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

    public function testRestRowsArriveInTheShapeTriageReads(): void
    {
        $rows = SecurityRun::pullRequestRows([
            [
                'number' => 7475,
                'title'  => 'Bump the maven group across 2 directories with 4 updates',
                'user'   => ['login' => 'dependabot[bot]', 'type' => 'Bot'],
                'draft'  => false,
                'head'   => ['ref' => 'dependabot/maven/foo'],
                'body'   => 'Bumps ...',
            ],
            [
                'number' => 20,
                'title'  => 'Work in progress',
                'user'   => ['login' => 'someone', 'type' => 'User'],
                'draft'  => true,
            ],
            ['title' => 'row without a number is not a PR'],
        ]);
        $this->assertCount(2, $rows);
        $this->assertSame(['login' => 'dependabot[bot]', 'is_bot' => true], $rows[0]['author'],
            'REST names the account "dependabot[bot]" where gh printed "app/dependabot"; isBot takes both');
        $this->assertTrue(self::call('isBot', $rows[0]['author']));
        $this->assertSame('dependabot/maven/foo', $rows[0]['headRefName']);
        $this->assertTrue($rows[1]['isDraft']);
        $this->assertSame('', $rows[1]['headRefName'], 'a missing head reads as empty, not as a crash');
        $this->assertFalse($rows[1]['author']['is_bot']);
    }

    public function testPackagesComeFromTheTitleAndTheBodyLinesItDoesNotCover(): void
    {
        $this->assertSame(
            ['lodash'],
            SecurityRun::prPackages('Bump lodash from 4.17.20 to 4.17.21', 'chatter')
        );
        $this->assertSame(
            ['vite'],
            SecurityRun::prPackages('chore(deps): bump vite from 7.3.6 to 7.3.7 in the npm_and_yarn group', '')
        );
        $grouped = "Bumps the npm_and_yarn group with 2 updates:\nUpdates `bootstrap` from 3.4.1 to 5.0.0\n"
            . "Updates `qs` from 6.11.0 to 6.15.2\nBumps `lodash` from 4.17.20 to 4.17.21 (transitive)\n";
        $this->assertSame(
            ['bootstrap', 'qs'],
            SecurityRun::prPackages('Bump the npm_and_yarn group across 1 directory with 2 updates', $grouped),
            'a grouped title names no package; the Updates lines do'
        );
        $this->assertSame([], SecurityRun::prPackages('Bump the maven group across 2 directories with 4 updates', 'no structured lines'));
    }

    public function testTheDirectoryAMentionedTitleNames(): void
    {
        $this->assertSame(
            'OPENAPI-REST-API/openapi-client/javascript-flowtyped',
            SecurityRun::prDirectory('Bump yargs-parser from 7.0.0 to 13.1.2 in /OPENAPI-REST-API/openapi-client/javascript-flowtyped in the npm_and_yarn group across 1 directory')
        );
        $this->assertSame('app', SecurityRun::prDirectory('Bump x from 1.0.0 to 1.0.1 in /app'));
        $this->assertNull(SecurityRun::prDirectory('Bump the maven group across 2 directories with 4 updates'));
        $this->assertNull(SecurityRun::prDirectory('Bump x from 1.0.0 to 1.0.1'), 'a root manifest names none');
    }

    public function testAnAlertCoversAPrWhileItsPackageStillHasOne(): void
    {
        $alerts = [
            ['package' => 'Yargs-Parser', 'manifest' => 'app/package.json', 'ecosystem' => 'npm'],
            ['package' => 'qs', 'manifest' => 'package.json', 'ecosystem' => 'npm'],
            ['package' => 'other', 'manifest' => '', 'ecosystem' => 'pip'],
        ];
        $this->assertTrue(SecurityRun::alertsCoverPr(['yargs-parser'], null, $alerts), 'names match case-insensitively');
        $this->assertTrue(SecurityRun::alertsCoverPr(['yargs-parser'], 'app', $alerts), 'and the directories agree');
        $this->assertFalse(SecurityRun::alertsCoverPr(['yargs-parser'], 'elsewhere', $alerts),
            'an alert on another manifest does not cover a PR moving this one');
        $this->assertTrue(SecurityRun::alertsCoverPr(['qs'], null, $alerts));
        $this->assertTrue(SecurityRun::alertsCoverPr(['other'], 'frontend', $alerts), 'an alert naming no manifest cannot be placed in another directory, so it covers');
        $this->assertFalse(SecurityRun::alertsCoverPr(['qs'], 'frontend', $alerts), 'a root manifest is not frontend');
        $this->assertFalse(SecurityRun::alertsCoverPr(['gone-package'], null, $alerts));
        $this->assertFalse(SecurityRun::alertsCoverPr([], null, $alerts), 'nothing to cover');
        $this->assertFalse(SecurityRun::alertsCoverPr(['lodash'], 'app', []), 'the empty alert list is the superseded case');
    }
}
