<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\PrTriageState;
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
        $this->assertTrue(self::covers(['yargs-parser'], null, $alerts), 'names match case-insensitively');
        $this->assertTrue(self::covers(['yargs-parser'], 'app', $alerts), 'and the directories agree');
        $this->assertFalse(self::covers(['yargs-parser'], 'elsewhere', $alerts),
            'an alert on another manifest does not cover a PR moving this one');
        $this->assertTrue(self::covers(['qs'], null, $alerts));
        $this->assertTrue(self::covers(['other'], 'frontend', $alerts), 'an alert naming no manifest cannot be placed in another directory, so it covers');
        $this->assertFalse(self::covers(['qs'], 'frontend', $alerts), 'a root manifest is not frontend');
        $this->assertFalse(self::covers(['gone-package'], null, $alerts));
        $this->assertFalse(self::covers([], null, $alerts), 'nothing to cover');
        $this->assertFalse(self::covers(['lodash'], 'app', []), 'the empty alert list is the superseded case');
        $this->assertFalse(self::latches(['lodash'], 'app', []));

        // latching is stricter: only an alert in the named directory (or a
        // title that names none) may plant the memory that later closes
        $this->assertTrue(self::latches(['yargs-parser'], 'app', $alerts), 'the PR directory and the alert agree');
        $this->assertFalse(self::latches(['yargs-parser'], 'elsewhere', $alerts), 'another directory never latches');
        $this->assertFalse(self::latches(['other'], 'frontend', $alerts), 'an unplaceable alert covers but never latches');
        $this->assertTrue(self::latches(['other'], null, $alerts), 'a grouped title has no directory to contradict');
        $this->assertFalse(self::latches(['qs'], 'app', $alerts), 'a root manifest is a placement too — and it is not the PR’s');
    }

    /**
     * @param list<string>                  $packages
     * @param list<array<string, mixed>>    $alerts
     */
    private static function covers(array $packages, ?string $dir, array $alerts): bool
    {
        return SecurityRun::alertsCoverPr($packages, $dir, $alerts)['covered'];
    }

    /**
     * @param list<string>                  $packages
     * @param list<array<string, mixed>>    $alerts
     */
    private static function latches(array $packages, ?string $dir, array $alerts): bool
    {
        return SecurityRun::alertsCoverPr($packages, $dir, $alerts)['strict'];
    }

    public function testTheTallySplitsPendingByDesignFromGenuinelyBlocked(): void
    {
        $tally = static function (string $outcome): string {
            $m = new ReflectionMethod(SecurityRun::class, 'tallyOf');
            return $m->invoke(null, $outcome);
        };
        // by design: --push, --allow-major or the human waits, the run is correct
        foreach (['would-supersede', 'needs-major', 'rebase-refused', 'close-failed'] as $pending) {
            $this->assertSame('pending', $tally($pending), $pending);
        }
        // genuinely stuck keeps the FAIL
        foreach (['merge-failed', 'rebase-failed', 'blocked-ci', 'blocked-protection', 'unknown-mergeability', 'blocked-permanent'] as $blocked) {
            $this->assertSame('blocked', $tally($blocked), $blocked);
        }
        foreach (['merged', 'auto-merge'] as $merged) {
            $this->assertSame('merged', $tally($merged), $merged);
        }
        foreach (['rebase-requested', 'rebase-nudged', 'manual-instructions'] as $rebased) {
            $this->assertSame('rebased', $tally($rebased), $rebased);
        }
        $this->assertSame('closed', $tally('superseded-closed'));
        foreach (['counted', 'behind-waiting', 'rebase-waiting'] as $quiet) {
            $this->assertSame('none', $tally($quiet), $quiet);
        }
        // every outcome the state file documents is classified
        foreach (PrTriageState::OUTCOMES as $outcome) {
            $this->assertContains($tally($outcome), ['merged', 'rebased', 'closed', 'pending', 'blocked', 'none'], $outcome);
        }
    }

    public function testTheMergeCommitShaIsReadFromTheObjectGhSends(): void
    {
        $object = ['mergeCommit' => ['oid' => 'abc1234def', 'url' => 'https://github.com/o/r/commit/abc1234def']];
        $this->assertSame('abc1234def', self::call('mergeCommitOid', $object), 'live gh answers --json mergeCommit with an object, not a string');
        $this->assertSame('abc1234def', self::call('mergeCommitOid', ['mergeCommit' => 'abc1234def']), 'a plain string still parses');
        $this->assertSame('', self::call('mergeCommitOid', null), 'a failed view records nothing');
        $this->assertSame('', self::call('mergeCommitOid', []));
        $this->assertSame('', self::call('mergeCommitOid', ['mergeCommit' => null]));
        $this->assertSame('', self::call('mergeCommitOid', ['mergeCommit' => ['url' => 'https://x']]), 'an object without an oid is nothing, never the word Array');
    }
}
