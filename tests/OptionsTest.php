<?php

namespace Detain\DepSecPatcher\Tests;

use InvalidArgumentException;
use Detain\DepSecPatcher\Options;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Every option the original tool accepted keeps its meaning and default.
 */
class OptionsTest extends TestCase
{
    public function testDefaults(): void
    {
        $o = Options::parse([], []);
        $this->assertSame(1, $o->threads);
        $this->assertSame('update', $o->mode);
        $this->assertSame('7.0', $o->cvssThreshold);
        $this->assertSame(0, $o->maxIssues);
        $this->assertSame('security: verified fixed', $o->closeLabel);
        $this->assertSame(5, $o->closeDelay);
        $this->assertSame(400, $o->closeLimit);
        $this->assertSame(1800, $o->timeout);
        $this->assertTrue($o->wants('maven'));
        $this->assertTrue($o->githubEnabled());
    }

    public function testFlagsAndValues(): void
    {
        $o = Options::parse([
            '-t', '4', '--check', '--no-maven', '--no-trivy', '--cvss-threshold=9', '--repo', 'o/r',
            '--max-issues', '0', '--no-github', '--close-fixed', '--close-label', '', '--timeout=60', 'some/dir',
        ], []);
        $this->assertSame(4, $o->threads);
        $this->assertSame('check', $o->mode);
        $this->assertFalse($o->wants('maven'));
        $this->assertTrue($o->wants('gradle'));
        $this->assertFalse($o->wants('trivy'));
        $this->assertFalse($o->wants('grype'), 'grype follows --no-trivy');
        $this->assertSame('9', $o->cvssThreshold);
        $this->assertSame('o/r', $o->ghRepo);
        $this->assertSame(0, $o->maxIssues);
        $this->assertFalse($o->githubEnabled());
        $this->assertTrue($o->closeFixed);
        $this->assertSame('', $o->closeLabel, 'empty label disables labelling');
        $this->assertSame(60, $o->timeout);
        $this->assertSame('some/dir', $o->target);
    }

    public function testEnvironment(): void
    {
        $o = Options::parse([], ['SECURITY_UPDATE_MODE' => 'check', 'API_SAMPLES_PROFILE' => 'mailbaby', 'VULN_DB' => '/x.json', 'GH_REPO' => 'a/b']);
        $this->assertSame('check', $o->mode);
        // The MyAdmin profile system is gone: its variable is simply ignored
        $this->assertFalse(property_exists($o, 'profile'));
        $this->assertSame('/x.json', $o->vulnDb);
        $this->assertSame('a/b', $o->ghRepo);
        $this->assertSame('update', Options::parse(['--update'], ['SECURITY_UPDATE_MODE' => 'check'])->mode, 'CLI wins');
    }

    public function testOnlyAndApplyStored(): void
    {
        $o = Options::parse(['--only', 'maven,netsec'], []);
        $this->assertTrue($o->wants('maven'));
        $this->assertTrue($o->wants('netsec'));
        $this->assertFalse($o->wants('node'));
        $this->assertFalse($o->wants('bandit'));

        $o = Options::parse(['--apply-stored'], []);
        $this->assertFalse($o->wants('maven'));
        $this->assertFalse($o->wants('netsec'));
    }

    /**
     * @param list<string> $argv
     */
    #[DataProvider('badArgs')]
    public function testErrors(array $argv, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        Options::parse($argv, []);
    }

    /**
     * @return array<string, array{list<string>, string}>
     */
    public static function badArgs(): array
    {
        return [
            'unknown option'   => [['--bogus'], 'unknown option: --bogus'],
            'missing value'    => [['-t'], 'option -t requires a value'],
            'zero threads'     => [['-t', '0'], '-t must be a positive integer'],
            'negative issues'  => [['--max-issues', '-1'], '--max-issues must be a non-negative integer'],
            'bad cvss'         => [['--cvss-threshold', 'high'], '--cvss-threshold must be a number'],
            'unknown --only'   => [['--only', 'cobol'], "--only: unknown check 'cobol'"],
            'pr and direct'    => [['--pr', '--push-direct'], '--pr and --push-direct cannot be combined'],
            'direct + branch'  => [['--push-direct', '--branch', 'x'], 'cannot be combined with --branch'],
            'pr-merge alone'   => [['--push', '--pr-merge', 'merge'], '--pr-merge applies only with --pr'],
            'bad pr-merge'     => [['--pr', '--pr-merge', 'octopus'], '--pr-merge must be one of squash, merge, rebase, none'],
        ];
    }

    public function testPushModes(): void
    {
        $o = Options::parse(['--push'], []);
        $this->assertTrue($o->push);
        $this->assertSame('branch', $o->pushMode);
        $this->assertSame('squash', $o->prMerge);

        $o = Options::parse(['--pr', '--pr-merge=rebase', '--branch', 'sec/x'], []);
        $this->assertTrue($o->push, '--pr implies --push');
        $this->assertSame('pr', $o->pushMode);
        $this->assertSame('rebase', $o->prMerge);
        $this->assertSame('sec/x', $o->branch);
        $this->assertSame('pr', Options::parse(['--pr', '--push'], [])->pushMode, '--push does not undo --pr');

        $this->assertFalse(Options::parse([], [])->allowMajor);
        $this->assertTrue(Options::parse(['--allow-major'], [])->allowMajor);

        $this->assertTrue(Options::parse([], [])->retriage);
        $this->assertFalse(Options::parse(['--no-retriage'], [])->retriage);

        $this->assertFalse(Options::parse([], [])->enablePosture);
        $this->assertTrue(Options::parse(['--enable-posture'], [])->enablePosture);

        $o = Options::parse(['--push-direct'], []);
        $this->assertTrue($o->push, '--push-direct implies --push');
        $this->assertSame('direct', $o->pushMode);
        $this->assertFalse(Options::parse([], [])->push);
    }

    public function testHelpMentionsEveryEcosystem(): void
    {
        $help = Options::help('prog');
        foreach (Options::ECOSYSTEMS as $eco) {
            $this->assertStringContainsString("--no-{$eco}", $help);
        }
        $this->assertMatchesRegularExpression('#--repo OWNER/NAME\s+GitHub repository#', $help);
        $this->assertStringContainsString("origin remote", $help);
        $this->assertMatchesRegularExpression('#--enable-posture\s+In update mode#', $help);
    }
}
