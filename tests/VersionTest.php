<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Version;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Version ordering must match GNU `sort -V` (the shell implementation's
 * comparator), with the semver prerelease rule layered on top.
 */
class VersionTest extends TestCase
{
    /**
     * Ascending order as produced by `LC_ALL=C sort -V` on this list.
     */
    public function testCompareMatchesSortV(): void
    {
        $expected = [
            '.', '..', '.5', '~1', '0.55.0', '1-2', '1.0', '1.00', '1.0.0', '1.0.0-beta', '1.0.0-rc.1', '1.0.9',
            '1.0.10', '1.2.x', '1.2-3', '1.2.3~rc1', '1.2.3', '1.2.3.tar.gz', '1.2.3a', '1.2.3+build', '1_2',
            '2.0.0-M1', '2.0.0-alpha', '2.13.4', '2.13.4.1', '4.1.42.Final', '4.1.100.Final', '9.0.106', '10.1.42',
            '11.0.8', 'A', 'Z', 'a', 'v0.55.0', 'v1.2.3', 'z',
        ];
        $shuffled = $expected;
        mt_srand(42);
        shuffle($shuffled);
        $this->assertSame($expected, Version::sortAscending($shuffled));
    }

    #[DataProvider('gteProvider')]
    public function testGte(string $a, string $b, bool $expected): void
    {
        $this->assertSame($expected, Version::gte($a, $b), "{$a} >= {$b}");
    }

    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function gteProvider(): array
    {
        return [
            'equal'                         => ['1.2.3', '1.2.3', true],
            'numeric not lexical'           => ['1.0.10', '1.0.9', true],
            'lower'                         => ['1.0.9', '1.0.10', false],
            'release outranks prerelease'   => ['1.0.0', '1.0.0-beta', true],
            'prerelease below its release'  => ['1.0.0-beta', '1.0.0', false],
            'prerelease ordering'           => ['1.0.0-rc.1', '1.0.0-beta', true],
            'maven suffix'                  => ['4.1.100.Final', '4.1.42.Final', true],
            'four-part'                     => ['2.13.4.1', '2.13.4', true],
            'trailing zero'                 => ['1.2', '1.2.0', true],
            'trailing zero, other way'      => ['1.2.0', '1.2', true],
            'pep440 rc below release'       => ['4.2rc1', '4.2', false],
            'pep440 dev below release'      => ['2.0.0.dev1', '2.0.0', false],
            'ruby rc below release'         => ['7.0.0.rc1', '7.0.0', false],
            'release above ruby rc'         => ['7.0.0', '7.0.0.rc1', true],
            'maven Final is a release'      => ['4.1.42.Final', '4.1.42', true],
        ];
    }

    #[DataProvider('floorProvider')]
    public function testFloor(string $declared, string $expected): void
    {
        $this->assertSame($expected, Version::floor($declared));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function floorProvider(): array
    {
        return [
            'caret'          => ['^4.17.1', '4.17.1'],
            'tilde'          => ['~1.2', '1.2'],
            'ruby pessimistic' => ['~> 2.0', '2.0'],
            'spaced operator' => ['>= 8.4.2', '8.4.2'],
            // The original shell script deleted the operators and spaces, yielding "1.22"
            'range takes the lower bound' => ['>=1.2 <2', '1.2'],
            'maven range'    => ['[2.8.3,3)', '2.8.3'],
            'wildcard'       => ['1.2.x', '1.2'],
            'v prefix'       => ['v1.2.3', '1.2.3'],
            'maven final'    => ['4.1.42.Final', '4.1.42.Final'],
            'unresolved property' => ['${jackson.version}', ''],
            'star'           => ['*', ''],
            'upper bound only' => ['<2', ''],
            'pip upper and lower' => ['<1.27,>=1.21.1', '1.21.1'],
            'not-equal ignored' => ['!=1.5,>=1.2', '1.2'],
            'union takes the lowest' => ['^5.4 || ^6.0', '5.4'],
            'composer single bar' => ['^1.0|^2.0', '1.0'],
            'maven open lower' => ['(,1.0]', ''],
            'maven union'    => ['[1.0,2.0),[3.0,)', '1.0'],
            'hyphen range'   => ['1.2.3 - 2.0.0', '1.2.3'],
            'composer dev branch' => ['1.0.x-dev', '1.0'],
            'dev-master'     => ['dev-master', ''],
        ];
    }

    public function testBranch(): void
    {
        $this->assertSame('9.0', Version::branch('9.0.106'));
        $this->assertSame('4.1', Version::branch('4.1.42.Final'));
        $this->assertSame('5', Version::branch('5'));
        $this->assertSame('2.13', Version::branch('^2.13.4'));
    }

    public function testSatisfiesOnOwnReleaseLine(): void
    {
        $tomcat = ['9.0.106', '10.1.42', '11.0.8'];
        $this->assertTrue(Version::satisfies('9.0.110', $tomcat), 'above the 9.0 fix');
        $this->assertTrue(Version::satisfies('10.1.42', $tomcat), 'exactly the 10.1 fix');
        $this->assertTrue(Version::satisfies('12.0.0', $tomcat), 'above every fix');
        $this->assertFalse(Version::satisfies('9.0.50', $tomcat), 'below the 9.0 fix');
        $this->assertFalse(Version::satisfies('10.0.5', $tomcat), 'unfixed 10.0 line');
        $this->assertFalse(Version::satisfies('', $tomcat));
    }

    #[DataProvider('prereleaseProvider')]
    public function testIsPrerelease(string $version, bool $expected): void
    {
        $this->assertSame($expected, Version::isPrerelease($version), $version);
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function prereleaseProvider(): array
    {
        return [
            'maven alpha'         => ['5.0.0.Alpha2', true],
            'maven milestone'     => ['7.1.0-M2', true],
            'maven RC'            => ['3.0.0.RC1', true],
            'jboss CR'            => ['2.0.0.CR1', true],
            'snapshot'            => ['1.2.3-SNAPSHOT', true],
            'semver rc'           => ['2.0.0-rc.1', true],
            'npm next'            => ['8.0.0-next.3', true],
            'pep440 rc'           => ['4.2rc1', true],
            'pep440 dev'          => ['2.0.0.dev1', true],
            'pep440 beta'         => ['1.0b2', true],
            'preview'             => ['9.0.0-preview.7', true],
            'early access'        => ['21-ea', true],
            'release'             => ['4.1.137', false],
            'maven Final'         => ['4.1.42.Final', false],
            'spring RELEASE'      => ['5.1.17.RELEASE', false],
            'guava jre'           => ['33.4.0-jre', false],
            'guava android'       => ['28.2-android', false],
            'jetty build date'    => ['9.4.44.v20210927', false],
            'go pseudo-version'   => ['0.0.0-20210101000000-abcdef123456', false],
            'four-part'           => ['2.12.7.1', false],
        ];
    }

    public function testAPrereleaseOnlySatisfiesAFixOnItsOwnReleaseLine(): void
    {
        $netty = ['4.1.137.Final', '4.2.17.Final'];
        $this->assertFalse(Version::satisfies('5.0.0.Alpha2', $netty), 'sorts above every fix, but is from 2015');
        $this->assertFalse(Version::satisfies('7.1.0-M2', ['6.2.19', '7.0.8']), 'a milestone of a line with no fix');
        $this->assertTrue(Version::satisfies('7.0.9-RC1', ['6.2.19', '7.0.8']), 'past the fix on its own line');
        $this->assertTrue(Version::satisfies('4.2.0-rc1', ['4.1.137', '4.2.0-beta3']));
        $this->assertTrue(Version::satisfies('33.4.0-jre', ['32.0.0-android']), 'a guava flavour is a release');
        $this->assertTrue(Version::satisfies('5.0.0', $netty), 'a release above every fix still counts');
        // Above every fix, a prerelease counts once its line has had a release that needed no fix
        $this->assertTrue(Version::satisfies('4.2.0-M2', ['3.0.0']), 'spring-boot 4.2 milestones follow 4.0 and 4.1');
        $this->assertTrue(Version::satisfies('7.1.0-M2', ['6.2.19']), 'no 7.x fix, and 7.0 came before it');
        $this->assertTrue(Version::satisfies('0.9.3-rc.1', ['0.8.4']));
        $this->assertFalse(Version::satisfies('7.1.0-M2', ['7.0.9']), 'the 7.x line needed a fix, which it may predate');
        $this->assertFalse(Version::satisfies('8.0.0-rc.6', ['7.26.10']), 'nothing on the 8.x line was released before it');
        $this->assertFalse(Version::satisfies('0.9.0-beta', ['0.8.4']));

        $this->assertTrue(Version::prereleaseAboveFixes('5.0.0.Alpha2', ['CVE' => $netty]));
        $this->assertTrue(Version::prereleaseAboveFixes('^8.0.0-rc.1', ['A' => ['7.29.6'], 'B' => ['7.20.0']]));
        $this->assertFalse(Version::prereleaseAboveFixes('1.0.0-beta', ['CVE' => ['1.0.0']]), 'its release is a fix to move to');
        $this->assertFalse(Version::prereleaseAboveFixes('7.0.9-RC1', ['CVE' => ['6.2.19', '7.0.8']]), 'already clear');
        $this->assertFalse(Version::prereleaseAboveFixes('7.1.0-M2', ['A' => ['6.2.19', '7.0.8'], 'B' => ['7.1.0']]), '7.1.0 clears both');
        $this->assertFalse(Version::prereleaseAboveFixes('5.0.0', ['CVE' => $netty]));
        $this->assertSame('1.0.0', Version::chooseTarget('1.0.0-beta', ['CVE' => ['1.0.0']]));
    }

    public function testAPrereleaseAboveEveryFixGoesBackToTheNewestReleaseWithTheFix(): void
    {
        $netty = ['4.1.137.Final', '4.2.17.Final'];
        $this->assertSame('4.2.17.Final', Version::releaseForPrerelease('5.0.0.Alpha2', ['CVE' => $netty]), 'no 5.x release: the newest fix');
        $this->assertSame('7.0.8', Version::releaseForPrerelease('7.1.0-M2', ['CVE' => ['6.2.19', '7.0.8']]), 'its own major line first');
        $this->assertSame('7.0.8', Version::releaseForPrerelease('7.1.0-M2', ['A' => ['6.2.19', '7.0.8'], 'B' => ['7.0.3']]), 'one release clearing both');
        $this->assertSame('4.2.17.Final', Version::releaseForPrerelease('5.0.0.Alpha2', ['CVE' => [...$netty, '4.3.0-RC1']]), 'never another prerelease');
        $this->assertSame('', Version::releaseForPrerelease('7.0.9-RC1', ['CVE' => ['6.2.19', '7.0.8']]), 'already clear');
        $this->assertSame('', Version::releaseForPrerelease('1.0.0-beta', ['CVE' => ['1.0.0']]), 'a fix above it: an ordinary bump');
        $this->assertSame('', Version::releaseForPrerelease('4.1.100.Final', ['CVE' => $netty]), 'not a prerelease');
        $this->assertSame('', Version::releaseForPrerelease('5.0.0.Alpha2', []));
    }

    public function testChooseTargetStaysOnReleaseLine(): void
    {
        $spec = ['CVE-2025-49124' => ['9.0.106', '10.1.42', '11.0.8']];
        $this->assertSame('9.0.106', Version::chooseTarget('9.0.50', $spec));
        $this->assertSame('10.1.42', Version::chooseTarget('10.0.5', $spec));
        // Already past its own line's fix: the original shell script forced 10.1.42 here
        $this->assertSame('', Version::chooseTarget('9.0.110', $spec));
    }

    public function testChooseTargetTakesHighestAcrossAdvisories(): void
    {
        $spec = ['CVE-A' => ['1.2.5'], 'CVE-B' => ['1.3.0'], 'CVE-C' => ['1.0.0']];
        $this->assertSame('1.3.0', Version::chooseTarget('^1.2.0', $spec));
        $this->assertSame('', Version::chooseTarget('1.3.0', $spec), 'already at the highest fix');
    }

    public function testChooseTargetTransitiveUsesPackageMaximum(): void
    {
        $this->assertSame('6.15.2', Version::chooseTarget('', ['GHSA' => ['6.14.0']], '6.15.2'));
    }

    public function testChooseTargetLeavesAdmittingRangeAlone(): void
    {
        // Maven resolves a range to the newest version it admits, so a range
        // that admits a fixed version must not be pinned (possibly downwards)
        $this->assertSame('', Version::chooseTarget('[2.8.3,3)', ['CVE' => ['2.21.3']]));
        $this->assertSame('2.21.3', Version::chooseTarget('[2.8.3,2.9)', ['CVE' => ['2.21.3']]));
    }

    public function testBracketRange(): void
    {
        $this->assertSame(
            ['lower' => '2.8.3', 'lowerInclusive' => true, 'upper' => '3', 'upperInclusive' => false],
            Version::bracketRange('[2.8.3,3)')
        );
        $this->assertSame(
            ['lower' => '', 'lowerInclusive' => false, 'upper' => '1.0', 'upperInclusive' => true],
            Version::bracketRange('(,1.0]')
        );
        $this->assertSame('1.5', Version::bracketRange('[1.5]')['upper'] ?? null);
        $this->assertNull(Version::bracketRange('^1.2.3'));
        $this->assertNull(Version::bracketRange('[1.0,2.0),[3.0,)'), 'unions are not handled');
    }

    public function testRangeAdmits(): void
    {
        $range = Version::bracketRange('[2.8.3,3)');
        $this->assertNotNull($range);
        $this->assertTrue(Version::rangeAdmits($range, '2.8.3'));
        $this->assertTrue(Version::rangeAdmits($range, '2.21.3'));
        $this->assertFalse(Version::rangeAdmits($range, '3'));
        $this->assertFalse(Version::rangeAdmits($range, '2.8.2'));
        $open = Version::bracketRange('[1.0,)');
        $this->assertNotNull($open);
        $this->assertTrue(Version::rangeAdmits($open, '99.0'));
    }

    public function testMax(): void
    {
        $this->assertSame('4.1.100.Final', Version::max(['4.1.42.Final', '4.1.100.Final', '4.1.9.Final']));
        $this->assertSame('', Version::max([]));
    }

    public function testMaxReleasePassesOverPrereleases(): void
    {
        $this->assertSame('7.29.6', Version::maxRelease(['7.29.6', '8.0.0-rc.6']), 'an override is never pinned to a release candidate');
        $this->assertSame('4.2', Version::maxRelease(['4.2', '5.0rc1', '5.0.0.dev1']));
        $this->assertSame('8.0.0-rc.6', Version::maxRelease(['8.0.0-rc.5', '8.0.0-rc.6']), 'unless that is all there is');
        $this->assertSame('', Version::maxRelease([]));
    }

    public function testMajorLineAndClearsAll(): void
    {
        $this->assertSame('4', Version::majorLine('^4.17.1'));
        $this->assertSame('0.8', Version::majorLine('0.8.15'), 'below 1.0 a minor release is a major one');
        $this->assertSame('', Version::majorLine('*'));
        $spec = ['A' => ['1.1.12', '2.0.2'], 'B' => ['1.1.21']];
        $this->assertTrue(Version::clearsAll('1.1.21', $spec));
        $this->assertFalse(Version::clearsAll('1.1.14', $spec));
        $this->assertFalse(Version::clearsAll('2.0.1', $spec), 'below the 2.x fix of A');
    }
}
