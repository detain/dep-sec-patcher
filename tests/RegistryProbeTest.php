<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\RegistryProbe;
use PHPUnit\Framework\TestCase;

/**
 * What the registry says exists, through an injected HTTP layer: the probe is
 * the guard that kept "io.netty:netty-codec-http2 7.0.12" and "lodash 4.18.0"
 * out of manifests, so its answers - and its silence - must be exact.
 */
class RegistryProbeTest extends TestCase
{
    /**
     * @param array<string, string|false> $answers URL => body, or false for a failed GET
     * @param-out int $asks
     */
    private static function probe(array $answers, ?int &$asks = null): RegistryProbe
    {
        $asks = 0;
        return new RegistryProbe(static function (string $url) use ($answers, &$asks): ?string {
            $asks++;
            return match (true) {
                !array_key_exists($url, $answers) => null,
                $answers[$url] === false          => null,
                default                           => (string)$answers[$url],
            };
        });
    }

    public function testMavenVersionsComeFromTheCoordinatesMetadata(): void
    {
        $url   = RegistryProbe::MAVEN_CENTRAL . '/io/netty/netty-codec-http2/maven-metadata.xml';
        $probe = self::probe([
            $url => '<metadata><versioning><versions><version>4.1.76.Final</version>'
                . '<version>4.1.135.Final</version></versions></versioning></metadata>',
        ], $asks);

        $this->assertSame(['4.1.76.Final', '4.1.135.Final'], $probe->versions('maven', 'io.netty:netty-codec-http2'));
        $this->assertTrue($probe->exists('maven', 'io.netty:netty-codec-http2', '4.1.135.Final'));
        $this->assertFalse($probe->exists('maven', 'io.netty:netty-codec-http2', '7.0.12'), 'a plexus-utils version, not a netty one');
        $this->assertSame(1, $asks, 'asked once, then cached');
    }

    public function testAMavenNameWithoutAGroupIdIsNobody(): void
    {
        // "netty-codec-http2" alone has no Central path, and guessing one is
        // how a short name reached another group's versions
        $probe = self::probe([], $asks);
        $this->assertNull($probe->versions('maven', 'netty-codec-http2'));
        $this->assertNull($probe->exists('maven', 'netty-codec-http2', '4.1.135.Final'));
        $this->assertSame(0, $asks, 'not even asked');
    }

    public function testNpmVersionsComeFromTheRegistryDocument(): void
    {
        $probe = self::probe([
            RegistryProbe::NPM_REGISTRY . '/lodash'        => '{"versions":{"4.17.20":{},"4.17.21":{}}}',
            RegistryProbe::NPM_REGISTRY . '/@babel%2Fcore' => '{"versions":{"7.29.0":{},"7.29.6":{}}}',
        ]);
        $this->assertSame(['4.17.20', '4.17.21'], $probe->versions('npm', 'lodash'));
        $this->assertFalse($probe->exists('npm', 'lodash', '4.18.0'), 'the version no lodash release ever had');
        $this->assertTrue($probe->exists('npm', '@babel/core', '7.29.6'), 'a scoped name reaches the registry');
    }

    public function testPipVersionsDropTheReleasesThatHaveNoFiles(): void
    {
        $probe = self::probe([
            RegistryProbe::PYPI . '/requests/json' => '{"releases":{"2.31.0":[{"digests":1}],"2.32.3":[{"digests":1}],"2.9.9":[]}}',
        ]);
        $this->assertSame(['2.31.0', '2.32.3'], $probe->versions('pip', 'Requests'));
        $this->assertFalse($probe->exists('pip', 'requests', '2.9.9'), 'a release with no files cannot install');
    }

    public function testAnUnansweredQuestionIsNeverAnEmptyAnswer(): void
    {
        $probe = self::probe([
            RegistryProbe::NPM_REGISTRY . '/left-pad'            => '{"versions":{"1.0.0":{}}}',
            RegistryProbe::MAVEN_CENTRAL . '/g/a/maven-metadata.xml' => '<metadata/>',
        ]);
        $this->assertNull($probe->versions('npm', 'unheard-of'), 'a 404-style miss is "cannot say"');
        $this->assertNull($probe->exists('npm', 'unheard-of', '1.0.0'));
        $this->assertNull($probe->versions('maven', 'g:a'), 'metadata that names no versions');
        $this->assertNull($probe->versions('cargo', 'serde'), 'an ecosystem with no probe');
        $this->assertNull($probe->versions('npm', 'bad name!'));
        $this->assertSame(['1.0.0'], $probe->versions('npm', 'left-pad'), 'while a package that does answer keeps its list');
    }

    public function testTheEcosystemOfAPypiRecordIsThePipOne(): void
    {
        $probe = self::probe([RegistryProbe::PYPI . '/urllib3/json' => '{"releases":{"2.6.3":[{}]}}']);
        $this->assertSame(['2.6.3'], $probe->versions('PyPI', 'urllib3'));
    }
}
