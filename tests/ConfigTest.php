<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Config;
use Detain\DepSecPatcher\Options;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The config file: loading, validation, and its place in the precedence
 * order (defaults < config < environment < command line).
 */
class ConfigTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    /**
     * @return array<string, mixed>
     */
    private static function full(): array
    {
        return [
            '$schema'        => 'ignored',
            '_comment'       => 'ignored too',
            'ecosystems'     => ['r' => false, 'swift' => false, 'maven' => true],
            'scanners'       => ['trivy' => false, 'bandit' => true, 'netsec' => false],
            'threads'        => 4,
            'timeout'        => 600,
            'nvd-timeout'    => 1200,
            'cvss-threshold' => 9,
            'max-issues'     => 50,
            'close-label'    => 'verified',
            'close-delay'    => 0,
            'close-limit'    => 10,
            'retriage'       => false,
            'allow-http'     => ['http://intranet.example/', '*.corp.example/'],
            'exclude-dirs'   => ['docs', './test/fixtures/'],
        ];
    }

    public function testLoadsEveryKey(): void
    {
        $o = Options::parse([], [], Config::fromArray(self::full()));
        $this->assertFalse($o->wants('r'));
        $this->assertFalse($o->wants('swift'));
        $this->assertTrue($o->wants('maven'));
        $this->assertFalse($o->wants('trivy'));
        $this->assertFalse($o->wants('grype'), 'grype follows trivy');
        $this->assertFalse($o->wants('netsec'));
        $this->assertSame('yes', $o->bandit);
        $this->assertSame(4, $o->threads);
        $this->assertSame(600, $o->timeout);
        $this->assertSame(1200, $o->nvdTimeout);
        $this->assertSame('9', $o->cvssThreshold);
        $this->assertSame(50, $o->maxIssues);
        $this->assertSame('verified', $o->closeLabel);
        $this->assertSame(0, $o->closeDelay);
        $this->assertSame(10, $o->closeLimit);
        $this->assertFalse($o->retriage);
        $this->assertSame(['intranet.example/', '*.corp.example/'], $o->allowHttp, 'http:// prefix dropped');
        $this->assertSame(['docs', 'test/fixtures'], $o->excludeDirs, 'paths normalised');
    }

    public function testCommandLineAndEnvironmentOverrideConfig(): void
    {
        $config = Config::fromArray(self::full() + ['only' => ['maven', 'node']]);
        $o = Options::parse(['-t', '2', '--timeout=0', '--cvss-threshold', '5', '--close-label', '', '--exclude-dir', 'extra', '--allow-http', 'x.test'], ['GH_REPO' => 'o/r'], $config);
        $this->assertSame(2, $o->threads);
        $this->assertSame(0, $o->timeout);
        $this->assertSame('5', $o->cvssThreshold);
        $this->assertSame('', $o->closeLabel);
        $this->assertSame(['docs', 'test/fixtures', 'extra'], $o->excludeDirs, 'CLI appends to the config list');
        $this->assertSame(['intranet.example/', '*.corp.example/', 'x.test'], $o->allowHttp);
        $this->assertSame('o/r', $o->ghRepo);
        $this->assertSame(['maven', 'node'], $o->only, 'config only applies without --only');

        $o = Options::parse(['--only', 'r,trivy'], [], $config);
        $this->assertSame(['r', 'trivy'], $o->only, 'CLI --only replaces the config list');
        $this->assertTrue($o->wants('r'), '--only re-enables an ecosystem the config disabled');
        $this->assertTrue($o->wants('trivy'), '--only re-enables a scanner the config disabled');

        $o = Options::parse(['--only', 'r', '--no-r'], [], $config);
        $this->assertFalse($o->wants('r'), 'an explicit --no-<name> still wins');

        $o = Options::parse(['--trivy'], [], Config::fromArray(self::full()));
        $this->assertTrue($o->wants('trivy'), '--trivy overrides the config');
    }

    public function testFromFile(): void
    {
        $dir = $this->scratchDir('config');
        file_put_contents($dir . '/' . Config::FILE, json_encode(['threads' => 3, 'ecosystems' => ['php' => false]]));
        $o = Options::parse([], [], Config::fromFile($dir . '/' . Config::FILE));
        $this->assertSame(3, $o->threads);
        $this->assertFalse($o->wants('php'));

        file_put_contents($dir . '/empty.json', '{}');
        $this->assertSame(1, Options::parse([], [], Config::fromFile($dir . '/empty.json'))->threads);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function badFiles(): array
    {
        return [
            'invalid json'   => ['{"threads": 2,', 'invalid JSON'],
            'not an object'  => ['[1, 2]', 'must be a JSON object'],
            'scalar'         => ['"x"', 'must be a JSON object'],
        ];
    }

    #[DataProvider('badFiles')]
    public function testBadFiles(string $content, string $message): void
    {
        $file = $this->scratchDir('config') . '/bad.json';
        file_put_contents($file, $content);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        Config::fromFile($file);
    }

    public function testMissingFile(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('config file not readable');
        Config::fromFile('/nonexistent/dep-sec-patcher.json');
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function badValues(): array
    {
        return [
            'unknown key'        => [['threds' => 2], 'unknown key "threds"'],
            'zero threads'       => [['threads' => 0], '"threads" must be a positive integer, got 0'],
            'string timeout'     => [['timeout' => '60'], '"timeout" must be a non-negative integer, got "60"'],
            'negative delay'     => [['close-delay' => -1], '"close-delay" must be a non-negative integer'],
            'float limit'        => [['close-limit' => 1.5], '"close-limit" must be a non-negative integer'],
            'cvss too high'      => [['cvss-threshold' => 11], 'must be a number from 0 to 10'],
            'cvss not numeric'   => [['cvss-threshold' => 'high'], 'must be a number from 0 to 10'],
            'label not string'   => [['close-label' => false], '"close-label" must be a string'],
            'ecosystems list'    => [['ecosystems' => ['maven']], '"ecosystems" must be an object'],
            'unknown ecosystem'  => [['ecosystems' => ['cobol' => false]], 'unknown name "cobol"'],
            'non-bool switch'    => [['scanners' => ['trivy' => 'no']], '"scanners"."trivy" must be true or false'],
            'unknown scanner'    => [['scanners' => ['snyk' => true]], 'unknown name "snyk"'],
            'only unknown'       => [['only' => ['maven', 'cobol']], "unknown check 'cobol'"],
            'only not list'      => [['only' => 'maven'], '"only" must be a list of strings'],
            'exclude escapes'    => [['exclude-dirs' => ['../up']], 'must be a relative path inside the target'],
            'exclude absolute'   => [['exclude-dirs' => ['/etc']], 'must be a relative path inside the target'],
            'exclude empty'      => [['exclude-dirs' => ['']], 'non-empty strings'],
            'allow-http spaces'  => [['allow-http' => ['a b']], 'without spaces'],
            'allow-http number'  => [['allow-http' => [1]], 'non-empty strings'],
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    #[DataProvider('badValues')]
    public function testValidation(array $data, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        Config::fromArray($data, 'cfg.json');
    }

    public function testErrorsNameTheFile(): void
    {
        try {
            Config::fromArray(['bogus' => 1], '/x/.dep-sec-patcher.json');
            $this->fail('expected an exception');
        } catch (InvalidArgumentException $e) {
            $this->assertStringStartsWith('/x/.dep-sec-patcher.json: ', $e->getMessage());
        }
    }
}
