<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Console;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\Environment;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\Scanner\NetworkScanner;
use Detain\DepSecPatcher\Scanner\Scanners;
use Detain\DepSecPatcher\Target;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * What gets scanned: --subdir, extra excluded directories, extra allowed
 * plain-HTTP prefixes, the new options, and the tool PATH.
 */
class ScopeTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    private function tree(): string
    {
        $root = $this->scratchDir('scope');
        foreach (['api/js/package.json', 'api/php/composer.json', 'api/docs/package.json', 'api/test/fixtures/package.json',
            'other/package.json', 'docs/package.json', 'package.json'] as $f) {
            @mkdir(dirname($root . '/' . $f), 0775, true);
            file_put_contents($root . '/' . $f, '{}');
        }
        return $root;
    }

    public function testSubdirKeepsRootRelativePaths(): void
    {
        $index = new ManifestIndex($this->tree(), 'api');
        $this->assertSame(['api/docs', 'api/js', 'api/test/fixtures'], $index->dirsWith(['package.json']));
        $this->assertSame(['api/php'], $index->dirsWith(['composer.json']));
    }

    public function testExtraExcludes(): void
    {
        $root = $this->tree();
        $index = new ManifestIndex($root, '', ['docs', 'api/test/fixtures']);
        $this->assertSame(['', 'api/js', 'other'], $index->dirsWith(['package.json']), 'a name prunes everywhere, a path only there');

        $this->assertSame([], (new ManifestIndex($root, 'docs', ['docs']))->files(), 'an excluded --subdir scans nothing');
    }

    public function testScannerExcludesAreRelativeToTheScanRoot(): void
    {
        $opt = Options::parse(['--exclude-dir', 'docs', '--exclude-dir', 'api/test/fixtures', '--exclude-dir', 'other/x'], []);
        $out = fopen('php://memory', 'w+');
        $this->assertIsResource($out);
        $console = new Console(false, '[t]', $out);
        $ctx = new Context($opt, $console, new ProcessRunner($console, 10), '/r', '/reports', ManifestIndex::fromList('/r', []), 'api');
        $this->assertSame('/r/api', $ctx->scanRoot());
        $this->assertSame(['docs', 'test/fixtures'], Scanners::extraExcludes($ctx), 'paths outside --subdir are dropped');
    }

    public function testTargetScope(): void
    {
        $t = new Target('/r', 'api');
        $this->assertTrue($t->inScope('api/js/package.json'));
        $this->assertTrue($t->inScope('/api/js/package.json'));
        $this->assertFalse($t->inScope('apiv2/package.json'), 'prefix is not containment');
        $this->assertFalse($t->inScope('other/package.json'));
        $this->assertSame('/r/api', $t->scanRoot());
        $this->assertTrue((new Target('/r'))->inScope('anything/at/all'));
    }

    public function testNetworkScannerAllowHttpExtendsDefaults(): void
    {
        $files = ['a.yaml' => "u: http://intranet.corp.example/api\n", 'b.yaml' => "u: http://localhost:8080\n", 'c.yaml' => "u: http://api.vendor.test/x\n"];
        $read  = static fn (string $f): string => $files[$f];
        $this->assertSame(['a.yaml', 'c.yaml'], NetworkScanner::scan(array_keys($files), $read)['http']);
        $this->assertSame(['c.yaml'], NetworkScanner::scan(array_keys($files), $read, ['*.corp.example/'])['http'], 'wildcard prefix');
        $this->assertSame([], NetworkScanner::scan(array_keys($files), $read, ['*.corp.example/', 'http://api.vendor.test/'])['http']);
        $this->assertSame(1, preg_match(NetworkScanner::allowPattern(), 'http://www.w3.org/2001/XMLSchema'));
        $this->assertSame(0, preg_match(NetworkScanner::allowPattern(['a.b']), 'http://axb'), 'dots are literal');
    }

    public function testNewOptions(): void
    {
        $o = Options::parse(['--subdir', './api/', '--state-dir', 's', '--workdir', 'w', '--config', 'c.json', '--push',
            '--branch', 'sec/fix-1', '--strict', '--no-grype', '--no-netsec', '-V', 'owner/name'], []);
        $this->assertSame('api', $o->subdir);
        $this->assertSame('s', $o->stateDir);
        $this->assertSame('w', $o->workdir);
        $this->assertSame('c.json', $o->configFile);
        $this->assertTrue($o->push);
        $this->assertSame('sec/fix-1', $o->branch);
        $this->assertTrue($o->strict);
        $this->assertTrue($o->version);
        $this->assertFalse($o->wants('grype'));
        $this->assertTrue($o->wants('trivy'), '--no-grype leaves trivy alone');
        $this->assertFalse($o->wants('netsec'));
        $this->assertSame('owner/name', $o->target);
    }

    /**
     * @return array<string, array{list<string>, string}>
     */
    public static function badNewArgs(): array
    {
        return [
            'profile is gone'     => [['--profile', 'x'], 'unknown option: --profile'],
            'project is gone'     => [['--project', 'x'], 'unknown option: --project'],
            'list-profiles gone'  => [['--list-profiles'], 'unknown option: --list-profiles'],
            'two targets'         => [['a', 'b'], 'only one TARGET'],
            'subdir escapes'      => [['--subdir', '../x'], '--subdir must be a relative path'],
            'subdir absolute'     => [['--subdir', '/etc'], '--subdir must be a relative path'],
            'bad branch'          => [['--branch', 'a..b'], 'not a valid branch name'],
            'bad allow-http'      => [['--allow-http', 'a b'], 'without spaces'],
        ];
    }

    /**
     * @param list<string> $argv
     */
    #[DataProvider('badNewArgs')]
    public function testNewOptionErrors(array $argv, string $message): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($message);
        Options::parse($argv, []);
    }

    public function testToolPath(): void
    {
        $dirs = ['/usr/local/go/bin', '/h/go/bin', '/h/.cargo/bin', '/h/.dotnet/tools', '/sdk/candidates/maven/current/bin'];
        $isDir = static fn (string $d): bool => in_array($d, $dirs, true);
        $glob  = static fn (string $p): array => $p === '/sdk/candidates/*/current/bin' ? ['/sdk/candidates/maven/current/bin'] : [];

        $path = Environment::toolPath(['HOME' => '/h', 'PATH' => '/usr/bin:/h/go/bin:/bin', 'SDKMAN_DIR' => '/sdk'], $isDir, $glob);
        $this->assertSame('/usr/local/go/bin:/h/go/bin:/h/.cargo/bin:/h/.dotnet/tools:/sdk/candidates/maven/current/bin:/usr/bin:/bin', $path);

        $path = Environment::toolPath(['HOME' => '/h', 'PATH' => '/bin', 'GOPATH' => '/g1:/g2', 'CARGO_HOME' => '/c'], static fn (string $d): bool => true, static fn (string $p): array => []);
        $this->assertSame('/usr/local/go/bin:/g1/bin:/g2/bin:/c/bin:/h/.dotnet/tools:/bin', $path);

        $this->assertSame('/usr/local/bin:/usr/bin:/bin', Environment::toolPath([], static fn (string $d): bool => false), 'no HOME, no PATH');
    }
}
