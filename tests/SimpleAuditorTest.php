<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\SimpleAuditor;
use Detain\DepSecPatcher\Console;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;
use PHPUnit\Framework\TestCase;

/**
 * Known tool failures get a cause rather than a bare exit status.
 */
class SimpleAuditorTest extends TestCase
{
    use Fixtures;

    /** What Dart 3 pub prints for a pubspec with no null-safe SDK constraint. */
    private const PUB_PRE_NULL_SAFETY = "Resolving dependencies...\nThe current Dart SDK version is 3.13.5.\n\n"
        . "Because swagger doesn't support null safety, version solving failed.\n\n"
        . "The lower bound of \"sdk: '<2.0.0'\" must be 2.12.0 or higher to enable null safety.\n"
        . "For details, see https://dart.dev/null-safety\n";

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testDartPreNullSafetyIsNamed(): void
    {
        $this->assertSame(
            "swagger predates null safety (sdk '<2.0.0'; Dart 3 needs >=2.12.0): not upgradable, the code must be migrated or, for a generated client, regenerated",
            SimpleAuditor::dartFailure(self::PUB_PRE_NULL_SAFETY)
        );
        $this->assertNull(SimpleAuditor::dartFailure("Because app depends on http ^9.0.0 which doesn't match any versions, version solving failed.\n"));
    }

    public function testDartUpgradeFailureCarriesTheCause(): void
    {
        $root = $this->scratchDir('dart');
        $bin  = $this->scratchDir('dart-bin');
        file_put_contents($root . '/pubspec.yaml', "name: swagger\n");
        file_put_contents($bin . '/dart', "#!/bin/sh\nprintf '%s' " . escapeshellarg(self::PUB_PRE_NULL_SAFETY) . " >&2\nexit 1\n");
        chmod($bin . '/dart', 0755);
        $this->setEnv('PATH', $bin . ':/usr/bin:/bin');

        $out = fopen('php://memory', 'w+');
        $this->assertIsResource($out);
        $console = new Console(false, '[t]', $out);
        $ctx = new Context(Options::parse(['--update', '--allow-major'], []), $console, new ProcessRunner($console, 30), $root, $root . '/reports', new ManifestIndex($root, ''));
        $t = SimpleAuditor::dart()->audit($ctx, '');
        $this->assertSame(TargetResult::WARN, $t->status);
        $this->assertStringStartsWith('dart pub upgrade --major-versions: swagger predates null safety', $t->detail);
        $this->assertNotSame([], $t->tail, 'the output tail is kept');
    }
}
