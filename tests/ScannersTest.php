<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\SimpleAuditor;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\Scanner\Scanners;
use Detain\DepSecPatcher\TargetResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Trivy's Maven Central rate-limit handling and Elixir's check-mode steps,
 * driven through stand-in tools on PATH.
 */
class ScannersTest extends TestCase
{
    use Fixtures;

    private const LIMITED = "2026-10-16T17:08:34-04:00\tFATAL\tError\tremote Maven repository returned 429 Too Many Requests"
        . " for https://repo.maven.apache.org/maven2/io/micronaut/micronaut-parent/4.4.0/micronaut-parent-4.4.0.pom. Retry-After: %s.\n"
        . "The repository blocks all subsequent requests from this IP until the block clears.\n";

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    /**
     * @return array<string, array{string, ?int}>
     */
    public static function rateLimitOutputs(): array
    {
        return [
            'trivy 429 with Retry-After' => [sprintf(self::LIMITED, '1600'), 1600],
            'short block'                => [sprintf(self::LIMITED, '45'), 45],
            'no usable Retry-After'      => ["remote Maven repository returned 429 Too Many Requests for https://x/y.pom\n", 60],
            'other failure'              => ["FATAL\tError\tunable to initialize scanner\n", null],
            'clean run'                  => ['', null],
        ];
    }

    #[DataProvider('rateLimitOutputs')]
    public function testRateLimitWait(string $output, ?int $expected): void
    {
        $this->assertSame($expected, Scanners::rateLimitWait($output));
    }

    public function testShortRateLimitIsWaitedOutAndRetried(): void
    {
        [$t, $calls] = $this->trivyWith(['1', 'ok']);
        $this->assertSame(TargetResult::FAIL, $t->status, 'the retried scan is reported');
        $this->assertCount(2, $calls);
        $this->assertStringNotContainsString('--offline-scan', implode("\n", $calls));
    }

    public function testLongRateLimitFallsBackToOfflineWithoutWaiting(): void
    {
        $start       = microtime(true);
        [$t, $calls] = $this->trivyWith(['1600']);
        $this->assertLessThan(5, microtime(true) - $start, 'a 1600s block is not waited out');
        $this->assertCount(2, $calls);
        $this->assertStringContainsString('--offline-scan', $calls[1]);
        $this->assertStringContainsString('offline scan', $t->detail);
        $this->assertSame(TargetResult::FAIL, $t->status, 'offline findings are still reported');
    }

    public function testRepeatedRateLimitFallsBackToOfflineAfterOneRetry(): void
    {
        [$t, $calls] = $this->trivyWith(['1', '1']);
        $this->assertCount(3, $calls);
        $this->assertStringNotContainsString('--offline-scan', $calls[1]);
        $this->assertStringContainsString('--offline-scan', $calls[2]);
        $this->assertStringContainsString('offline scan', $t->detail);
    }

    public function testElixirCheckModeFetchesDependenciesBeforeAuditing(): void
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/mix', "#!/bin/sh\necho \"\$*\" >> " . escapeshellarg($log) . "\n");
        chmod($bin . '/mix', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));

        $root = $this->scratchDir('elixir');
        file_put_contents($root . '/mix.exs', '');
        $t = SimpleAuditor::elixir()->audit($this->context($root, ['--check']), '');

        $this->assertSame(TargetResult::PASS, $t->status);
        $this->assertSame(['deps.get', 'hex.audit'], file($log, FILE_IGNORE_NEW_LINES));
    }

    /**
     * Run Scanners::trivy against a stand-in trivy that answers each online
     * call with the next scripted response: a Retry-After value (a 429 and
     * exit 1) or "ok". An --offline-scan call always succeeds.
     *
     * @param list<string> $responses
     * @return array{TargetResult, list<string>}
     */
    private function trivyWith(array $responses): array
    {
        $bin   = $this->scratchDir('bin');
        $log   = $bin . '/calls.log';
        $queue = $bin . '/responses';
        file_put_contents($queue, implode("\n", $responses) . "\n");
        $report = json_encode(['Results' => [['Vulnerabilities' => [['Severity' => 'HIGH']]]]]);
        $limited = addcslashes(sprintf(self::LIMITED, '$next'), '"');
        file_put_contents($bin . '/trivy', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            out=''
            prev=''
            for a in "\$@"; do [ "\$prev" = --output ] && out="\$a"; prev="\$a"; done
            case " \$* " in *" --offline-scan "*) printf '%s' '{$report}' > "\$out"; exit 0;; esac
            next=\$(head -n 1 '{$queue}'); sed -i 1d '{$queue}'
            if [ "\$next" = ok ]; then printf '%s' '{$report}' > "\$out"; exit 0; fi
            printf "{$limited}" >&2
            exit 1
            SH);
        chmod($bin . '/trivy', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));

        $t = Scanners::trivy($this->context($this->scratchDir('tree'), ['--check']));
        return [$t, file($log, FILE_IGNORE_NEW_LINES) ?: []];
    }

    /**
     * @param list<string> $args
     */
    private function context(string $root, array $args): Context
    {
        [$console, $runner] = $this->quietRunner(30);
        return new Context(Options::parse($args, []), $console, $runner, $root, $this->scratchDir('reports'), ManifestIndex::fromList($root, []));
    }
}
