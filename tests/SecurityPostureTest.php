<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Console;
use Detain\DepSecPatcher\SecurityRun;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * What --enable-posture does to a repository's security settings, driven
 * through the fake API seam the method already takes: every `gh api` write is
 * a recorded call returning a canned CommandResult, and the console lines are
 * captured rather than printed.
 */
class SecurityPostureTest extends TestCase
{
    /**
     * @param list<list<string>> $log
     * @param array<string, CommandResult> $responses endpoint needle => result
     * @return \Closure(list<string>): CommandResult
     */
    private static function api(array &$log, array $responses = []): \Closure
    {
        return static function (array $args) use (&$log, $responses): CommandResult {
            $log[] = $args;
            $joined = implode(' ', $args);
            foreach ($responses as $needle => $result) {
                if (str_contains($joined, $needle)) {
                    return $result;
                }
            }
            return self::res(0);
        };
    }

    private static function res(int $exit, string $output = ''): CommandResult
    {
        return new CommandResult('gh api', $exit, false, '', $output, 0.0);
    }

    /**
     * @param array<string, mixed>     $info
     * @param array<string, CommandResult> $responses
     * @param list<list<string>>       $log
     * @return array{0: list<string>, 1: string, 2: Console}
     */
    private function posture(bool $write, array $info, array &$log, array $responses = []): array
    {
        $stream = fopen('php://memory', 'w+b');
        $this->assertIsResource($stream);
        $c = new Console(false, '', $stream);
        $m = new ReflectionMethod(SecurityRun::class, 'reportSecurityPosture');
        /** @var list<string> $done */
        $done = $m->invoke(null, $write, 'o/r', $info, self::api($log, $responses), $c);
        rewind($stream);
        $text = (string)stream_get_contents($stream);
        fclose($stream);
        return [$done, $text, $c];
    }

    /**
     * @param array<string, string> $statuses
     * @return array<string, mixed>
     */
    private static function repo(string $visibility, array $statuses = []): array
    {
        $sa = [];
        foreach ($statuses as $key => $status) {
            $sa[$key] = ['status' => $status];
        }
        return ['visibility' => $visibility, 'security_and_analysis' => $sa];
    }

    public function testSecurityUpdatesAreEnabledWithOnePut(): void
    {
        $log = [];
        [$done, $text] = $this->posture(true, self::repo('private', [
            'dependabot_security_updates' => 'disabled',
            'secret_scanning'             => 'enabled',
        ]), $log, ['private-vulnerability-reporting' => self::res(1, 'HTTP 404')]);

        $this->assertSame(['dependabot-security-updates'], $done);
        $this->assertContains(['api', '-X', 'PUT', 'repos/o/r/vulnerability-alerts'], $log);
        $this->assertStringContainsString('[OK]   Dependabot security updates: enabled (was disabled)', $text);
    }

    public function testForbiddenSecurityUpdatesWarnWithoutFailing(): void
    {
        $log = [];
        [$done, $text, $c] = $this->posture(true, self::repo('private', [
            'dependabot_security_updates' => 'disabled',
            'secret_scanning'             => 'enabled',
        ]), $log, [
            'vulnerability-alerts'            => self::res(1, 'gh: Forbidden (HTTP 403)'),
            'private-vulnerability-reporting' => self::res(1, 'HTTP 404'),
        ]);

        $this->assertSame([], $done);
        $this->assertStringContainsString('cannot enable security updates: HTTP 403', $text);
        $this->assertStringContainsString('[WARN]', $text);
        $this->assertGreaterThan(0, $c->warn, 'a 403 is a warning, never a FAIL or an exception');
        $this->assertSame(0, $c->fail);
    }

    public function testSecretScanningIsSkippedWhenPrivate(): void
    {
        $log = [];
        [$done, $text] = $this->posture(true, self::repo('private', [
            'dependabot_security_updates' => 'enabled',
            'secret_scanning'             => 'disabled',
        ]), $log, ['private-vulnerability-reporting' => self::res(0)]);

        $this->assertNotContains('secret-scanning', $done);
        $paths = implode("\n", array_map(static fn (array $a): string => implode(' ', $a), $log));
        $this->assertStringNotContainsString('security_and_analysis[secret_scanning][status]', $paths, 'no PATCH for a private repo');
        $this->assertStringContainsString('advanced security licence', $text);
    }

    public function testSecretScanningAndPushProtectionPatchShapes(): void
    {
        $log = [];
        [$done] = $this->posture(true, self::repo('public', [
            'dependabot_security_updates'         => 'enabled',
            'secret_scanning'                     => 'disabled',
            'secret_scanning_push_protection'     => 'disabled',
        ]), $log);

        $this->assertContains('secret-scanning', $done);
        $this->assertContains('secret-scanning-push-protection', $done);
        $this->assertContains(
            ['api', '-X', 'PATCH', 'repos/o/r', '-f', 'security_and_analysis[secret_scanning][status]=enabled'],
            $log
        );
        $this->assertContains(
            ['api', '-X', 'PATCH', 'repos/o/r', '-f', 'security_and_analysis[secret_scanning_push_protection][status]=enabled'],
            $log
        );
    }

    public function testPushProtectionFollowsOnlyWhenScanningIsOn(): void
    {
        $log = [];
        // Secret scanning enable fails; push protection must not be attempted
        [$done] = $this->posture(true, self::repo('public', [
            'dependabot_security_updates'     => 'enabled',
            'secret_scanning'                 => 'disabled',
            'secret_scanning_push_protection' => 'disabled',
        ]), $log, ['secret_scanning][status]' => self::res(1, 'HTTP 451')]);

        $this->assertNotContains('secret-scanning', $done);
        $this->assertNotContains('secret-scanning-push-protection', $done);
        $paths = implode("\n", array_map(static fn (array $a): string => implode(' ', $a), $log));
        $this->assertStringNotContainsString('secret_scanning_push_protection', $paths);
    }

    public function testPrivateVulnerabilityReportingTreatsConflictAsAlreadyEnabled(): void
    {
        $log = [];
        [$done, $text] = $this->posture(true, self::repo('private', [
            'dependabot_security_updates' => 'enabled',
            'secret_scanning'             => 'enabled',
        ]), $log, ['private-vulnerability-reporting' => self::res(1, 'gh: Conflict (HTTP 409)')]);

        $this->assertSame(['private-vulnerability-reporting'], $done);
        $this->assertStringContainsString('Private vulnerability reporting: already enabled', $text);
        $this->assertContains(['api', '-X', 'POST', 'repos/o/r/private-vulnerability-reporting'], $log);
    }

    public function testEverySettingIsReportedInOrderWhenAllWereOff(): void
    {
        $log = [];
        [$done] = $this->posture(true, self::repo('public', [
            'dependabot_security_updates'     => 'disabled',
            'secret_scanning'                 => 'disabled',
            'secret_scanning_push_protection' => 'disabled',
        ]), $log);

        $this->assertSame([
            'dependabot-security-updates',
            'secret-scanning',
            'secret-scanning-push-protection',
            'private-vulnerability-reporting',
        ], $done);
        $this->assertCount(4, $log);
    }

    public function testNothingIsCalledWhenPostureIsOff(): void
    {
        $log = [];
        [$done, $text] = $this->posture(false, self::repo('public', [
            'dependabot_security_updates' => 'disabled',
            'secret_scanning'             => 'disabled',
        ]), $log);

        $this->assertSame([], $done);
        $this->assertSame([], $log, 'the default reports the settings and touches nothing');
        $this->assertStringContainsString('[FAIL] Secret scanning: disabled', $text);
        $this->assertStringContainsString('[FAIL] Dependabot security updates: disabled', $text);
    }

    public function testAlreadyEnabledSettingsAreReportedNotRewritten(): void
    {
        $log = [];
        [$done, $text] = $this->posture(true, self::repo('public', [
            'dependabot_security_updates'     => 'enabled',
            'secret_scanning'                 => 'enabled',
            'secret_scanning_push_protection' => 'enabled',
        ]), $log, ['private-vulnerability-reporting' => self::res(1, 'HTTP 404')]);

        $this->assertSame([], $done, 'only PVR was tried, and it was unavailable');
        $this->assertStringContainsString('[OK]   Secret scanning: enabled', $text);
        $this->assertStringContainsString('[OK]   Dependabot security updates: enabled', $text);
        $paths = implode("\n", array_map(static fn (array $a): string => implode(' ', $a), $log));
        $this->assertStringNotContainsString('-X PATCH', $paths);
        $this->assertStringNotContainsString('vulnerability-alerts', $paths);
    }

    public function testUnknownVisibilityDoesNotAttemptScanningWrite(): void
    {
        $log = [];
        // No visibility and no `private` key: the safe reading is not-public.
        [$done] = $this->posture(true, ['security_and_analysis' => [
            'dependabot_security_updates' => 'enabled',
            'secret_scanning'             => 'disabled',
        ]], $log, ['private-vulnerability-reporting' => self::res(0)]);

        $this->assertNotContains('secret-scanning', $done);
        $paths = implode("\n", array_map(static fn (array $a): string => implode(' ', $a), $log));
        $this->assertStringNotContainsString('secret_scanning][status]', $paths);
    }
}
