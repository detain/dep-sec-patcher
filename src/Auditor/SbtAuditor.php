<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\TargetResult;

/**
 * SBT (Scala): informational dependencyUpdates via the sbt-updates plugin.
 * Without the plugin the task does not exist, so the project is skipped with
 * that reason rather than spending a JVM start on a guaranteed failure.
 */
final class SbtAuditor extends Auditor
{
    /** sbt 1.3 moved dependency resolution onto Coursier, whose cache is lock-protected. */
    public const CONCURRENT_SINCE = '1.3.0';

    public function name(): string
    {
        return 'sbt';
    }

    public function tool(): string
    {
        return 'sbt';
    }

    public function manifests(): array
    {
        return ['build.sbt'];
    }

    public function concurrency(Context $ctx): array
    {
        $version = $ctx->toolVersion('sbt', ['sbt', '--script-version']);
        return ['sbt' => $this->gated(
            'sbt',
            $version,
            self::CONCURRENT_SINCE,
            'sbt before 1.3 resolves through Ivy, whose shared cache is not safe for concurrent use'
        )];
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        if (!$this->hasUpdatesPlugin($ctx, $dir)) {
            return new TargetResult(TargetResult::SKIP, 'sbt-updates plugin not configured (dependencyUpdates unavailable)');
        }
        $argv = $ctx->checkMode()
            ? ['sbt', '-batch', 'dependencyUpdates']
            : ['sbt', '-batch', 'reload', 'set dependencyUpdates / onlyEval := false', 'dependencyUpdates'];
        $r = $this->run($ctx, $dir, $argv);
        $t = new TargetResult($r->ok() ? TargetResult::PASS : TargetResult::WARN, 'dependencyUpdates ' . ($r->ok() ? 'ok' : $r->failureReason()));
        $t->tail = $r->tail(20);
        return $t;
    }

    private function hasUpdatesPlugin(Context $ctx, string $dir): bool
    {
        $home  = getenv('HOME') ?: '';
        $files = array_merge(
            glob($this->abs($ctx, $dir) . '/project/*.sbt') ?: [],
            glob($home . '/.sbt/1.0/plugins/*.sbt') ?: []
        );
        foreach ($files as $file) {
            if (str_contains((string)@file_get_contents($file), 'sbt-updates')) {
                return true;
            }
        }
        return false;
    }
}
