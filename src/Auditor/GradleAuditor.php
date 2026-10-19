<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Gradle (Android, Kotlin): informational. dependencyUpdates needs the
 * ben-manes gradle-versions-plugin, which many projects do not apply, so
 * check mode reports that instead of running a build guaranteed to fail.
 *
 * Gradle locks its user home across processes, so concurrent builds are safe.
 */
final class GradleAuditor extends Auditor
{
    public function name(): string
    {
        return 'gradle';
    }

    public function tool(): string
    {
        return 'gradle';
    }

    public function manifests(): array
    {
        return ['gradlew'];
    }

    public function skipReason(Context $ctx): ?string
    {
        // A wrapper is enough on its own; a system gradle is only the fallback
        return ProcessRunner::has('gradle') || $ctx->files->any(['gradlew']) ? null : 'neither gradle nor gradlew found';
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        // sh, not ./gradlew: generated wrappers are often committed without +x.
        // Some are bash scripts (arrays), which sh cannot parse
        $cmd = ['gradle'];
        if ($this->exists($ctx, $dir, 'gradlew')) {
            $first = (string)strtok((string)@file_get_contents($this->abs($ctx, $dir) . '/gradlew', false, null, 0, 200), "\n");
            $cmd   = [str_contains($first, 'bash') ? 'bash' : 'sh', 'gradlew'];
        }
        $flags = ['--no-daemon', '-q', '--console=plain'];

        if ($ctx->checkMode()) {
            if (!$this->hasVersionsPlugin($ctx, $dir)) {
                return new TargetResult(TargetResult::SKIP, 'gradle-versions-plugin not applied (dependencyUpdates unavailable)');
            }
            $r = $this->run($ctx, $dir, array_merge($cmd, ['dependencyUpdates'], $flags));
            $what = 'dependencyUpdates';
        } else {
            $r = $this->run($ctx, $dir, array_merge($cmd, ['dependencies'], $flags));
            $what = 'dependency resolution';
        }
        if ($r->ok()) {
            return new TargetResult(TargetResult::PASS, "{$what} ok");
        }
        $t = new TargetResult(TargetResult::WARN, "{$what} " . $r->failureReason());
        $t->tail = $r->tail(15);
        return $t;
    }

    private function hasVersionsPlugin(Context $ctx, string $dir): bool
    {
        $files = glob($this->abs($ctx, $dir) . '/{build,settings}.gradle{,.kts}', GLOB_BRACE) ?: [];
        $home  = getenv('HOME') ?: '';
        $files = array_merge($files, glob($home . '/.gradle/init.d/*.gradle*') ?: []);
        foreach ($files as $file) {
            if (str_contains((string)@file_get_contents($file), 'com.github.ben-manes.versions')) {
                return true;
            }
        }
        return false;
    }
}
