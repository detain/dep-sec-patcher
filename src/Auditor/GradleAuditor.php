<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;
use Detain\DepSecPatcher\Version;

/**
 * Gradle (Android, Kotlin): informational. dependencyUpdates needs the
 * ben-manes gradle-versions-plugin, which many projects do not apply, so
 * check mode reports that instead of running a build guaranteed to fail.
 *
 * Gradle locks its user home across processes, so concurrent builds are safe.
 *
 * Gradle runs on Java only up to a release that postdates it; on a newer
 * JVM a wrapper fails to compile its settings with "Unsupported class file
 * major version". Such a build runs on an installed JDK it supports, or is
 * skipped with what it needs.
 */
final class GradleAuditor extends Auditor
{
    /** Gradle release => the newest Java it runs on (docs.gradle.org compatibility matrix). */
    private const MAX_JAVA = [
        '9.1' => 25, '8.14' => 24, '8.10' => 23, '8.8' => 22, '8.5' => 21, '8.3' => 20, '7.6' => 19,
        '7.5' => 18, '7.3' => 17, '7.0' => 16, '6.7' => 15, '6.3' => 14, '6.0' => 13, '5.4' => 12, '5.0' => 11,
        '4.7' => 10, '4.3' => 9, '2.0' => 8,
    ];

    /**
     * @param list<string> $jvmRoots where to look for other JDKs
     */
    public function __construct(private readonly array $jvmRoots = ['/usr/lib/jvm'])
    {
    }

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
        $env = [];
        $notes = [];
        if ($this->exists($ctx, $dir, 'gradlew')) {
            $first = (string)strtok((string)@file_get_contents($this->abs($ctx, $dir) . '/gradlew', false, null, 0, 200), "\n");
            $cmd   = [str_contains($first, 'bash') ? 'bash' : 'sh', 'gradlew'];

            $gradle = self::wrapperVersion((string)@file_get_contents($this->abs($ctx, $dir) . '/gradle/wrapper/gradle-wrapper.properties'));
            $max    = self::maxJava($gradle);
            $home   = (string)getenv('JAVA_HOME');
            $java   = $home !== '' ? self::jdkMajor($home) : (int)$ctx->toolVersion('java', ['java', '-version'], '/version "(?:1\.)?(\d+)/');
            if ($max > 0 && $java > $max) {
                $jdk = self::jdk($max, $this->jvmRoots);
                if ($jdk === '') {
                    return new TargetResult(TargetResult::SKIP, "Gradle {$gradle} runs on Java {$max} at most, and this host has Java {$java}:"
                        . " install a JDK {$max} or older under " . implode(' or ', $this->jvmRoots) . ', or update the wrapper');
                }
                $env['JAVA_HOME'] = $jdk;
                $notes[] = "Gradle {$gradle} does not run on Java {$java}; ran on {$jdk}";
            }
        }
        $flags = ['--no-daemon', '-q', '--console=plain'];

        if ($ctx->checkMode()) {
            if (!$this->hasVersionsPlugin($ctx, $dir)) {
                return new TargetResult(TargetResult::SKIP, 'gradle-versions-plugin not applied (dependencyUpdates unavailable)');
            }
            $r = $this->run($ctx, $dir, array_merge($cmd, ['dependencyUpdates'], $flags), null, $env);
            $what = 'dependencyUpdates';
        } else {
            $r = $this->run($ctx, $dir, array_merge($cmd, ['dependencies'], $flags), null, $env);
            $what = 'dependency resolution';
        }
        if ($r->ok()) {
            $t = new TargetResult(TargetResult::PASS, "{$what} ok");
        } else {
            $t = new TargetResult(TargetResult::WARN, "{$what} " . $r->failureReason());
            $t->tail = self::failure($r);
        }
        $t->notes = $notes;
        return $t;
    }

    /**
     * Gradle's own account of a failure, its "Where" and "What went wrong"
     * sections, rather than the last lines, which are its generic "Try"
     * advice or the end of a stack trace.
     *
     * @return list<string>
     */
    public static function failure(CommandResult $r): array
    {
        $out = [];
        $in  = false;
        foreach ($r->tail(PHP_INT_MAX) as $line) {
            if (preg_match('/^\* (?:Where|What went wrong):/', $line) === 1) {
                $in = true;
            } elseif (preg_match('/^\* \w/', $line) === 1 || str_starts_with($line, 'BUILD FAILED')) {
                $in = false;
            }
            if ($in) {
                $out[] = $line;
            }
        }
        return $out === [] ? $r->tail(15) : array_slice($out, 0, 15);
    }

    /**
     * "gradle-7.0-bin.zip" in a wrapper's distributionUrl -> "7.0".
     */
    public static function wrapperVersion(string $properties): string
    {
        return preg_match('/^\s*distributionUrl\s*=.*gradle-(\d+(?:\.\d+)*)(?:-[a-z0-9-]+)?-(?:bin|all)\.zip/m', $properties, $m) === 1 ? $m[1] : '';
    }

    /**
     * The newest Java a Gradle release runs on; 0 when unknown (too old for
     * the table, or a release newer than it).
     */
    public static function maxJava(string $gradle): int
    {
        if ($gradle === '' || Version::compare(Version::branch($gradle), array_key_first(self::MAX_JAVA)) > 0) {
            return 0;
        }
        foreach (self::MAX_JAVA as $since => $java) {
            if (Version::gte($gradle, $since)) {
                return $java;
            }
        }
        return 0;
    }

    /**
     * The newest installed JDK at or below Java $max (and at least 8), or ''.
     *
     * @param list<string> $roots
     */
    public static function jdk(int $max, array $roots): string
    {
        $best = '';
        $bestMajor = 0;
        foreach ($roots as $root) {
            foreach (glob(rtrim($root, '/') . '/*', GLOB_ONLYDIR) ?: [] as $home) {
                $major = self::jdkMajor($home);
                if ($major >= 8 && $major <= $max && $major > $bestMajor && is_executable($home . '/bin/java')) {
                    [$best, $bestMajor] = [$home, $major];
                }
            }
        }
        return $best;
    }

    /**
     * A JDK's major version from its "release" file: JAVA_VERSION="17.0.12"
     * or "1.8.0_392"; 0 when unreadable.
     */
    public static function jdkMajor(string $home): int
    {
        $release = (string)@file_get_contents(rtrim($home, '/') . '/release');
        return preg_match('/^JAVA_VERSION="(?:1\.)?(\d+)/m', $release, $m) === 1 ? (int)$m[1] : 0;
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
