<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\TargetResult;

/**
 * SBT (Scala): informational dependencyUpdates via the sbt-updates plugin.
 *
 * A project or global configuration that already has the plugin is used as
 * it is. Otherwise the plugin is added for the one command with
 * --addPluginSbtFile, the way IDEs load theirs; sbt 2 ignores global plugins,
 * so for it that is the only way. Older sbt without the option is skipped
 * with the line to add, rather than spending a JVM start on a guaranteed
 * failure.
 *
 * sbt 2's runner defaults to its native client, which starts a server in the
 * background that outlives the command, so sbt always runs in the foreground.
 *
 * A build without project/build.properties predates sbt 2, which cannot load
 * an sbt 1 build definition ("value in is not a member of ..."), so it runs
 * on sbt 1 even when the runner is sbt 2's.
 */
final class SbtAuditor extends Auditor
{
    /** sbt 1.3 moved dependency resolution onto Coursier, whose cache is lock-protected. */
    public const CONCURRENT_SINCE = '1.3.0';
    /** Below this --addPluginSbtFile is not relied on (it works on 1.10 and 2.0). */
    public const INJECT_SINCE = '1.4.0';
    /** sbt-updates 0.7 supports sbt 1 and 2; 0.6.4 is the last release for sbt 0.13. */
    private const PLUGIN = 'addSbtPlugin("com.timushev.sbt" %% "sbt-updates" %% "%s")';
    /** The sbt a build that names no version runs on under sbt 2's runner. */
    public const SBT1 = '1.10.11';

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
        $version = $this->declaredVersion($ctx, $dir);
        $runner  = $ctx->toolVersion('sbt', ['sbt', '--script-version']);
        $argv    = ['sbt'];
        $notes   = [];
        if ($version === '' && (int)$runner >= 2) {
            // The runner still takes it for an sbt 2 build, which it would
            // hand to a background server: --server keeps it in the foreground
            $version = self::SBT1;
            $argv    = ['sbt', '--server', '-Dsbt.version=' . self::SBT1];
            $notes[] = 'no project/build.properties: ran sbt ' . self::SBT1 . " rather than the runner's sbt {$runner}";
        } elseif ($version === '') {
            $version = $runner;
        }
        if ((int)$version >= 2) {
            $argv[] = '--server';
        }
        // sbt would otherwise write a project/build.properties into a build without one
        $argv[] = '-Dsbt.skip.version.write=true';
        $global = self::globalPluginDir($version);
        if (!$this->hasUpdatesPlugin($ctx, $dir, $global)) {
            if ($version !== '' && version_compare($version, self::INJECT_SINCE, '<')) {
                $home = getenv('HOME') ?: '~';
                return new TargetResult(TargetResult::SKIP, "sbt-updates plugin not configured for sbt {$version} (dependencyUpdates"
                    . ' unavailable): add ' . sprintf(self::PLUGIN, str_starts_with($version, '0.') ? '0.6.4' : '0.7.1')
                    . " to {$home}/.sbt/{$global}/plugins/sbt-updates.sbt");
            }
            // Outside the tree, so the project is not touched
            $plugin = $ctx->reportPath('sbt', $dir, 'sbt-updates.sbt');
            file_put_contents($plugin, sprintf(self::PLUGIN, '0.7.1') . "\n");
            $argv[] = '--addPluginSbtFile=' . $plugin;
        }
        if ($version !== '' && version_compare($version, '1.6.0', '<')) {
            // Old sbt (0.13 tested) installs a SecurityManager, which Java 18+
            // refuses unless told to allow it; Java 24 removed it for good
            $java = (int)$ctx->toolVersion('java', ['java', '-version'], '/version "(?:1\.)?(\d+)/');
            if ($java >= 18 && $java < 24) {
                $argv[] = '-Djava.security.manager=allow';
            }
        }
        // Informational in both modes: sbt-updates only reports
        $argv = array_merge($argv, ['-batch', 'dependencyUpdates']);
        // SBT_NATIVE_CLIENT=true in the environment would turn the client on for sbt 1.4+ too
        $r = $this->run($ctx, $dir, $argv, null, ['SBT_NATIVE_CLIENT' => 'false']);
        $t = new TargetResult($r->ok() ? TargetResult::PASS : TargetResult::WARN, 'dependencyUpdates ' . ($r->ok() ? 'ok' : $r->failureReason()));
        $t->tail  = $r->tail(20);
        $t->notes = $notes;
        return $t;
    }

    /**
     * The sbt version project/build.properties names, or ''.
     */
    private function declaredVersion(Context $ctx, string $dir): string
    {
        $props = (string)@file_get_contents($this->abs($ctx, $dir) . '/project/build.properties');
        return preg_match('/^\s*sbt\.version\s*=\s*([0-9][^\s]*)/m', $props, $m) === 1 ? $m[1] : '';
    }

    /**
     * Directory under ~/.sbt whose plugins/ that sbt version loads globally,
     * or '' for sbt 2, which loads none.
     */
    public static function globalPluginDir(string $version): string
    {
        return match (true) {
            str_starts_with($version, '0.') => '0.13',
            (int)$version >= 2              => '',
            default                         => '1.0',
        };
    }

    private function hasUpdatesPlugin(Context $ctx, string $dir, string $global): bool
    {
        $files = glob($this->abs($ctx, $dir) . '/project/*.sbt') ?: [];
        if ($global !== '') {
            $files = array_merge($files, glob((getenv('HOME') ?: '') . "/.sbt/{$global}/plugins/*.sbt") ?: []);
        }
        foreach ($files as $file) {
            if (str_contains((string)@file_get_contents($file), 'sbt-updates')) {
                return true;
            }
        }
        return false;
    }
}
