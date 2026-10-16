<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Node: npm, yarn or pnpm depending on the lockfile present.
 *
 * Lockfile-only operations throughout (--package-lock-only), with install
 * scripts disabled: the audited tree never needs node_modules, so downloading every
 * tarball and running third-party postinstall hooks on this host bought
 * nothing.
 */
final class NodeAuditor extends Auditor
{
    /** Yarn 2+ (Berry) documents its cache as safe to share between concurrent instances. */
    public const YARN_CONCURRENT_SINCE = '2.0.0';

    public function name(): string
    {
        return 'node';
    }

    public function tool(): string
    {
        return 'npm';
    }

    public function manifests(): array
    {
        return ['package.json'];
    }

    public function group(Context $ctx, string $dir): string
    {
        return 'node:' . $this->manager($ctx, $dir);
    }

    public function concurrency(Context $ctx): array
    {
        $policies = [
            'node:npm'  => ConcurrencyPolicy::unlimited('npm'),
            'node:pnpm' => ConcurrencyPolicy::unlimited('pnpm'),
        ];
        $policies['node:yarn'] = $this->gated(
            'yarn',
            $this->yarnVersion($ctx),
            self::YARN_CONCURRENT_SINCE,
            'Yarn 1 can corrupt its shared cache when several installs run at once'
        );
        return $policies;
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        return match ($this->manager($ctx, $dir)) {
            'yarn'  => $this->yarn($ctx, $dir),
            'pnpm'  => $this->pnpm($ctx, $dir),
            default => $this->npm($ctx, $dir),
        };
    }

    private function manager(Context $ctx, string $dir): string
    {
        if ($this->exists($ctx, $dir, 'yarn.lock') && ProcessRunner::has('yarn')) {
            return 'yarn';
        }
        if ($this->exists($ctx, $dir, 'pnpm-lock.yaml') && ProcessRunner::has('pnpm')) {
            return 'pnpm';
        }
        return 'npm';
    }

    private function npm(Context $ctx, string $dir): TargetResult
    {
        $quiet = ['--ignore-scripts', '--no-audit', '--no-fund'];
        $notes = [];
        // npm audit needs a lockfile; in check mode the guard removes it again
        $r = $this->run($ctx, $dir, array_merge(['npm', 'install', '--package-lock-only'], $quiet));
        if (!$r->ok()) {
            return TargetResult::fromFailure($r, 'npm install --package-lock-only');
        }
        if (!$ctx->checkMode()) {
            $r = $this->run($ctx, $dir, array_merge(['npm', 'update', '--package-lock-only'], $quiet));
            if (!$r->ok()) {
                $notes[] = 'npm update ' . $r->failureReason();
            }
            $r = $this->run($ctx, $dir, ['npm', 'audit', 'fix', '--force', '--package-lock-only', '--ignore-scripts', '--no-fund']);
            if (!$r->ok()) {
                $notes[] = 'npm audit fix ' . $r->failureReason();
            }
        }
        $argv = ['npm', 'audit', '--json'];
        if ($ctx->checkMode()) {
            $argv[] = '--omit=dev';
        }
        $result = $this->fromCounts($this->run($ctx, $dir, $argv), 'npm audit', static fn ($d) => $d['metadata']['vulnerabilities'] ?? null);
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    private function pnpm(Context $ctx, string $dir): TargetResult
    {
        $notes = [];
        if (!$ctx->checkMode()) {
            $r = $this->run($ctx, $dir, ['pnpm', 'up', '--latest'], null, ['npm_config_ignore_scripts' => 'true']);
            if (!$r->ok()) {
                $notes[] = 'pnpm up ' . $r->failureReason();
            }
        }
        $result = $this->fromCounts($this->run($ctx, $dir, ['pnpm', 'audit', '--json']), 'pnpm audit', static fn ($d) => $d['metadata']['vulnerabilities'] ?? null);
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    private function yarn(Context $ctx, string $dir): TargetResult
    {
        $berry = version_compare($this->yarnVersion($ctx) ?: '1', '2', '>=');
        $notes = [];
        if (!$ctx->checkMode()) {
            if ($berry) {
                $notes[] = 'yarn ' . $this->yarnVersion($ctx) . ': dependency upgrade not automated for Yarn 2+';
            } else {
                $r = $this->run($ctx, $dir, ['yarn', 'upgrade', '--ignore-scripts', '--non-interactive']);
                if (!$r->ok()) {
                    $notes[] = 'yarn upgrade ' . $r->failureReason();
                }
            }
        }
        if ($berry) {
            $r = $this->run($ctx, $dir, ['yarn', 'npm', 'audit', '--all', '--json']);
            $counts = [];
            foreach (preg_split('/\r?\n/', $r->stdout) ?: [] as $line) {
                $row = json_decode($line, true);
                if (is_array($row) && isset($row['children']['Severity'])) {
                    $sev = self::severity($row['children']['Severity']);
                    $counts[$sev] = ($counts[$sev] ?? 0) + 1;
                }
            }
            $result = ($r->exitCode > 1 || $r->timedOut) && $counts === []
                ? TargetResult::fromFailure($r, 'yarn npm audit')
                : TargetResult::fromSeverities($counts, 'yarn npm audit');
        } else {
            $r = $this->run($ctx, $dir, ['yarn', 'audit', '--json', '--non-interactive']);
            $summary = null;
            foreach (preg_split('/\r?\n/', $r->stdout) ?: [] as $line) {
                $row = json_decode($line, true);
                if (is_array($row) && ($row['type'] ?? '') === 'auditSummary') {
                    $summary = $row['data']['vulnerabilities'] ?? null;
                }
            }
            $result = is_array($summary)
                ? TargetResult::fromSeverities(self::normalise($summary), 'yarn audit')
                : TargetResult::fromFailure($r, 'yarn audit');
        }
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    /**
     * npm/pnpm style {info, low, moderate, high, critical, total}.
     */
    private function fromCounts(CommandResult $r, string $what, callable $pick): TargetResult
    {
        $data   = self::json($r->stdout);
        $counts = is_array($data) ? $pick($data) : null;
        if (!is_array($counts)) {
            $t = TargetResult::fromFailure($r, $what);
            if (is_array($data) && isset($data['error']['summary'])) {
                $t->detail = $what . ': ' . $data['error']['summary'];
            }
            return $t;
        }
        return TargetResult::fromSeverities(self::normalise($counts), $what);
    }

    /**
     * @param array<string, mixed> $counts
     * @return array<string, int>
     */
    private static function normalise(array $counts): array
    {
        $out = [];
        foreach ($counts as $sev => $n) {
            if ($sev === 'total' || !is_numeric($n)) {
                continue;
            }
            $key       = self::severity((string)$sev);
            $out[$key] = ($out[$key] ?? 0) + (int)$n;
        }
        return $out;
    }

    private function yarnVersion(Context $ctx): string
    {
        return $ctx->toolVersion('yarn', ['yarn', '--version']);
    }
}
