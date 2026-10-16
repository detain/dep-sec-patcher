<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Ruby / Bundler with bundler-audit.
 *
 * `bundle lock --update` resolves and writes Gemfile.lock without installing
 * gems (the original shell script's `bundle update` installed them system-wide). The
 * advisory database is refreshed once, not once per Gemfile.
 */
final class RubyAuditor extends Auditor
{
    /** Bundler 2.6 documents its compact-index cache files as concurrency-safe. */
    public const CONCURRENT_SINCE = '2.6.0';

    public function name(): string
    {
        return 'ruby';
    }

    public function tool(): string
    {
        return 'bundle';
    }

    public function manifests(): array
    {
        return ['Gemfile'];
    }

    public function skipReason(Context $ctx): ?string
    {
        if (!ProcessRunner::has('bundle')) {
            return 'bundle not installed';
        }
        $r = $ctx->runner->run(['bundle', '--version'], $ctx->root, ['timeout' => 60, 'label' => 'ruby']);
        if (!$r->ok()) {
            return 'bundle is installed but does not run: ' . ($r->tail(1)[0] ?? $r->failureReason());
        }
        return null;
    }

    public function concurrency(Context $ctx): array
    {
        return ['ruby' => $this->gated(
            'bundler',
            $ctx->toolVersion('bundler', ['bundle', '--version']),
            self::CONCURRENT_SINCE,
            'Bundler before 2.6 does not protect its shared gem-index cache against concurrent writers'
        )];
    }

    public function prepare(Context $ctx, array $targets): void
    {
        if (!ProcessRunner::has('bundle-audit') && ProcessRunner::has('gem')) {
            $r = $ctx->runner->run(['gem', 'install', 'bundler-audit', '--no-document'], $ctx->root, ['label' => 'ruby:install']);
            if (!$r->ok()) {
                $ctx->console->warn('could not install bundler-audit: ' . $r->failureReason());
            }
        }
        if (!ProcessRunner::has('bundle-audit')) {
            $ctx->console->warn('bundler-audit not installed: Gemfiles will be updated but not audited');
            return;
        }
        $r = $ctx->runner->run(['bundle-audit', 'update', '--quiet'], $ctx->root, ['label' => 'ruby:advisory-db']);
        if (!$r->ok()) {
            $ctx->console->warn('bundle-audit advisory database update failed (' . $r->failureReason() . '); using the existing copy');
        }
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $notes = [];
        if (!$ctx->checkMode()) {
            $r = $this->run($ctx, $dir, ['bundle', 'lock', '--update']);
            if (!$r->ok()) {
                $notes[] = 'bundle lock --update ' . $r->failureReason();
            }
        } elseif (!$this->exists($ctx, $dir, 'Gemfile.lock')) {
            // bundle-audit reads the lockfile; the guard removes it again
            $r = $this->run($ctx, $dir, ['bundle', 'lock']);
            if (!$r->ok()) {
                return TargetResult::fromFailure($r, 'bundle lock (to create a lockfile)');
            }
        }
        if (!ProcessRunner::has('bundle-audit')) {
            $t = new TargetResult(TargetResult::WARN, 'bundler-audit not installed, not audited');
            $t->notes = $notes;
            return $t;
        }
        if (!$this->exists($ctx, $dir, 'Gemfile.lock')) {
            $t = new TargetResult(TargetResult::ERROR, 'no Gemfile.lock to audit');
            $t->notes = $notes;
            return $t;
        }

        $r    = $this->run($ctx, $dir, ['bundle-audit', 'check', '--format', 'json']);
        $data = self::json($r->stdout);
        if (!is_array($data) || !isset($data['results'])) {
            $t = TargetResult::fromFailure($r, 'bundle-audit');
            $t->notes = $notes;
            return $t;
        }
        $counts = [];
        $hits   = [];
        foreach ($data['results'] as $res) {
            $sev          = self::severity($res['advisory']['criticality'] ?? null);
            $counts[$sev] = ($counts[$sev] ?? 0) + 1;
            $hits[]       = ($res['gem']['name'] ?? $res['source'] ?? '?') . ' ' . ($res['gem']['version'] ?? '')
                . ': ' . ($res['advisory']['id'] ?? $res['type'] ?? '?');
        }
        $t = TargetResult::fromSeverities($counts, 'bundle-audit');
        $t->notes = array_merge($notes, array_slice($hits, 0, 10));
        return $t;
    }
}
