<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\TargetResult;

/**
 * PHP / Composer. Resolves with --no-install (the lockfile is all an audit
 * needs; vendor/ was deleted afterwards anyway) and without scripts or
 * plugins from the resolved packages.
 */
final class ComposerAuditor extends Auditor
{
    private const FLAGS = ['--no-install', '--no-interaction', '--no-scripts', '--no-plugins', '--no-progress'];

    public function name(): string
    {
        return 'php';
    }

    public function tool(): string
    {
        return 'composer';
    }

    public function manifests(): array
    {
        return ['composer.json'];
    }

    public function concurrency(Context $ctx): array
    {
        return ['php' => ConcurrencyPolicy::serial(
            'composer',
            $ctx->toolVersion('composer', ['composer', '--version', '--no-ansi']),
            'Composer\'s shared cache and temp files are not safe for concurrent use (no fixed version known)'
        )];
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $notes = [];
        if (!$ctx->checkMode()) {
            $r = $this->run($ctx, $dir, array_merge(['composer', 'update', '-W'], self::FLAGS));
            if (!$r->ok()) {
                $notes[] = 'composer update ' . $r->failureReason();
            }
        } elseif (!$this->exists($ctx, $dir, 'composer.lock')) {
            // composer audit needs a lockfile; the guard removes it again
            $r = $this->run($ctx, $dir, array_merge(['composer', 'update'], self::FLAGS));
            if (!$r->ok()) {
                return TargetResult::fromFailure($r, 'composer update (to create a lockfile)');
            }
        }

        $r    = $this->run($ctx, $dir, ['composer', 'audit', '--locked', '--no-interaction', '--format=json']);
        $data = self::json($r->stdout);
        if (!is_array($data) || !array_key_exists('advisories', $data)) {
            if ($r->ok() && str_contains($r->output, 'No packages')) {
                $t = new TargetResult(TargetResult::PASS, 'composer audit: no packages to audit');
                $t->notes = $notes;
                return $t;
            }
            $t = TargetResult::fromFailure($r, 'composer audit');
            $t->notes = $notes;
            return $t;
        }
        $counts = [];
        foreach ((array)$data['advisories'] as $advisories) {
            foreach ((array)$advisories as $advisory) {
                $sev          = self::severity($advisory['severity'] ?? null);
                $counts[$sev] = ($counts[$sev] ?? 0) + 1;
            }
        }
        $t = TargetResult::fromSeverities($counts, 'composer audit');
        $abandoned = array_keys((array)($data['abandoned'] ?? []));
        if ($abandoned !== []) {
            $notes[] = 'abandoned: ' . implode(', ', $abandoned);
        }
        $t->notes = array_merge($notes, $t->notes);
        return $t;
    }
}
