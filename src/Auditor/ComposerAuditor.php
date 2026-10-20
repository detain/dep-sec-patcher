<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\TargetResult;

/**
 * PHP / Composer. Updates with --no-install (the lockfile is all an audit
 * needs) and without scripts or plugins from the resolved packages.
 *
 * `composer audit --locked` reads the lockfile directly - vendor/ install
 * state is irrelevant to it (verified against Composer 2.10). A project
 * without a composer.lock (a library, usually) has no resolved transitive
 * state to audit: a freshly invented resolution is not what the project
 * installs, so the audit is skipped with a note instead. It used to be
 * fabricated, audited and deleted again, which reported vulnerabilities that
 * belonged to no real install of the project.
 */
final class ComposerAuditor extends Auditor
{
    /** Note (and SKIP reason) for a project whose lockfile is absent. */
    public const NO_LOCK_NOTE = 'no composer.lock: audit skipped (no resolved transitive state to audit; commit a composer.lock to have this project audited)';

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
        // The lockfile is the only thing an audit can honestly evaluate: it
        // records what gets installed. Without one there is nothing to check
        // - an invented resolution says nothing about the project - so the
        // project is reported SKIP with the reason instead of failing or
        // auditing a state nobody installs.
        if (!$this->exists($ctx, $dir, 'composer.lock')) {
            return new TargetResult(TargetResult::SKIP, self::NO_LOCK_NOTE);
        }
        return $this->updateAndAudit($ctx, $dir);
    }

    private function updateAndAudit(Context $ctx, string $dir): TargetResult
    {
        $notes = [];
        if (!$ctx->checkMode()) {
            $r = $this->update($ctx, $dir, ['-W'], $notes);
            if (!$r->ok()) {
                $notes[] = 'composer update ' . $r->failureReason();
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

    /**
     * composer update. Composer 2.9+ refuses to resolve to versions with
     * security advisories, so a requirement only an insecure version meets
     * fails the whole update; retry with that blocking off, so everything
     * else still updates and the audit reports what stayed insecure.
     *
     * @param list<string> $extra
     * @param list<string> $notes
     */
    private function update(Context $ctx, string $dir, array $extra, array &$notes): CommandResult
    {
        $argv = array_merge(['composer', 'update'], $extra, self::FLAGS);
        $r    = $this->run($ctx, $dir, $argv);
        if ($r->ok() || preg_match('/affected by security advisories|policy\.advisories|block-insecure/', $r->output) !== 1) {
            return $r;
        }
        $notes[] = 'only versions with security advisories satisfy the requirements; resolved with Composer\'s advisory blocking off';
        // COMPOSER_NO_SECURITY_BLOCKING is the Composer 2.9 name
        return $this->run($ctx, $dir, $argv, null, ['COMPOSER_NO_BLOCKING' => '1', 'COMPOSER_NO_SECURITY_BLOCKING' => '1']);
    }
}
