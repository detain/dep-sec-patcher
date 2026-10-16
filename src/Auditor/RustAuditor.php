<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Rust: cargo update and cargo-audit. Cargo and cargo-audit both take file
 * locks on their shared state and wait for each other, so this runs in
 * parallel safely.
 */
final class RustAuditor extends Auditor
{
    public function name(): string
    {
        return 'rust';
    }

    public function tool(): string
    {
        return 'cargo';
    }

    public function manifests(): array
    {
        return ['Cargo.toml'];
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $notes = [];
        if (!$ctx->checkMode()) {
            $r = $this->run($ctx, $dir, ['cargo', 'update']);
            if (!$r->ok()) {
                $notes[] = 'cargo update ' . $r->failureReason();
            }
        } elseif (!$this->exists($ctx, $dir, 'Cargo.lock')) {
            // cargo audit reads the lockfile; the guard removes it again
            $r = $this->run($ctx, $dir, ['cargo', 'generate-lockfile']);
            if (!$r->ok()) {
                return TargetResult::fromFailure($r, 'cargo generate-lockfile');
            }
        }
        if (!ProcessRunner::has('cargo-audit')) {
            $t = new TargetResult(TargetResult::WARN, 'cargo-audit not installed, not audited');
            $t->notes = $notes;
            return $t;
        }
        $r    = $this->run($ctx, $dir, ['cargo', 'audit', '--json']);
        $data = self::json($r->stdout);
        if (!is_array($data) || !isset($data['vulnerabilities'])) {
            $t = TargetResult::fromFailure($r, 'cargo audit');
            $t->notes = $notes;
            return $t;
        }
        $list   = $data['vulnerabilities']['list'] ?? [];
        $counts = [];
        $hits   = [];
        foreach ($list as $v) {
            $sev          = self::severity($v['advisory']['severity'] ?? null);
            $counts[$sev] = ($counts[$sev] ?? 0) + 1;
            $hits[]       = ($v['package']['name'] ?? '?') . ' ' . ($v['package']['version'] ?? '') . ': ' . ($v['advisory']['id'] ?? '?');
        }
        $t = TargetResult::fromSeverities($counts, 'cargo audit');
        $t->notes = array_merge($notes, array_slice($hits, 0, 10));
        return $t;
    }
}
