<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Python: pip-audit (preferred) or safety against requirements.txt.
 *
 * The original shell script's snippet was missing a closing `fi`, so bash rejected it
 * and Python was never audited. It also ran
 * `pip install --break-system-packages -U -r requirements.txt`, which upgraded
 * packages in the host's own Python and never touched the sample; that is
 * gone. `pip-audit --fix` is what updates requirements.txt.
 */
final class PythonAuditor extends Auditor
{
    public function name(): string
    {
        return 'python';
    }

    public function tool(): string
    {
        return 'python3';
    }

    public function manifests(): array
    {
        return ['requirements.txt', 'pyproject.toml', 'Pipfile'];
    }

    public function skipReason(Context $ctx): ?string
    {
        if (!ProcessRunner::has('python3')) {
            return 'python3 not installed';
        }
        return ProcessRunner::has('pip-audit') || ProcessRunner::has('safety') ? null : 'neither pip-audit nor safety installed';
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        if (!$this->exists($ctx, $dir, 'requirements.txt')) {
            return new TargetResult(TargetResult::SKIP, 'no requirements.txt to audit');
        }
        if (!ProcessRunner::has('pip-audit')) {
            $r = $this->run($ctx, $dir, ['safety', 'check', '-r', 'requirements.txt']);
            if ($r->ok()) {
                return new TargetResult(TargetResult::PASS, 'safety: no known vulnerabilities');
            }
            // safety exits 64 when it found vulnerabilities
            $t = $r->exitCode === 64 && !$r->timedOut
                ? new TargetResult(TargetResult::FAIL, 'safety: vulnerabilities found', 1)
                : TargetResult::fromFailure($r, 'safety');
            $t->tail = $r->tail(20);
            return $t;
        }

        $argv = ['pip-audit', '-r', 'requirements.txt', '-f', 'json', '--progress-spinner', 'off'];
        if (!$ctx->checkMode()) {
            $argv[] = '--fix';
        }
        $r    = $this->run($ctx, $dir, $argv);
        $data = self::json($r->stdout);
        // pip-audit 2.x wraps the list in {"dependencies": [...]}, 1.x did not
        $deps = is_array($data) ? ($data['dependencies'] ?? (array_is_list($data) ? $data : null)) : null;
        if (!is_array($deps)) {
            return TargetResult::fromFailure($r, 'pip-audit');
        }
        $vulns = [];
        foreach ($deps as $dep) {
            foreach (($dep['vulns'] ?? []) as $v) {
                $vulns[] = ($dep['name'] ?? '?') . ' ' . ($dep['version'] ?? '') . ': ' . ($v['id'] ?? '?')
                    . (!empty($v['fix_versions']) ? ' (fixed in ' . implode(', ', $v['fix_versions']) . ')' : '');
            }
        }
        // pip-audit reports no severity, so every finding counts
        $t = TargetResult::fromSeverities($vulns === [] ? [] : ['unknown' => count($vulns)], 'pip-audit');
        foreach (array_slice($vulns, 0, 10) as $v) {
            $t->note($v);
        }
        foreach (($data['fixes'] ?? []) as $fix) {
            if (!empty($fix['new_version'])) {
                $t->note('fixed: ' . ($fix['name'] ?? '?') . ' ' . ($fix['old_version'] ?? '') . ' -> ' . $fix['new_version']);
            }
        }
        return $t;
    }
}
