<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Python: pip-audit (preferred) or safety against requirements files.
 *
 * The original shell script's snippet was missing a closing `fi`, so bash rejected it
 * and Python was never audited. It also ran
 * `pip install --break-system-packages -U -r requirements.txt`, which upgraded
 * packages in the host's own Python and never touched the project; that is
 * gone. `pip-audit --fix` is what updates requirements.txt.
 *
 * A directory is *detected* as Python by any dependency manifest — the
 * requirements spellings (requirements.txt, requirements-dev.txt,
 * dev-requirements.txt, ...), pyproject.toml, Pipfile, setup.py, setup.cfg
 * and poetry.lock — because silence about a directory full of Python code
 * reads as "nothing here". What actually gets *audited* is narrower: only
 * requirements-style files, the one shape both pip-audit and safety consume.
 * A directory detected through pyproject.toml/Pipfile/setup.py/setup.cfg/
 * poetry.lock alone prints a SKIP naming what was found, so the report says
 * what was seen and what was deliberately not touched.
 */
final class PythonAuditor extends Auditor
{
    /** Requirements-style names pip-audit/safety can consume with -r. */
    public const REQUIREMENTS_RX = '/^.*requirements.*\.txt$/i';

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
        return ['requirements.txt', '*requirements*.txt', 'pyproject.toml', 'Pipfile', 'setup.py', 'setup.cfg', 'poetry.lock'];
    }

    public function skipReason(Context $ctx): ?string
    {
        if (!ProcessRunner::has('python3')) {
            return 'python3 not installed';
        }
        return ProcessRunner::has('pip-audit') || ProcessRunner::has('safety') ? null : 'neither pip-audit nor safety installed';
    }

    /**
     * Requirements files in one directory, requirements.txt first, then the
     * rest sorted by name (requirements-dev.txt, dev-requirements.txt, ...).
     *
     * @return list<string> basenames
     */
    public static function requirementsFiles(callable $listDir): array
    {
        $found = array_values(array_filter($listDir(), static fn (string $f): bool => self::isRequirements($f)));
        usort($found, static fn (string $a, string $b): int => [$a !== 'requirements.txt', $a] <=> [$b !== 'requirements.txt', $b]);
        return $found;
    }

    public static function isRequirements(string $base): bool
    {
        return preg_match(self::REQUIREMENTS_RX, $base) === 1;
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $abs     = $this->abs($ctx, $dir);
        $listing = static function () use ($abs): array {
            $entries = @scandir($abs);
            return $entries === false ? [] : array_values(array_diff($entries, ['.', '..']));
        };
        $files = self::requirementsFiles($listing);
        if ($files === []) {
            // Detected as Python by a manifest pip-audit cannot consume. Say
            // which files were seen: a directory holding a pyproject.toml is
            // not a directory holding nothing, and "no requirements.txt"
            // alone does not tell anyone what is actually there.
            $seen = array_values(array_filter($listing(), static function (string $f): bool {
                return in_array($f, ['pyproject.toml', 'Pipfile', 'setup.py', 'setup.cfg', 'poetry.lock'], true);
            }));
            return new TargetResult(TargetResult::SKIP, 'no requirements file to audit'
                . ($seen === [] ? '' : ' (found ' . implode(', ', $seen) . '; pip-audit reads requirements files)'));
        }

        // Every requirements file in the directory is audited: a vulnerable
        // pin hiding in requirements-dev.txt is still a reportable finding.
        $results = [];
        foreach ($files as $file) {
            $results[] = $this->auditOne($ctx, $dir, $file);
        }
        return self::merge($results, $files);
    }

    private function auditOne(Context $ctx, string $dir, string $file): TargetResult
    {
        if (!ProcessRunner::has('pip-audit')) {
            $r = $this->run($ctx, $dir, ['safety', 'check', '-r', $file]);
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

        $argv = ['pip-audit', '-r', $file, '-f', 'json', '--progress-spinner', 'off'];
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

    /**
     * Several requirements files, one result for the directory: the worst
     * status wins, findings add up, and each file's own notes are kept under
     * the file they came from.
     *
     * @param list<TargetResult> $results
     * @param list<string>       $files
     */
    private static function merge(array $results, array $files): TargetResult
    {
        if (count($results) === 1) {
            return $results[0];
        }
        $rank  = [TargetResult::SKIP => 0, TargetResult::PASS => 1, TargetResult::WARN => 2, TargetResult::FAIL => 3, TargetResult::ERROR => 4];
        $m     = new TargetResult(TargetResult::PASS, '');
        $worst = TargetResult::PASS;
        foreach ($results as $i => $r) {
            if ($rank[$r->status] > $rank[$worst]) {
                $worst = $r->status;
                $m->detail = $r->detail;
            } elseif ($r->detail !== '' && !str_contains($m->detail, $r->detail)) {
                $m->detail = $m->detail === '' ? $r->detail : $m->detail . '; ' . $r->detail;
            }
            $m->vulns    += $r->vulns;
            $m->outdated += $r->outdated;
            $m->tail      = array_merge($m->tail, $r->tail);
            foreach ($r->notes as $note) {
                $m->notes[] = $files[$i] . ': ' . $note;
            }
        }
        $m->status = $worst;
        return $m;
    }
}
