<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Go: module updates, govulncheck, and optionally gosec (whose report now
 * goes to the report directory instead of being committed into the project).
 */
final class GoAuditor extends Auditor
{
    public function name(): string
    {
        return 'go';
    }

    public function tool(): string
    {
        return 'go';
    }

    public function manifests(): array
    {
        return ['go.mod'];
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $notes    = [];
        $outdated = 0;
        if ($ctx->checkMode()) {
            $r = $this->run($ctx, $dir, ['go', 'list', '-m', '-u', 'all']);
            if ($r->ok()) {
                foreach (preg_split('/\r?\n/', $r->stdout) ?: [] as $line) {
                    if (preg_match('/^(\S+) (\S+) \[(\S+)\]/', $line, $m) === 1) {
                        $outdated++;
                        if ($outdated <= 10) {
                            $notes[] = "outdated: {$m[1]} {$m[2]} -> {$m[3]}";
                        }
                    }
                }
            } else {
                $notes[] = 'go list -m -u ' . $r->failureReason();
            }
        } else {
            foreach ([['go', 'get', '-u', './...'], ['go', 'mod', 'tidy']] as $argv) {
                $r = $this->run($ctx, $dir, $argv);
                if (!$r->ok()) {
                    $notes[] = implode(' ', $argv) . ' ' . $r->failureReason();
                }
            }
        }

        if (ProcessRunner::has('govulncheck')) {
            $t = $this->govulncheck($ctx, $dir);
        } else {
            $t = new TargetResult(TargetResult::WARN, 'govulncheck not installed, not audited');
        }
        $t->outdated = $outdated;

        if ($ctx->opt->gosec !== 'no' && ProcessRunner::has('gosec')) {
            $report = $ctx->reportPath('gosec', $dir, 'gosec-results.json');
            $r      = $this->run($ctx, $dir, ['gosec', '-no-fail', '-quiet', '-fmt', 'json', '-out', $report, './...']);
            $data   = is_file($report) ? json_decode((string)file_get_contents($report), true) : null;
            if (is_array($data)) {
                $issues  = count($data['Issues'] ?? []);
                $notes[] = "gosec: {$issues} finding" . ($issues === 1 ? '' : 's') . " (report: {$report})";
            } else {
                $notes[] = 'gosec wrote no report (' . $r->failureReason() . '; usually the package does not build)';
            }
        }
        $t->notes = array_merge($notes, $t->notes);
        return $t;
    }

    /**
     * Symbol-level scan first (only reachable code counts). Generated SDKs
     * often do not compile, which makes that scan fail to load the packages;
     * fall back to a module-level scan of go.mod, which needs no build.
     */
    private function govulncheck(Context $ctx, string $dir): TargetResult
    {
        $r    = $this->run($ctx, $dir, ['govulncheck', './...']);
        $mode = 'reachable';
        if ($r->exitCode === 1 && !$r->timedOut) {
            $first = $r;
            $r     = $this->run($ctx, $dir, ['govulncheck', '-scan', 'module']);
            $mode  = 'module-level';
            if (!$r->ok() && $r->exitCode !== 3) {
                return TargetResult::fromFailure($first, 'govulncheck');
            }
        }
        $why = $mode === 'module-level' ? 'the packages do not build, so only go.mod was scanned, not which code is reachable' : '';
        if ($r->ok()) {
            $t = new TargetResult(TargetResult::PASS, "govulncheck: no {$mode} vulnerabilities");
            if ($why !== '') {
                $t->note($why);
            }
            return $t;
        }
        if ($r->exitCode !== 3 || $r->timedOut) {
            return TargetResult::fromFailure($r, 'govulncheck');
        }
        // 3 = vulnerabilities found
        [$modules, $stdlib] = self::parseFindings($r->stdout);
        $n = count($modules);
        // Standard-library findings belong to this host's Go toolchain, not
        // to the project, so on their own they do not fail it
        $t = $n > 0
            ? new TargetResult(TargetResult::FAIL, "govulncheck: {$n} {$mode} vulnerabilit" . ($n === 1 ? 'y' : 'ies') . ' in dependencies', $n)
            : new TargetResult(TargetResult::PASS, "govulncheck: no {$mode} vulnerabilities in dependencies");
        if ($why !== '') {
            $t->note($why);
        }
        foreach (array_slice($modules, 0, 10) as $line) {
            $t->note($line);
        }
        if ($stdlib !== []) {
            $t->note(count($stdlib) . ' more in the Go standard library of the local toolchain ('
                . explode(' ', $stdlib[0])[1] . '); upgrade Go on this host');
        }
        return $t;
    }

    /**
     * Split govulncheck text output into dependency findings and standard
     * library findings (which belong to the toolchain, not the project).
     *
     * @return array{0: list<string>, 1: list<string>} "id module@found -> fixed" lines, "id stdlib@version" lines
     */
    public static function parseFindings(string $out): array
    {
        $modules = [];
        $stdlib  = [];
        $blocks  = preg_split('/^(?=Vulnerability #\d+: )/m', $out) ?: [];
        foreach ($blocks as $block) {
            if (preg_match('/^Vulnerability #\d+: (\S+)/', $block, $id) !== 1) {
                continue;
            }
            $found = preg_match('/Found in: (\S+)/', $block, $f) === 1 ? $f[1] : '?';
            $fixed = preg_match('/Fixed in: (\S+)/', $block, $x) === 1 ? $x[1] : 'no fix';
            if (str_contains($block, 'Standard library')) {
                $stdlib[] = "{$id[1]} {$found}";
            } else {
                $modules[] = "{$id[1]} {$found} -> {$fixed}";
            }
        }
        return [array_values(array_unique($modules)), array_values(array_unique($stdlib))];
    }
}
