<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Scanner;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Whole-tree scanners: bandit, Trivy, grype.
 *
 * Each runs once over the scanned tree and writes its report to the report
 * directory. The original shell script ran bandit -r in every directory holding a .py
 * file (so nested code was scanned repeatedly) and wrote bandit/trivy/gosec
 * JSON into the audited directories, where it ended up committed to the
 * published repository. Its Trivy call used --security-checks, which current Trivy
 * rejects, and the error was swallowed.
 */
final class Scanners
{
    /**
     * Longest Retry-After worth waiting out when Maven Central rate-limits
     * Trivy's POM lookups. A longer block (Central has answered with 1600s)
     * goes straight to --offline-scan instead.
     */
    public const RATE_LIMIT_MAX_WAIT = 300;

    public static function bandit(Context $ctx): TargetResult
    {
        if (!ProcessRunner::has('bandit')) {
            return new TargetResult(TargetResult::SKIP, 'bandit not installed');
        }
        if (!$ctx->files->any(['*.py'])) {
            return new TargetResult(TargetResult::SKIP, 'no Python files');
        }
        $report = $ctx->reportPath('bandit', '', 'bandit-results.json');
        @unlink($report);
        $dirs    = array_merge(['node_modules', 'vendor', '.git', 'target', '.venv', 'build'], self::extraExcludes($ctx));
        $exclude = implode(',', array_map(static fn ($d) => "*/{$d}/*", $dirs));
        $r = $ctx->runner->run(['bandit', '-r', '.', '-q', '-f', 'json', '-o', $report, '-x', $exclude], $ctx->scanRoot(), ['label' => 'bandit']);
        $data = is_file($report) ? json_decode((string)file_get_contents($report), true) : null;
        if (!is_array($data) || !isset($data['results'])) {
            return TargetResult::fromFailure($r, 'bandit');
        }
        $bySev = [];
        foreach ($data['results'] as $res) {
            $sev         = strtolower((string)($res['issue_severity'] ?? 'unknown'));
            $bySev[$sev] = ($bySev[$sev] ?? 0) + 1;
        }
        $total = array_sum($bySev);
        $parts = [];
        foreach ($bySev as $sev => $n) {
            $parts[] = "{$n} {$sev}";
        }
        // Source lint findings on generated code: HIGH fails, the rest informs
        $t = new TargetResult(
            ($bySev['high'] ?? 0) > 0 ? TargetResult::FAIL : ($total > 0 ? TargetResult::WARN : TargetResult::PASS),
            $total === 0 ? 'bandit: no findings' : "bandit: {$total} findings (" . implode(', ', $parts) . ')',
            $total
        );
        $t->note("report: {$report}");
        return $t;
    }

    public static function trivy(Context $ctx): TargetResult
    {
        if (!ProcessRunner::has('trivy')) {
            return new TargetResult(TargetResult::SKIP, 'trivy not installed');
        }
        $report  = $ctx->reportPath('trivy', '', 'trivy-fs-results.json');
        $timeout = $ctx->opt->timeout > 0 ? $ctx->opt->timeout : 3600;
        $argv    = [
            'trivy', 'fs', '--quiet',
            '--scanners', 'vuln,misconfig,secret',
            '--format', 'json', '--output', $report,
            // Trivy's own default timeout is 5 minutes, too short for this tree
            '--timeout', $timeout . 's',
            '--skip-dirs', '**/node_modules', '--skip-dirs', '**/vendor', '--skip-dirs', '**/.git',
            ...self::trivySkips($ctx),
        ];

        // Trivy fetches parent POMs from Maven Central, which rate-limits by
        // IP (the Maven audits earlier in the run count too) and makes Trivy
        // abort the whole scan. Wait out a short block once; otherwise scan
        // offline, which skips only those remote lookups.
        $r       = self::runTrivy($ctx, $argv, $report, $timeout);
        $wait    = self::rateLimitWait($r->output);
        $offline = false;
        if ($wait !== null && $wait <= self::RATE_LIMIT_MAX_WAIT) {
            $ctx->console->detail('[trivy] Maven Central rate limit, retrying in ' . CommandResult::duration($wait + 1));
            sleep($wait + 1);
            $r    = self::runTrivy($ctx, $argv, $report, $timeout);
            $wait = self::rateLimitWait($r->output);
        }
        if ($wait !== null) {
            $ctx->console->detail('[trivy] Maven Central rate limit (Retry-After ' . CommandResult::duration($wait) . '), rescanning with --offline-scan');
            $r       = self::runTrivy($ctx, [...$argv, '--offline-scan'], $report, $timeout);
            $offline = true;
        }

        $data = is_file($report) ? json_decode((string)file_get_contents($report), true) : null;
        if (!is_array($data)) {
            $t = TargetResult::fromFailure($r, 'trivy fs' . ($offline ? ' --offline-scan' : ''));
            if ($offline) {
                $t->note('fell back to --offline-scan after a Maven Central rate limit');
            }
            return $t;
        }
        $vulns  = [];
        $misc   = 0;
        $secret = 0;
        foreach (($data['Results'] ?? []) as $res) {
            foreach (($res['Vulnerabilities'] ?? []) as $v) {
                $sev         = strtolower((string)($v['Severity'] ?? 'unknown'));
                $vulns[$sev] = ($vulns[$sev] ?? 0) + 1;
            }
            foreach (($res['Misconfigurations'] ?? []) as $m) {
                if (($m['Status'] ?? 'FAIL') === 'FAIL') {
                    $misc++;
                }
            }
            $secret += count($res['Secrets'] ?? []);
        }
        $t = TargetResult::fromSeverities(array_map('intval', $vulns), 'trivy');
        if ($secret > 0) {
            $t->status  = TargetResult::FAIL;
            $t->detail .= "; {$secret} secret" . ($secret === 1 ? '' : 's');
        }
        if ($misc > 0) {
            $t->detail .= "; {$misc} misconfiguration" . ($misc === 1 ? '' : 's');
            if ($t->status === TargetResult::PASS) {
                $t->status = TargetResult::WARN;
            }
        }
        if ($offline) {
            $t->detail .= '; offline scan';
            $t->note('Maven Central rate-limited the scan, so it ran with --offline-scan: Java dependencies that only resolve through remote parent POMs may be missing');
        }
        $t->note("report: {$report}");
        return $t;
    }

    /**
     * @param list<string> $argv trivy fs options; the scan root "." is appended
     */
    private static function runTrivy(Context $ctx, array $argv, string $report, int $timeout): CommandResult
    {
        @unlink($report);
        return $ctx->runner->run([...$argv, '.'], $ctx->scanRoot(), ['label' => 'trivy', 'timeout' => $timeout + 60]);
    }

    /**
     * Seconds a Maven repository asked Trivy to back off (its 429 Retry-After),
     * or null when the output shows no rate limit. A 429 without a numeric
     * Retry-After counts as one minute.
     */
    public static function rateLimitWait(string $output): ?int
    {
        if (preg_match('/returned 429 Too Many Requests/i', $output) !== 1) {
            return null;
        }
        return preg_match('/Retry-After:\s*(\d+)/i', $output, $m) === 1 ? (int)$m[1] : 60;
    }

    /**
     * Build each Dockerfile's image and scan it with grype. Nothing at all
     * when grype or docker is not installed (an optional pair, absent on most
     * hosts), one SKIP when the docker daemon cannot be reached.
     *
     * @return list<array{0: string, 1: TargetResult}>
     */
    public static function grype(Context $ctx): array
    {
        $dirs = array_slice($ctx->files->dirsWith(['Dockerfile']), 0, 5);
        if (!ProcessRunner::has('grype') || !ProcessRunner::has('docker') || $dirs === []) {
            return [];
        }
        // Otherwise every build fails the same way and shows as a tool error
        $info = $ctx->runner->run(['docker', 'info', '--format', '{{.ServerVersion}}'], $ctx->root, ['label' => 'grype:docker', 'timeout' => 60]);
        if (!$info->ok()) {
            $why = $info->tail(1)[0] ?? $info->failureReason();
            return [['', new TargetResult(TargetResult::SKIP, 'docker daemon not reachable: ' . $why)]];
        }
        $out = [];
        foreach ($dirs as $dir) {
            $cwd = $dir === '' ? $ctx->root : $ctx->root . '/' . $dir;
            $tag = 'dep-sec-patcher-scan-' . getmypid() . '-' . count($out);
            // Host networking: RUN steps still reach the network on a daemon with no default bridge ("bridge": "none").
            $b   = $ctx->runner->run(['docker', 'build', '--network=host', '-q', '-t', $tag, '.'], $cwd, ['label' => 'grype:build']);
            if (!$b->ok()) {
                $out[] = [$dir, TargetResult::fromFailure($b, 'docker build')];
                continue;
            }
            $g    = $ctx->runner->run(['grype', $tag, '-o', 'json', '-q'], $cwd, ['label' => 'grype']);
            $data = json_decode($g->stdout, true);
            $ctx->runner->run(['docker', 'rmi', '-f', $tag], $cwd, ['label' => 'grype:cleanup', 'timeout' => 300]);
            if (!is_array($data)) {
                $out[] = [$dir, TargetResult::fromFailure($g, 'grype')];
                continue;
            }
            $bySev = [];
            foreach (($data['matches'] ?? []) as $m) {
                $sev         = strtolower((string)($m['vulnerability']['severity'] ?? 'unknown'));
                $sev         = $sev === 'negligible' ? 'low' : $sev;
                $bySev[$sev] = ($bySev[$sev] ?? 0) + 1;
            }
            $out[] = [$dir, TargetResult::fromSeverities($bySev, 'grype')];
        }
        return $out;
    }

    /**
     * Extra excluded directories (--exclude-dir / config), as paths relative
     * to the scan root; bare names stay bare. Paths outside --subdir are dropped.
     *
     * @return list<string>
     */
    public static function extraExcludes(Context $ctx): array
    {
        $out = [];
        foreach ($ctx->opt->excludeDirs as $entry) {
            $entry = trim($entry, '/');
            if ($entry === '') {
                continue;
            }
            if (!str_contains($entry, '/') || $ctx->subdir === '') {
                $out[] = $entry;
            } elseif (str_starts_with($entry, $ctx->subdir . '/')) {
                $out[] = substr($entry, strlen($ctx->subdir) + 1);
            }
        }
        return $out;
    }

    /**
     * @return list<string> extra `--skip-dirs` arguments for trivy
     */
    private static function trivySkips(Context $ctx): array
    {
        $args = [];
        foreach (self::extraExcludes($ctx) as $dir) {
            $args[] = '--skip-dirs';
            $args[] = str_contains($dir, '/') ? $dir : '**/' . $dir;
        }
        return $args;
    }
}
