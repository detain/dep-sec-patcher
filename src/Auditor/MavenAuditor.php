<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\TargetResult;
use Detain\DepSecPatcher\Version;

/**
 * Maven: versions-maven-plugin updates, OWASP dependency-check audit.
 *
 * The NVD database is refreshed ONCE, up front, with the API key; every pom
 * is then checked with autoUpdate=false. Previously each pom triggered its own
 * keyless refresh. NVD throttles keyless clients to ~5 requests/30s, and once
 * the local copy is more than 120 days old a refresh is a full 368k-record
 * download, so the first pom sat "hung" for hours, and since an interrupted
 * refresh records nothing, every later run started the download again.
 */
final class MavenAuditor extends Auditor
{
    /** First release bundling a resolver with cross-process named locks (1.9.x). */
    public const CONCURRENT_SINCE = '3.9.0';
    private const ODC = 'org.owasp:dependency-check-maven';

    public function name(): string
    {
        return 'maven';
    }

    public function tool(): string
    {
        return 'mvn';
    }

    public function manifests(): array
    {
        return ['pom.xml'];
    }

    public function concurrency(Context $ctx): array
    {
        return ['maven' => $this->gated(
            'maven',
            $this->version($ctx),
            self::CONCURRENT_SINCE,
            'Maven before 3.9 has no cross-process locking on the shared ~/.m2 repository, so concurrent runs can corrupt downloaded artifacts'
        )];
    }

    public function prepare(Context $ctx, array $targets): void
    {
        $key = (string)($ctx->state['nvd_api_key'] ?? '');
        $ctx->state['maven.base'] = $this->baseArgs($ctx);

        if ($key === '') {
            $ctx->console->warn('dependency-check: no NVD API key (NVD_API_KEY / --nvd-api-key). NVD throttles keyless clients'
                . ' hard and a full database refresh can take hours; get a free key at https://nvd.nist.gov/developers/request-an-api-key');
        }
        $ctx->console->info('dependency-check: refreshing the NVD database (timeout ' . CommandResult::duration($ctx->opt->nvdTimeout) . ')...');

        $argv = array_merge($this->base($ctx), [self::ODC . ':update-only']);
        $env  = $this->env($ctx);
        if ($key !== '') {
            // By environment variable, not -DnvdApiKey: a command-line value
            // is visible to every user on the host through ps
            $argv[] = '-DnvdApiKeyEnvironmentVariable=NVD_API_KEY';
            $env['NVD_API_KEY'] = $key;
        }
        $r = $ctx->runner->run($argv, $ctx->root, [
            'timeout' => $ctx->opt->nvdTimeout,
            'label'   => 'maven:nvd-update',
            'env'     => $env + $ctx->env,
        ]);
        if ($r->ok()) {
            $ctx->console->ok('dependency-check: NVD database up to date (' . CommandResult::duration($r->seconds) . ')');
            return;
        }
        $ctx->state['maven.stale'] = true;
        $ctx->console->warn('dependency-check: NVD update failed (' . $r->failureReason() . '); checking against the existing database'
            . ($key === '' ? ' (set NVD_API_KEY)' : ''));
        foreach ($r->tail(8) as $line) {
            $ctx->console->detail($line);
        }
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $base  = $this->base($ctx);
        $env   = $this->env($ctx);
        $notes = [];

        if (!$ctx->checkMode()) {
            $common = ['-DgenerateBackupPoms=false', '-DallowSnapshots=false'];
            if (!$ctx->opt->allowMajor) {
                // The same opt-in as an auto-fix crossing a major line
                $common[] = '-DallowMajorUpdates=false';
            }
            $r = $this->run($ctx, $dir, array_merge($base, ['versions:use-latest-releases'], $common), null, $env);
            // Fall back only on failure. The original shell script's `a || echo && b`
            // always ran use-latest-versions too, which accepts prereleases.
            if (!$r->ok()) {
                $notes[] = 'versions:use-latest-releases ' . $r->failureReason() . ', trying use-latest-versions';
                $r = $this->run($ctx, $dir, array_merge($base, ['versions:use-latest-versions'], $common), null, $env);
                if (!$r->ok()) {
                    $notes[] = 'versions:use-latest-versions ' . $r->failureReason();
                }
            }
            // A version taken from <properties> (${jackson-version}, as
            // generated clients declare theirs) is only moved by update-properties
            $r = $this->run($ctx, $dir, array_merge($base, ['versions:update-properties'], $common), null, $env);
            if (!$r->ok()) {
                $notes[] = 'versions:update-properties ' . $r->failureReason();
            }
        }

        // Report goes to the report directory, never into the project's target/
        $report = $ctx->reportPath('maven', $dir, 'dependency-check-report.json');
        @unlink($report);
        $threshold = $ctx->opt->cvssThreshold;
        $r = $this->run($ctx, $dir, array_merge($base, [
            '-DskipTests',
            self::ODC . ':check',
            '-DautoUpdate=false',
            '-DfailBuildOnCVSS=' . $threshold,
            '-Dformat=JSON',
            '-Dodc.outputDirectory=' . dirname($report),
        ]), null, $env);

        $result = is_file($report)
            ? self::fromReport((string)file_get_contents($report), (float)$threshold)
            : TargetResult::fromFailure($r, 'dependency-check');
        if (!empty($ctx->state['maven.stale'])) {
            $notes[] = 'NVD data may be stale: the database update failed this run';
        }
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    /**
     * Summarise a dependency-check JSON report. Fails when anything reaches
     * the CVSS threshold, which is also what failBuildOnCVSS fails on.
     */
    public static function fromReport(string $json, float $threshold): TargetResult
    {
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return new TargetResult(TargetResult::ERROR, 'dependency-check report is not valid JSON');
        }
        $total   = 0;
        $serious = 0;
        $hits    = [];
        foreach (($data['dependencies'] ?? []) as $dep) {
            $vulns = $dep['vulnerabilities'] ?? [];
            if (!is_array($vulns) || $vulns === []) {
                continue;
            }
            $worst = 0.0;
            foreach ($vulns as $v) {
                $score = max(
                    (float)($v['cvssv4']['baseScore'] ?? 0),
                    (float)($v['cvssv3']['baseScore'] ?? 0),
                    (float)($v['cvssv2']['score'] ?? 0)
                );
                $worst = max($worst, $score);
                $total++;
                if ($score >= $threshold) {
                    $serious++;
                }
            }
            $hits[] = ($dep['fileName'] ?? '?') . ' (' . count($vulns) . ', max ' . $worst . ')';
        }
        if ($total === 0) {
            return new TargetResult(TargetResult::PASS, 'dependency-check: no known vulnerabilities');
        }
        $t = new TargetResult(
            $serious > 0 ? TargetResult::FAIL : TargetResult::WARN,
            "dependency-check: {$total} vulnerabilit" . ($total === 1 ? 'y' : 'ies') . " in " . count($hits)
                . " dependenc" . (count($hits) === 1 ? 'y' : 'ies') . ", {$serious} with CVSS >= {$threshold}",
            $total
        );
        foreach (array_slice($hits, 0, 10) as $hit) {
            $t->note($hit);
        }
        return $t;
    }

    private function version(Context $ctx): string
    {
        return $ctx->toolVersion('maven', ['mvn', '-v', '-B'], '/Apache Maven (\d+\.\d+\.\d+)/');
    }

    /**
     * The mvn prefix computed in prepare(), shared with forked workers.
     *
     * @return list<string>
     */
    private function base(Context $ctx): array
    {
        $base = $ctx->state['maven.base'] ?? null;
        return is_array($base) ? array_values(array_map('strval', $base)) : $this->baseArgs($ctx);
    }

    /**
     * @return list<string>
     */
    private function baseArgs(Context $ctx): array
    {
        $base = ['mvn', '-B', '-ntp'];
        $v    = $this->version($ctx);
        if ($v !== '' && Version::gte($v, self::CONCURRENT_SINCE)) {
            // Cross-process advisory locks, so concurrent mvn runs can safely
            // share ~/.m2 (resolver named locks, file-lock + file-gav)
            $base[] = '-Daether.syncContext.named.factory=file-lock';
            $base[] = '-Daether.syncContext.named.nameMapper=file-gav';
        }
        return $base;
    }

    /**
     * @return array<string, string>
     */
    private function env(Context $ctx): array
    {
        $opts = trim((string)getenv('MAVEN_OPTS'));
        // The JVM option only exists from Java 17; older JVMs refuse to start
        // with it. (mvn -v reports the Java it runs on: "Java version: 21.0.2")
        $java = $ctx->toolVersion('mvn-java', ['mvn', '-v'], '/Java version: (\d+(?:\.\d+)*)/');
        if (!str_contains($opts, '--enable-native-access') && $java !== '' && Version::gte($java, '17')) {
            $opts = trim($opts . ' --enable-native-access=ALL-UNNAMED');
        }
        return $opts === '' ? [] : ['MAVEN_OPTS' => $opts];
    }
}
