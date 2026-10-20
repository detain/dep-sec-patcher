<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestEditor;
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
    /**
     * Versions the versions plugin must not move to. It counts anything that
     * is not a -SNAPSHOT as a release, so without this it picks milestones
     * (spring-webmvc 7.1.0-M2, netty 5.0.0.Alpha2) over the latest release.
     * The same pattern as Version::isPrerelease(), so the guava "-a" of
     * 28.2-android is no alpha; the plugin needs it to match the whole version.
     */
    public const PRERELEASES = '(?i)^' . Version::PRERELEASE . '.*$';
    /**
     * Pinned, not resolved by prefix: a pom whose pluginManagement holds an
     * old versions plugin (2.7 is common) would otherwise run that, and
     * before 2.13 it silently ignores maven.version.ignore.
     */
    public const VERSIONS_PLUGIN = 'org.codehaus.mojo:versions-maven-plugin:2.23.0';
    private const CENTRAL = 'https://repo.maven.apache.org/maven2';

    /** @var \Closure(string, string): list<string> groupId, artifactId => the versions published */
    private \Closure $published;
    /** @var array<string, list<string>> */
    private array $versionCache = [];

    /**
     * @param (\Closure(string, string): list<string>)|null $published what versions of
     *        groupId:artifactId exist (default: Maven Central, else the ~/.m2 metadata)
     */
    public function __construct(?\Closure $published = null)
    {
        $this->published = $published ?? self::publishedVersions(...);
    }

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

        $reverted = false;
        if (!$ctx->checkMode()) {
            $common = ['-DgenerateBackupPoms=false', '-DallowSnapshots=false', '-Dmaven.version.ignore=' . self::PRERELEASES];
            if (!$ctx->opt->allowMajor) {
                // The same opt-in as an auto-fix crossing a major line
                $common[] = '-DallowMajorUpdates=false';
            }
            $before = self::poms($this->abs($ctx, $dir));
            // An old <parent> (spring-boot-starter-parent 2.1, micronaut-parent
            // 3.0) manages most of the graph's versions, so it moves first
            if (preg_match('#<parent>#', (string)reset($before)) === 1) {
                $r = $this->run($ctx, $dir, array_merge($base, [self::VERSIONS_PLUGIN . ':update-parent'], $common), null, $env);
                if (!$r->ok()) {
                    $notes[] = 'versions:update-parent ' . $r->failureReason();
                }
            }
            $r      = $this->run($ctx, $dir, array_merge($base, [self::VERSIONS_PLUGIN . ':use-latest-releases'], $common), null, $env);
            // Fall back only on failure. The original shell script's `a || echo && b`
            // always ran use-latest-versions too, which accepts prereleases.
            if (!$r->ok()) {
                $notes[] = 'versions:use-latest-releases ' . $r->failureReason() . ', trying use-latest-versions';
                $r = $this->run($ctx, $dir, array_merge($base, [self::VERSIONS_PLUGIN . ':use-latest-versions'], $common), null, $env);
                if (!$r->ok()) {
                    $notes[] = 'versions:use-latest-versions ' . $r->failureReason();
                }
            }
            // A version taken from <properties> (${jackson-version}, as
            // generated clients declare theirs) is only moved by update-properties
            $r = $this->run($ctx, $dir, array_merge($base, [self::VERSIONS_PLUGIN . ':update-properties'], $common), null, $env);
            if (!$r->ok()) {
                $notes[] = 'versions:update-properties ' . $r->failureReason();
            }
            $reverted = $this->verifyUpdate($ctx, $dir, $base, $env, $before, $notes);
        }

        // Report goes to the report directory, never into the project's target/
        $report = $ctx->reportPath('maven', $dir, 'dependency-check-report.json');
        $threshold = $ctx->opt->cvssThreshold;
        $r = $this->dependencyCheck($ctx, $dir, $base, $env, $report);
        if (!$ctx->checkMode() && is_file($report)) {
            $before = (string)file_get_contents($report);
            if ($this->pinTransitive($ctx, $dir, $base, $env, $before, $notes) > 0) {
                // Judged on what the pins left
                $r = $this->dependencyCheck($ctx, $dir, $base, $env, $report);
                $notes[] = 'dependency-check before the pins: ' . self::fromReport($before, (float)$threshold)->detail;
            }
        }

        $result = is_file($report)
            ? self::fromReport((string)file_get_contents($report), (float)$threshold)
            : TargetResult::fromFailure($r, 'dependency-check');
        if (!empty($ctx->state['maven.stale'])) {
            $notes[] = 'NVD data may be stale: the database update failed this run';
        }
        $result->notes = array_merge($notes, $result->notes);
        if ($reverted && $result->status === TargetResult::PASS) {
            $result->status = TargetResult::WARN;
        }
        return $result;
    }

    /**
     * Check that what the versions plugin wrote still resolves. One property
     * often serves several artifacts, and update-properties can set it to a
     * version only one of them has: ${jackson-version} went to 2.22, which
     * jackson-annotations has and jackson-datatype-joda does not.
     *
     * Only the changes behind the artifacts that fail are undone: a shared
     * property goes to the newest release every artifact using it has (on
     * the line in use unless --allow-major), anything else back to what it
     * was, and the pom is checked again. Only when that still fails are the
     * poms put back whole, and the auto-fix then applies its per-artifact
     * fixes to the restored poms.
     *
     * A pom that already failed to resolve keeps the update when the update
     * adds no unresolved artifact of its own. Returns whether it reverted.
     *
     * @param list<string>          $base
     * @param array<string, string> $env
     * @param array<string, string> $before pom path => content before the update
     * @param list<string>          $notes
     */
    private function verifyUpdate(Context $ctx, string $dir, array $base, array $env, array $before, array &$notes): bool
    {
        if (self::changed($before) === []) {
            return false;
        }
        $broken = $this->unresolved($ctx, $dir, $base, $env);
        if ($broken === null) {
            return false;
        }
        $first = $broken;
        $done  = [];
        for ($round = 0; $round < 3 && $broken !== null && $broken !== []; $round++) {
            $current = self::current($before);
            $edits   = $this->narrowing($before, $current, $broken, $ctx->opt->allowMajor, $done);
            if ($edits === []) {
                break;
            }
            foreach ($edits as $id => $e) {
                $current[$e['path']] = $e['kind'] === 'property'
                    ? MavenPom::setProperty($current[$e['path']], $e['key'], $e['from'], $e['to'])
                    : MavenPom::setVersion($current[$e['path']], $e['key'], $e['from'], $e['to']);
                $done[$id] = $e + ['first' => $done[$id]['first'] ?? $e['from']];
                file_put_contents($e['path'], $current[$e['path']]);
            }
            $broken = $this->unresolved($ctx, $dir, $base, $env);
        }
        if ($broken === null) {
            $notes[] = 'the version update left pom.xml unresolvable (' . self::listed($first) . '); ' . self::narrowed($done) . ' and kept the rest of it';
            return false;
        }

        $after = self::changed($before);
        foreach (array_keys($after) as $path) {
            file_put_contents($path, $before[$path]);
        }
        $was = $after === [] ? $broken : $this->unresolved($ctx, $dir, $base, $env);
        $new = $was === null ? $broken : array_values(array_diff($broken, $was));
        if ($was !== null && $broken !== [] && $new === []) {
            foreach ($after as $path => $content) {
                file_put_contents($path, $content);
            }
            $notes[] = 'pom.xml did not resolve before the version update either (' . self::listed($was) . '); kept the update'
                . ($done !== [] ? ' (' . self::narrowed($done) . ')' : '') . ', which adds no unresolved artifact';
            return false;
        }
        $notes[] = 'WARN: the version update left pom.xml unresolvable (' . self::listed($new !== [] ? $new : $broken) . '); reverted '
            . count($after) . ' pom' . (count($after) === 1 ? '' : 's') . ' to the pre-update content, leaving the per-artifact fixes to auto-fix';
        return true;
    }

    /**
     * The edits that undo the version changes behind the $missing artifacts:
     * a changed <version> whose artifact failed, or a changed property one
     * of whose users failed at its new value. A property gets the newest
     * release all its users have, the first time; then its old value.
     *
     * @param array<string, string> $before  pom path => content before the update
     * @param array<string, string> $current pom path => content now
     * @param list<string>          $missing
     * @param array<string, mixed>  $tried   edit id => an earlier edit
     * @return array<string, array{path: string, kind: string, key: string, from: string, to: string, why: string}> by edit id
     */
    private function narrowing(array $before, array $current, array $missing, bool $anyMajor, array $tried): array
    {
        $changes = [];
        $refs    = [];
        foreach ($current as $path => $content) {
            $now = MavenPom::sites($content);
            foreach ($now['refs'] as $prop => $users) {
                $refs[$prop] = array_values(array_unique(array_merge($refs[$prop] ?? [], $users)));
            }
            if (!isset($before[$path]) || $before[$path] === $content) {
                continue;
            }
            $was = MavenPom::sites($before[$path]);
            foreach (['props' => 'property', 'lits' => 'version'] as $set => $kind) {
                foreach ($now[$set] as $key => $value) {
                    if (isset($was[$set][$key]) && $was[$set][$key] !== $value) {
                        $changes[$path . "\0" . $kind . "\0" . $key] = [$path, $kind, (string)$key, $was[$set][$key], $value];
                    }
                }
            }
        }

        $edits = [];
        foreach ($missing as $coord) {
            $parts = explode(':', $coord);
            if (count($parts) < 4) {
                continue;
            }
            $ga = $parts[0] . ':' . $parts[1];
            $v  = (string)end($parts);
            foreach ($changes as $id => [$path, $kind, $key, $old, $new]) {
                if (isset($edits[$id]) || $new !== $v
                    || ($kind === 'version' ? $key !== $ga : !in_array($ga, $refs[$key] ?? [], true))) {
                    continue;
                }
                $first = is_array($tried[$id] ?? null) ? (string)($tried[$id]['first'] ?? $old) : $old;
                $edit  = ['path' => $path, 'kind' => $kind, 'key' => $key, 'from' => $new, 'to' => $first, 'why' => "{$ga} has no {$new}"];
                if ($kind === 'property' && !isset($tried[$id])) {
                    $users = $refs[$key];
                    $pick  = MavenPom::newestOnLine($this->commonVersions($users), $old, $anyMajor);
                    if ($pick !== '' && $pick !== $new) {
                        $edit['to']  = $pick;
                        $edit['why'] = "{$ga} has no {$new}; {$pick} is the newest release all " . count($users) . ' artifacts using it have';
                    }
                }
                $edits[$id] = $edit;
            }
        }
        return $edits;
    }

    /**
     * @param array<string, array{kind: string, key: string, to: string, why: string}> $done
     */
    private static function narrowed(array $done): string
    {
        $out = [];
        foreach ($done as $e) {
            $what  = $e['kind'] === 'property' ? '${' . $e['key'] . '}' : $e['key'];
            $out[] = "set {$what} to {$e['to']} ({$e['why']})";
        }
        return implode(', ', $out);
    }

    /**
     * The versions every one of $gas has been published at.
     *
     * @param list<string> $gas groupId:artifactId
     * @return list<string>
     */
    private function commonVersions(array $gas): array
    {
        $common = null;
        foreach ($gas as $ga) {
            [$g, $a] = array_pad(explode(':', $ga, 2), 2, '');
            $have    = $this->versionsOf($g, $a);
            $common  = $common === null ? $have : array_values(array_intersect($common, $have));
            if ($common === []) {
                return [];
            }
        }
        return $common ?? [];
    }

    /**
     * @return list<string>
     */
    private function versionsOf(string $g, string $a): array
    {
        return $this->versionCache[$g . ':' . $a] ??= ($this->published)($g, $a);
    }

    /**
     * What versions of groupId:artifactId exist: Maven Central's metadata,
     * else whatever metadata the local repository holds.
     *
     * @return list<string>
     */
    public static function publishedVersions(string $g, string $a): array
    {
        if (preg_match('/^[\w.-]+$/', $g . $a) !== 1) {
            return [];
        }
        $path = str_replace('.', '/', $g) . '/' . $a;
        $ctx  = stream_context_create(['http' => ['timeout' => 15, 'user_agent' => 'dep-sec-patcher']]);
        $xml  = @file_get_contents(self::CENTRAL . '/' . $path . '/maven-metadata.xml', false, $ctx);
        if (is_string($xml) && ($found = MavenPom::metadataVersions($xml)) !== []) {
            return $found;
        }
        $found = [];
        $home  = (string)getenv('HOME');
        foreach (glob($home . '/.m2/repository/' . $path . '/maven-metadata*.xml') ?: [] as $file) {
            $found = array_merge($found, MavenPom::metadataVersions((string)file_get_contents($file)));
        }
        return array_values(array_unique($found));
    }

    /**
     * The poms in $before whose content changed, path => content now.
     *
     * @phpstan-impure
     * @param array<string, string> $before
     * @return array<string, string>
     */
    private static function changed(array $before): array
    {
        return array_diff_assoc(self::current($before), $before);
    }

    /**
     * @phpstan-impure
     * @param array<string, string> $before
     * @return array<string, string>
     */
    private static function current(array $before): array
    {
        $now = [];
        foreach ($before as $path => $content) {
            $c          = @file_get_contents($path);
            $now[$path] = is_string($c) ? $c : $content;
        }
        return $now;
    }

    /**
     * Pin the vulnerable artifacts dependency-check found that no pom
     * declares, the transitive copies an old parent or BOM brings in, in
     * the root pom's <dependencyManagement> (the same entry auto-fix writes
     * for a transitive advisory): the newest release on the major line in
     * use, or the newest of all with --allow-major, that clears the fixed
     * versions the report names. A pin whose artifact does not resolve is
     * dropped, and when the pom still fails to resolve over what it failed
     * on before, every pin is. Returns how many pins were kept.
     *
     * @param list<string>          $base
     * @param array<string, string> $env
     * @param list<string>          $notes
     */
    private function pinTransitive(Context $ctx, string $dir, array $base, array $env, string $report, array &$notes): int
    {
        $found = self::vulnerableArtifacts($report);
        $abs   = $this->abs($ctx, $dir);
        $root  = $abs . '/pom.xml';
        $poms  = self::poms($abs);
        if ($found === [] || !isset($poms[$root])) {
            return 0;
        }
        $own     = array_filter(array_map([MavenPom::class, 'coordinate'], array_values($poms)));
        $any     = $ctx->opt->allowMajor;
        $pins    = [];
        $skipped = [];
        foreach ($found as $ga => $f) {
            if (in_array($ga, $own, true)) {
                continue;
            }
            foreach ($poms as $path => $content) {
                if (ManifestEditor::declared('maven', $path, $content, $ga) !== '') {
                    continue 2;
                }
            }
            $lines = array_values(array_unique(array_map([Version::class, 'majorLine'], $f['versions'])));
            if (count($lines) > 1) {
                $skipped[] = "{$ga} (in use at " . implode(', ', $f['versions']) . ')';
                continue;
            }
            $current = Version::maxMaven($f['versions']);
            $later   = [];
            $floors  = $f['floors'];
            if (!$any) {
                // A fix only a new major has waits for --allow-major
                $later  = array_values(array_filter($floors, static fn (string $v): bool => Version::majorLine($v) !== $lines[0] && Version::gteMaven($v, $current)));
                $floors = array_values(array_diff($floors, $later));
            }
            [$g, $a]   = explode(':', $ga, 2);
            $published = $this->versionsOf($g, $a);
            $to = MavenPom::newestOnLine($published, $current, $any, $floors, $f['above']);
            if ($to === '') {
                // Nothing on the line clears it all: still the newest there
                $to = MavenPom::newestOnLine($published, $current, $any);
            }
            if ($to !== '' && Version::compareMaven($to, $current) < 0) {
                // Hard guard: a pin never moves an artifact backwards. The
                // r09 of the world sort above release numbers byte-for-byte,
                // and pinning one broke a guava 28.1-jre build.
                $notes[] = "WARN: not pinning {$ga}: {$to} compares below the {$current} in use";
                $to      = '';
            }
            if ($to === '') {
                $skipped[] = "{$ga} {$current} (no newer release" . ($any ? '' : ' on its major line') . ')';
                continue;
            }
            $pins[$ga] = ['from' => $current, 'to' => $to, 'later' => $later];
        }
        if ($skipped !== []) {
            $notes[] = 'not pinned: ' . self::listed($skipped);
        }
        if ($pins === []) {
            return 0;
        }

        $original = $poms[$root];
        $write    = static function (array $pins) use ($original, $root): void {
            $content = $original;
            foreach ($pins as $ga => $p) {
                $r = ManifestEditor::apply('maven', 'pom.xml', $content, (string)$ga, $p['to']);
                if ($r['status'] === ManifestEditor::OK) {
                    $content = $r['content'];
                }
            }
            file_put_contents($root, $content);
        };
        $write($pins);
        $broken  = $this->unresolved($ctx, $dir, $base, $env);
        $dropped = [];
        if ($broken !== null) {
            foreach ($broken as $coord) {
                $parts = explode(':', $coord);
                $ga    = $parts[0] . ':' . ($parts[1] ?? '');
                if (isset($pins[$ga]) && end($parts) === $pins[$ga]['to']) {
                    $dropped[] = "{$ga} {$pins[$ga]['to']}";
                    unset($pins[$ga]);
                }
            }
            if ($dropped !== [] && $pins !== []) {
                $write($pins);
                $broken = $this->unresolved($ctx, $dir, $base, $env);
            }
        }
        if ($broken !== null && $pins !== []) {
            file_put_contents($root, $original);
            $was = $this->unresolved($ctx, $dir, $base, $env);
            if ($was !== null && $broken !== [] && array_diff($broken, $was) === []) {
                $write($pins);
                $broken = null;
            } else {
                $notes[] = 'WARN: pinning ' . count($pins) . ' transitive dependenc' . (count($pins) === 1 ? 'y' : 'ies')
                    . ' left pom.xml unresolvable (' . self::listed($broken) . '); left them unpinned';
                $pins = [];
            }
        }
        if ($pins === []) {
            file_put_contents($root, $original);
            if ($dropped !== []) {
                $notes[] = 'not pinned, the pinned version does not resolve: ' . self::listed($dropped);
            }
            return 0;
        }
        $list = [];
        foreach ($pins as $ga => $p) {
            $list[] = "{$ga} {$p['from']} -> {$p['to']}" . ($p['later'] !== [] ? ' (a full fix needs ' . implode(', ', $p['later']) . ', --allow-major)' : '');
        }
        $notes[] = 'pinned ' . count($pins) . ' vulnerable transitive dependenc' . (count($pins) === 1 ? 'y' : 'ies')
            . ' in <dependencyManagement>: ' . implode('; ', $list);
        if ($dropped !== []) {
            $notes[] = 'not pinned, the pinned version does not resolve: ' . self::listed($dropped);
        }
        return count($pins);
    }

    /**
     * The Maven artifacts a dependency-check report finds vulnerable:
     * groupId:artifactId => the versions in use and the fixed versions its
     * matched CPE ranges name (floors: versionEndExcluding; above:
     * versionEndIncluding). Jars the report folds into one entry share it.
     *
     * @return array<string, array{versions: list<string>, floors: list<string>, above: list<string>}>
     */
    public static function vulnerableArtifacts(string $json): array
    {
        $data = json_decode($json, true);
        $out  = [];
        foreach (is_array($data) && is_array($data['dependencies'] ?? null) ? $data['dependencies'] : [] as $dep) {
            if (!is_array($dep) || !is_array($dep['vulnerabilities'] ?? null) || $dep['vulnerabilities'] === []) {
                continue;
            }
            // dependency-check folds the same-version jars of one family
            // (spring-aop, spring-context, ...) into one entry: the related
            // ones are pinned too, or one pin would split the family
            $ids = [];
            foreach (is_array($dep['packages'] ?? null) ? $dep['packages'] : [] as $pkg) {
                $ids[] = [(string)($dep['fileName'] ?? ''), (string)($pkg['id'] ?? '')];
            }
            foreach (is_array($dep['relatedDependencies'] ?? null) ? $dep['relatedDependencies'] : [] as $rel) {
                foreach (is_array($rel['packageIds'] ?? null) ? $rel['packageIds'] : [] as $pkg) {
                    $ids[] = [(string)($rel['fileName'] ?? ''), (string)($pkg['id'] ?? '')];
                }
            }
            foreach ($ids as [$file, $id]) {
                if (preg_match('#^pkg:maven/([^/]+)/([^@/]+)@([^?\#]+)#', $id, $m) !== 1) {
                    continue;
                }
                [, $g, $a, $v] = array_map('rawurldecode', $m);
                // A jar that shades others names them too: only the jar's own
                if ($file !== '' && !str_starts_with($file, "{$a}-{$v}")) {
                    continue;
                }
                $ga  = "{$g}:{$a}";
                $out[$ga] ??= ['versions' => [], 'floors' => [], 'above' => []];
                $out[$ga]['versions'][] = $v;
                foreach ($dep['vulnerabilities'] as $vuln) {
                    foreach (is_array($vuln['vulnerableSoftware'] ?? null) ? $vuln['vulnerableSoftware'] : [] as $sw) {
                        $sw = is_array($sw['software'] ?? null) ? $sw['software'] : [];
                        if (($sw['vulnerabilityIdMatched'] ?? '') !== 'true') {
                            continue;
                        }
                        if (is_string($sw['versionEndExcluding'] ?? null) && $sw['versionEndExcluding'] !== '') {
                            $out[$ga]['floors'][] = $sw['versionEndExcluding'];
                        } elseif (is_string($sw['versionEndIncluding'] ?? null) && $sw['versionEndIncluding'] !== '') {
                            $out[$ga]['above'][] = $sw['versionEndIncluding'];
                        }
                    }
                }
            }
        }
        foreach ($out as $ga => $f) {
            $out[$ga] = array_map(static fn (array $l): array => Version::sortAscending(array_values(array_unique($l))), $f);
        }
        ksort($out);
        return $out;
    }

    /**
     * @param list<string>          $base
     * @param array<string, string> $env
     */
    private function dependencyCheck(Context $ctx, string $dir, array $base, array $env, string $report): CommandResult
    {
        @unlink($report);
        return $this->run($ctx, $dir, array_merge($base, [
            '-DskipTests',
            self::ODC . ':check',
            '-DautoUpdate=false',
            '-DfailBuildOnCVSS=' . $ctx->opt->cvssThreshold,
            '-Dformat=JSON',
            '-Dodc.outputDirectory=' . dirname($report),
        ]), null, $env);
    }

    /**
     * Run dependency:resolve: null when everything resolves, else the
     * artifacts that did not (empty when the output names none). A failure
     * Maven cached on an earlier run is retried once with -U, so a
     * since-published artifact is not reported missing.
     *
     * @param list<string>          $base
     * @param array<string, string> $env
     * @return list<string>|null
     */
    private function unresolved(Context $ctx, string $dir, array $base, array $env): ?array
    {
        $r = $this->run($ctx, $dir, array_merge($base, ['dependency:resolve']), null, $env);
        if (!$r->ok() && self::cachedFailure($r->output)) {
            $r = $this->run($ctx, $dir, array_merge($base, ['-U', 'dependency:resolve']), null, $env);
        }
        return $r->ok() ? null : self::missingArtifacts($r->output);
    }

    /**
     * Whether Maven refused to look again for an artifact it failed to find
     * on an earlier run ("... during a previous attempt. This failure was
     * cached in the local repository ...").
     */
    public static function cachedFailure(string $output): bool
    {
        return str_contains($output, 'during a previous attempt') || str_contains($output, 'was cached in the local repository');
    }

    /**
     * The groupId:artifactId:type[:classifier]:version coordinates a failed
     * resolution names, sorted and unique. The project's own coordinate
     * ("for project ...") and the failing plugin's ("goal ...") are left out.
     *
     * @return list<string>
     */
    public static function missingArtifacts(string $output): array
    {
        $found = [];
        foreach (preg_split('/\r?\n/', CommandResult::plain($output)) ?: [] as $line) {
            if (preg_match('/dependency: |Could not find artifact|was not found in|could not be resolved|Non-resolvable|\(absent\)/', $line) !== 1) {
                continue;
            }
            $line = (string)preg_replace('/(?:for project|goal|parent POM for)\s+\S+/', '', $line);
            preg_match_all('/(?<![\w.:-])[\w.-]+(?::[\w.-]+){3,4}(?![\w.:-])/', $line, $m);
            foreach ($m[0] as $coord) {
                $found[$coord] = true;
            }
        }
        $list = array_keys($found);
        sort($list);
        return $list;
    }

    /**
     * @param list<string> $items
     */
    private static function listed(array $items): string
    {
        if ($items === []) {
            return 'dependency:resolve failed';
        }
        return implode(', ', array_slice($items, 0, 3)) . (count($items) > 3 ? ' and ' . (count($items) - 3) . ' more' : '');
    }

    /**
     * The pom in $abs and the module poms it reaches through <modules>,
     * path => content, since the versions plugin edits the whole reactor.
     *
     * @return array<string, string>
     */
    public static function poms(string $abs, int $depth = 0): array
    {
        $pom     = $abs . '/pom.xml';
        $content = @file_get_contents($pom);
        if (!is_string($content)) {
            return [];
        }
        $out = [$pom => $content];
        if ($depth < 8 && preg_match_all('#<module>\s*([^<]+?)\s*</module>#', $content, $m) > 0) {
            foreach ($m[1] as $module) {
                $path = $abs . '/' . $module;
                // A module may name its pom file directly
                $out += str_ends_with($module, '.xml') ? (is_file($path) ? [$path => (string)file_get_contents($path)] : []) : self::poms($path, $depth + 1);
            }
        }
        return $out;
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
