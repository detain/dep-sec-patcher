<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\JsonFile;
use Detain\DepSecPatcher\Lockfile;
use Detain\DepSecPatcher\NodeWorkspace;
use Detain\DepSecPatcher\ProcessRunner;
use Detain\DepSecPatcher\TargetResult;

/**
 * Node: npm, yarn or pnpm depending on the lockfile present, and on the
 * pnpm/yarn/npm workspace a directory belongs to where there is none.
 *
 * Lockfile-only operations throughout (--package-lock-only), with install
 * scripts disabled: the audited tree never needs node_modules, so downloading every
 * tarball and running third-party postinstall hooks on this host bought
 * nothing.
 */
final class NodeAuditor extends Auditor
{
    /** Yarn 2+ (Berry) documents its cache as safe to share between concurrent instances. */
    public const YARN_CONCURRENT_SINCE = '2.0.0';

    public function name(): string
    {
        return 'node';
    }

    public function tool(): string
    {
        return 'npm';
    }

    public function manifests(): array
    {
        return ['package.json'];
    }

    public function group(Context $ctx, string $dir): string
    {
        return 'node:' . $this->manager($ctx, $dir);
    }

    public function concurrency(Context $ctx): array
    {
        $policies = [
            'node:npm'  => ConcurrencyPolicy::unlimited('npm'),
            'node:pnpm' => ConcurrencyPolicy::unlimited('pnpm'),
        ];
        $policies['node:yarn'] = $this->gated(
            'yarn',
            $this->yarnVersion($ctx),
            self::YARN_CONCURRENT_SINCE,
            'Yarn 1 can corrupt its shared cache when several installs run at once'
        );
        return $policies;
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        // A workspace installs and audits from its root: the root's lockfile
        // pins every member and `pnpm audit` there reports the whole graph,
        // so a member audited on its own is at best redundant — and npm, the
        // fallback for a member without a local lockfile, fails every
        // install of the `workspace:`/`catalog:` specifiers linking siblings
        $workspace = NodeWorkspace::containing($ctx->root, $this->abs($ctx, $dir));
        if ($workspace !== null && $workspace['member'] && ProcessRunner::has($workspace['manager'])) {
            return new TargetResult(TargetResult::SKIP, $workspace['manager'] . ' workspace member — covered by root workspace audit at '
                . ($workspace['rel'] === '' ? '.' : $workspace['rel']));
        }
        return match ($this->manager($ctx, $dir)) {
            'yarn'  => $this->yarn($ctx, $dir),
            'pnpm'  => $this->pnpm($ctx, $dir),
            default => $this->npm($ctx, $dir),
        };
    }

    /**
     * Lockfiles a run here may create that belong to another manager, so the
     * guard removes them again even in update mode: a member has no lockfile
     * of its own (the root's pins it), and inside a pnpm/yarn workspace the
     * workspace tool owns the one file — an npm package-lock left behind by
     * the fallback dispatch is only something --push could commit by mistake.
     *
     * @return list<string>
     */
    public function guardPurge(Context $ctx, string $dir): array
    {
        $workspace = NodeWorkspace::containing($ctx->root, $this->abs($ctx, $dir));
        if ($workspace === null || $workspace['manager'] === 'npm') {
            return [];
        }
        return $workspace['member']
            ? NodeWorkspace::lockfiles()
            : array_values(array_diff(NodeWorkspace::lockfiles(), NodeWorkspace::MANAGER_LOCKS[$workspace['manager']]));
    }

    private function manager(Context $ctx, string $dir): string
    {
        if ($this->exists($ctx, $dir, 'yarn.lock') && ProcessRunner::has('yarn')) {
            return 'yarn';
        }
        if ($this->exists($ctx, $dir, 'pnpm-lock.yaml') && ProcessRunner::has('pnpm')) {
            return 'pnpm';
        }
        // A workspace root dispatches by the tool its layout dictates even
        // before its lockfile exists: pnpm-workspace.yaml means pnpm. Members
        // are audited by audit() itself, and a directory the globs do not
        // claim is nobody's member: its own lockfiles, or npm, decide.
        $workspace = NodeWorkspace::containing($ctx->root, $this->abs($ctx, $dir));
        if ($workspace !== null && $workspace['root'] === $this->abs($ctx, $dir)
            && $workspace['manager'] !== 'npm' && ProcessRunner::has($workspace['manager'])) {
            return $workspace['manager'];
        }
        // corepack's "packageManager" field, as a tiebreaker only
        $declared = NodeWorkspace::packageManager($this->abs($ctx, $dir));
        if (in_array($declared, ['pnpm', 'yarn'], true) && ProcessRunner::has($declared)) {
            return $declared;
        }
        return 'npm';
    }

    private function npm(Context $ctx, string $dir): TargetResult
    {
        // Belt and braces for the workspace-protocol specifiers: an
        // undetected member, or one of a workspace rooted above the scanned
        // tree, fails `npm install` with EUNSUPPORTEDPROTOCOL on every run
        $link = NodeWorkspace::protocolSpecifier($this->abs($ctx, $dir));
        if ($link !== '') {
            return new TargetResult(TargetResult::SKIP, 'npm cannot resolve ' . $link . ' (a workspace-protocol specifier); only its workspace root can audit this package');
        }
        $quiet = ['--ignore-scripts', '--no-audit', '--no-fund'];
        $peers = [];
        $notes = [];
        // npm audit needs a lockfile; in check mode the guard removes it again
        $install = function () use ($ctx, $dir, $quiet, &$peers): CommandResult {
            return $this->run($ctx, $dir, array_merge(['npm', 'install', '--package-lock-only'], $quiet, $peers));
        };
        $r = $install();
        if (!$r->ok() && stripos($r->output, 'ERESOLVE') !== false) {
            // A peer dependency conflict in package.json itself: resolving
            // the way npm 6 did still gives the audit a lockfile to read
            $peers   = ['--legacy-peer-deps'];
            $notes[] = 'conflicting peer dependencies in package.json (npm ERESOLVE); resolved with --legacy-peer-deps';
            $r       = $install();
        }
        // An override naming a version that was never published (an earlier
        // run's, or a hand-written one) fails every install; drop it
        for ($tries = 0; !$r->ok() && !$ctx->checkMode() && $tries < 10; $tries++) {
            $dropped = $this->dropUnpublishedOverride($ctx, $dir, $r);
            if ($dropped === null) {
                break;
            }
            $notes[] = $dropped;
            $r       = $install();
        }
        if (!$r->ok()) {
            return TargetResult::fromFailure($r, 'npm install --package-lock-only');
        }
        if (!$ctx->checkMode()) {
            $r = $this->run($ctx, $dir, array_merge(['npm', 'update', '--package-lock-only'], $quiet, $peers));
            if (!$r->ok()) {
                $notes[] = 'npm update ' . $r->failureReason();
            }
            // --force is npm's opt-in to breaking (major) upgrades: the same
            // opt-in as an auto-fix crossing a major line
            $fix = array_merge(['npm', 'audit', 'fix'], $ctx->opt->allowMajor ? ['--force'] : [], ['--package-lock-only', '--ignore-scripts', '--no-fund'], $peers);
            $r   = $this->run($ctx, $dir, $fix);
            if (!$r->ok()) {
                $notes[] = self::auditFixNote($r, $ctx->opt->allowMajor);
            }
            $notes = array_merge($notes, $this->overrideLeftovers($ctx, $dir, $install));
        }
        $argv = ['npm', 'audit', '--json'];
        if ($ctx->checkMode()) {
            $argv[] = '--omit=dev';
        }
        $result = $this->fromCounts($this->run($ctx, $dir, $argv), 'npm audit', static fn ($d) => $d['metadata']['vulnerabilities'] ?? null);
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    private function pnpm(Context $ctx, string $dir): TargetResult
    {
        $notes = [];
        if (!$ctx->checkMode()) {
            // --latest ignores the declared ranges, so it can cross a major line
            $r = $this->run($ctx, $dir, $ctx->opt->allowMajor ? ['pnpm', 'up', '--latest'] : ['pnpm', 'up'], null, ['npm_config_ignore_scripts' => 'true']);
            if (!$r->ok()) {
                $notes[] = 'pnpm up ' . $r->failureReason();
            }
        }
        $result = $this->fromCounts($this->run($ctx, $dir, ['pnpm', 'audit', '--json']), 'pnpm audit', static fn ($d) => $d['metadata']['vulnerabilities'] ?? null);
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    private function yarn(Context $ctx, string $dir): TargetResult
    {
        $berry = version_compare($this->yarnVersion($ctx) ?: '1', '2', '>=');
        $notes = [];
        if (!$ctx->checkMode()) {
            if ($berry) {
                $notes[] = 'yarn ' . $this->yarnVersion($ctx) . ': dependency upgrade not automated for Yarn 2+';
            } else {
                // Bring the lockfile in line with package.json first (auto-fix
                // may have just edited it); `yarn upgrade` refuses an
                // outdated lockfile
                $r = $this->run($ctx, $dir, ['yarn', 'install', '--ignore-scripts', '--non-interactive', '--no-progress']);
                if (!$r->ok()) {
                    $notes[] = 'yarn install ' . $r->failureReason();
                }
                $r = $this->run($ctx, $dir, ['yarn', 'upgrade', '--ignore-scripts', '--non-interactive', '--no-progress']);
                if (!$r->ok()) {
                    $notes[] = 'yarn upgrade ' . $r->failureReason();
                }
            }
        }
        if ($berry) {
            $r = $this->run($ctx, $dir, ['yarn', 'npm', 'audit', '--all', '--json']);
            $counts = [];
            foreach (preg_split('/\r?\n/', $r->stdout) ?: [] as $line) {
                $row = json_decode($line, true);
                if (is_array($row) && isset($row['children']['Severity'])) {
                    $sev = self::severity($row['children']['Severity']);
                    $counts[$sev] = ($counts[$sev] ?? 0) + 1;
                }
            }
            $result = ($r->exitCode > 1 || $r->timedOut) && $counts === []
                ? TargetResult::fromFailure($r, 'yarn npm audit')
                : TargetResult::fromSeverities($counts, 'yarn npm audit');
        } else {
            $r = $this->run($ctx, $dir, ['yarn', 'audit', '--json', '--non-interactive']);
            $summary = null;
            foreach (preg_split('/\r?\n/', $r->stdout) ?: [] as $line) {
                $row = json_decode($line, true);
                if (is_array($row) && ($row['type'] ?? '') === 'auditSummary') {
                    $summary = $row['data']['vulnerabilities'] ?? null;
                }
            }
            $result = is_array($summary)
                ? TargetResult::fromSeverities(self::normalise($summary), 'yarn audit')
                : TargetResult::fromFailure($r, 'yarn audit');
        }
        $result->notes = array_merge($notes, $result->notes);
        return $result;
    }

    /**
     * Why `npm audit fix` failed. It exits 1 whenever anything is left
     * vulnerable, which the audit after it counts, so say what was left
     * rather than just "exit 1".
     */
    public static function auditFixNote(CommandResult $r, bool $forced = false): string
    {
        $major = $none = $other = 0;
        // One block per vulnerable package: "name  range", then its details
        foreach (preg_split('/\R\s*\R/', $r->output) ?: [] as $block) {
            if (preg_match('/^((?:@[\w.-]+\/)?[\w.-]+)  (\S.*)$/', (string)strtok(trim($block), "\n"), $m) !== 1
                || stripos($block, 'fix available') === false) {
                continue;
            }
            match (true) {
                // Every version is affected: whatever npm suggests is a
                // different (often older) parent, not a fix
                trim($m[2]) === '*', str_contains($block, 'No fix available') => $none++,
                str_contains($block, 'fix available via `npm audit fix --force`') => $major++,
                default => $other++,
            };
        }
        if ($r->timedOut || $r->exitCode !== 1 || $major + $none + $other === 0) {
            return 'npm audit fix ' . $r->failureReason();
        }
        $left = [];
        if ($major > 0) {
            // With --force already passed, suggesting --allow-major is no help
            $left[] = $forced ? "{$major} not fixed even with --force" : "{$major} need" . ($major === 1 ? 's' : '') . ' a major upgrade (--allow-major)';
        }
        if ($other > 0) {
            $left[] = "{$other} it could not resolve";
        }
        if ($none > 0) {
            $left[] = "{$none} ha" . ($none === 1 ? 's' : 've') . ' no fix available';
        }
        return 'npm audit fix left ' . implode(', ', $left);
    }

    /**
     * Pin what `npm audit fix` left with "overrides", on the line in use,
     * and re-resolve the lockfile. Undone if npm cannot resolve the result.
     *
     * @param callable(): CommandResult $install
     * @return list<string> notes
     */
    private function overrideLeftovers(Context $ctx, string $dir, callable $install): array
    {
        $abs   = $this->abs($ctx, $dir);
        $audit = self::json($this->run($ctx, $dir, ['npm', 'audit', '--json'])->stdout);
        $file  = $abs . '/package.json';
        $raw   = is_file($file) ? (string)file_get_contents($file) : '';
        try {
            $doc = JsonFile::decodeObject($raw);
        } catch (\JsonException $e) {
            return [];
        }
        if (!is_array($audit) || ($audit['vulnerabilities'] ?? []) === [] || !$doc instanceof \stdClass) {
            return [];
        }
        $direct = [];
        foreach (['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as $section) {
            foreach (array_keys((array)($doc->{$section} ?? [])) as $name) {
                $direct[(string)$name] = true;
            }
        }
        $plan = NpmOverrides::plan(
            $audit,
            static fn (string $pkg): array => Lockfile::versions($abs, 'npm', $pkg) ?? [],
            fn (string $pkg): ?array => self::registryVersions($ctx->runner, $abs, $pkg),
            (array)($doc->overrides ?? []),
            $direct,
            $ctx->opt->allowMajor
        );
        $notes = $plan['notes'];
        if ($plan['overrides'] === []) {
            return $notes;
        }
        $lockFile = $abs . '/package-lock.json';
        $lock     = is_file($lockFile) ? (string)file_get_contents($lockFile) : null;
        $doc->overrides = (object)array_merge((array)($doc->overrides ?? []), $plan['overrides']);
        file_put_contents($file, JsonFile::encode($doc, JsonFile::detectIndent($raw)));
        $r    = $install();
        $list = implode(', ', array_map(static fn (string $k, string $v): string => "{$k} {$v}", array_keys($plan['overrides']), $plan['overrides']));
        if (!$r->ok()) {
            file_put_contents($file, $raw);
            if ($lock !== null) {
                file_put_contents($lockFile, $lock);
            }
            $notes[] = "npm overrides not kept ({$list}): npm install " . $r->failureReason();
            return $notes;
        }
        $notes[] = "npm overrides for what npm audit fix left: {$list}";
        return $notes;
    }

    /**
     * Remove the override behind npm's "No matching version found for
     * name@spec" from package.json. Returns a note, or null when the failure
     * is not an override's (a declared dependency is for a person to fix).
     */
    private function dropUnpublishedOverride(Context $ctx, string $dir, CommandResult $r): ?string
    {
        if (preg_match('/No matching version found for ((?:@[\w.-]+\/)?[\w.-]+)@(\S+?)\.?(?:\s|$)/', $r->output, $m) !== 1) {
            return null;
        }
        [$name, $spec] = [$m[1], $m[2]];
        $file = $this->abs($ctx, $dir) . '/package.json';
        $raw  = is_file($file) ? (string)file_get_contents($file) : '';
        try {
            $doc = JsonFile::decodeObject($raw);
        } catch (\JsonException $e) {
            return null;
        }
        if (!$doc instanceof \stdClass) {
            return null;
        }
        $dropped = [];
        foreach (['overrides', 'resolutions'] as $section) {
            if (!($doc->{$section} ?? null) instanceof \stdClass) {
                continue;
            }
            foreach (get_object_vars($doc->{$section}) as $key => $value) {
                // Exactly this package: "json-schema-ref-parser" is not
                // "@apidevtools/json-schema-ref-parser"
                if ($value === $spec && ($key === $name || str_starts_with((string)$key, $name . '@'))) {
                    unset($doc->{$section}->{$key});
                    $dropped[] = "{$section}.{$key}";
                }
            }
            if (get_object_vars($doc->{$section}) === []) {
                unset($doc->{$section});
            }
        }
        if ($dropped === [] || file_put_contents($file, JsonFile::encode($doc, JsonFile::detectIndent($raw))) === false) {
            return null;
        }
        return "removed " . implode(', ', $dropped) . " {$spec} from package.json: npm has no matching version of {$name}";
    }

    /**
     * Every version the registry publishes for a package, or null when it
     * cannot be asked (offline, private registry without access).
     *
     * @return list<string>|null
     */
    public static function registryVersions(ProcessRunner $runner, string $cwd, string $pkg): ?array
    {
        $r    = $runner->run(['npm', 'view', $pkg, 'versions', '--json'], $cwd, ['timeout' => 60, 'label' => 'npm view']);
        $data = self::json($r->stdout);
        if (!$r->ok()) {
            return is_array($data) && in_array($data['error']['code'] ?? null, ['E404'], true) ? [] : null;
        }
        return match (true) {
            is_string($data) => [$data],
            is_array($data)  => array_values(array_map('strval', array_filter($data, 'is_string'))),
            default          => null,
        };
    }

    /**
     * npm/pnpm style {info, low, moderate, high, critical, total}.
     */
    private function fromCounts(CommandResult $r, string $what, callable $pick): TargetResult
    {
        $data   = self::json($r->stdout);
        $counts = is_array($data) ? $pick($data) : null;
        if (!is_array($counts)) {
            $t = TargetResult::fromFailure($r, $what);
            if (is_array($data) && isset($data['error']['summary'])) {
                $t->detail = $what . ': ' . $data['error']['summary'];
            }
            return $t;
        }
        return TargetResult::fromSeverities(self::normalise($counts), $what);
    }

    /**
     * @param array<string, mixed> $counts
     * @return array<string, int>
     */
    private static function normalise(array $counts): array
    {
        $out = [];
        foreach ($counts as $sev => $n) {
            if ($sev === 'total' || !is_numeric($n)) {
                continue;
            }
            $key       = self::severity((string)$sev);
            $out[$key] = ($out[$key] ?? 0) + (int)$n;
        }
        return $out;
    }

    private function yarnVersion(Context $ctx): string
    {
        return $ctx->toolVersion('yarn', ['yarn', '--version']);
    }
}
