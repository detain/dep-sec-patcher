<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\NodeAuditor;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestEditor;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\NodeWorkspace;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\TargetResult;
use Detain\DepSecPatcher\WorkspaceGuard;
use PHPUnit\Framework\TestCase;

/**
 * pnpm/yarn workspaces: root and member detection, the Node auditor skipping
 * members (whose workspace protocols npm cannot resolve), the protocol
 * specifier guard outside any detected root, and the guard removing lockfiles
 * a stray run created in a directory whose workspace owns none.
 *
 * The audits are driven through stand-in tools on PATH, so nothing touches
 * the network or a real package manager.
 */
class NodeWorkspaceTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    // ── detection ────────────────────────────────────────────────────────────

    public function testClaimsMatchesGlobsExactlyTheWayWorkspaceToolsDo(): void
    {
        $this->assertTrue(NodeWorkspace::claims(['apps/*'], 'apps/electron'));
        $this->assertFalse(NodeWorkspace::claims(['apps/*'], 'apps/electron/sub'), 'a single star spans no directory separator');
        $this->assertFalse(NodeWorkspace::claims(['apps/*'], 'libs/x'));
        $this->assertTrue(NodeWorkspace::claims(['tools/cli'], 'tools/cli'), 'exact paths claim themselves');
        $this->assertFalse(NodeWorkspace::claims(['tools/cli'], 'tools/cli/inner'));
        $this->assertFalse(NodeWorkspace::claims(['packages/*', '!packages/legacy'], 'packages/legacy'), 'negation rejects');
        $this->assertFalse(NodeWorkspace::claims(['!packages/legacy', 'packages/*'], 'packages/legacy'), 'an exclusion wins whatever its order');
        $this->assertTrue(NodeWorkspace::claims(['packages/*', '!packages/other'], 'packages/legacy'), 'an exclusion that does not match changes nothing');
        $this->assertTrue(NodeWorkspace::claims(['pkg/**'], 'pkg/a'));
        $this->assertTrue(NodeWorkspace::claims(['pkg/**'], 'pkg/a/b'), 'a double star spans directories');
        $this->assertTrue(NodeWorkspace::claims(['**/lib'], 'a/b/lib'));
        $this->assertTrue(NodeWorkspace::claims(['@scope/*'], '@scope/pkg'), 'a scoped member name is a single segment');
    }

    public function testYamlPackagesReadsTheWorkspaceListOnly(): void
    {
        $yaml = "# monorepo\npackages:\n  - apps/*\n  - \"packages/*\"\n  - '!packages/legacy' # ours is not yours\n\n"
            . "catalogs:\n  default:\n    qs: ^6.11.2\n\nonlyBuiltDependencies: []\n";
        $this->assertSame(['apps/*', 'packages/*', '!packages/legacy'], NodeWorkspace::yamlPackages($yaml));
        $this->assertSame(['a/*', 'b/*'], NodeWorkspace::yamlPackages("packages: [\"a/*\", \"b/*\"]\nroot: false\n"));
        $this->assertSame([], NodeWorkspace::yamlPackages("catalogs:\n  default:\n    qs: ^6.11.2\n"));
    }

    public function testRootManagerFollowsTheEvidenceOfTheRoot(): void
    {
        $root = $this->scratchDir('ws');
        $this->assertSame('npm', NodeWorkspace::rootManager($root));

        file_put_contents($root . '/package.json', '{"name":"r","workspaces":["packages/*"]}');
        $this->assertSame('npm', NodeWorkspace::rootManager($root), 'npm/yarn 1 workspaces keep a root package-lock');

        file_put_contents($root . '/yarn.lock', "# yarn lockfile v1\n");
        $this->assertSame('yarn', NodeWorkspace::rootManager($root));
        unlink($root . '/yarn.lock');

        file_put_contents($root . '/package.json', '{"name":"r","workspaces":["packages/*"],"packageManager":"pnpm@9.1.2"}');
        $this->assertSame('pnpm', NodeWorkspace::rootManager($root), 'corepack is the tiebreaker without a lockfile');

        file_put_contents($root . '/pnpm-workspace.yaml', "packages:\n  - packages/*\n");
        $this->assertSame('pnpm', NodeWorkspace::rootManager($root));
    }

    public function testContainingFindsTheRootAndItsMembersInsideTheScannedTree(): void
    {
        $root = $this->pnpmTree();

        $member = NodeWorkspace::containing($root, $root . '/apps/x');
        $this->assertIsArray($member);
        $this->assertSame($root, $member['root']);
        $this->assertSame('', $member['rel']);
        $this->assertSame('pnpm', $member['manager']);
        $this->assertTrue($member['member']);

        $top = NodeWorkspace::containing($root, $root);
        $this->assertIsArray($top);
        $this->assertFalse($top['member'], 'a root is never its own member');

        $this->assertNull(NodeWorkspace::containing($root . '/apps/x', $root . '/apps/x'), 'the workspace root sits above the scanned tree');
    }

    // ── audit dispatch ───────────────────────────────────────────────────────

    public function testWorkspaceMembersAreSkippedAsCoveredByTheRootAudit(): void
    {
        $log  = $this->silentShims(['npm', 'pnpm', 'yarn']);
        $root = $this->pnpmTree();
        $aud  = new NodeAuditor();

        foreach (['apps/x' => 'workspace:*', 'packages/y' => 'catalog:'] as $dir => $protocol) {
            $t = $aud->audit($this->context($root, ['--update']), $dir);
            $this->assertSame(TargetResult::SKIP, $t->status, $dir);
            $this->assertStringContainsString('pnpm workspace member — covered by root workspace audit at .', $t->detail);
            $this->assertFileDoesNotExist($root . '/' . $dir . '/package-lock.json', 'no npm install is attempted in a member (' . $protocol . ')');
        }
        $this->assertSame('', $this->calls($log), 'a skipped member runs no tool at all');
    }

    public function testTheWorkspaceRootAuditsThroughPnpmEvenWithoutItsLockfile(): void
    {
        $log  = $this->shim('pnpm', <<<'SH'
            echo "pnpm $*" >> '__LOG__'
            case " $* " in
              *" audit --json "*) echo '{"metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 0, "total": 1}}}' ;;
            esac
            SH);
        $root = $this->pnpmTree();
        unlink($root . '/pnpm-lock.yaml'); // pnpm-workspace.yaml alone must still mean pnpm
        $t = (new NodeAuditor())->audit($this->context($root, ['--update']), '');
        $this->assertSame(TargetResult::FAIL, $t->status, $t->detail);
        $calls = $this->calls($log);
        $this->assertStringContainsString('pnpm up', $calls, 'update mode upgrades the whole workspace graph');
        $this->assertStringContainsString('pnpm audit --json', $calls);
    }

    public function testANegatedMemberIsNoMemberAndStillAuditsWithNpm(): void
    {
        $log  = $this->shim('npm', <<<'SH'
            echo "npm $*" >> '__LOG__'
            case " $* " in
              *" audit --json "*) echo '{"metadata": {"vulnerabilities": {"high": 0, "critical": 0}}}' ;;
            esac
            SH);
        $root = $this->pnpmTree();
        $t    = (new NodeAuditor())->audit($this->context($root, ['--update']), 'packages/legacy');
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $this->assertStringContainsString('npm install --package-lock-only', $this->calls($log), 'the negation dropped it from the workspace, npm handles it');
    }

    public function testNpmIsNotTriedWhereWorkspaceProtocolsCannotResolve(): void
    {
        $log  = $this->silentShims(['npm']);
        $dir  = $this->scratchDir('stray'); // no workspace anywhere above it
        file_put_contents($dir . '/package.json', '{"name":"orphan","dependencies":{"shared":"workspace:^1.0.0"}}');
        $t = (new NodeAuditor())->audit($this->context($dir, ['--update']), '');
        $this->assertSame(TargetResult::SKIP, $t->status);
        $this->assertStringContainsString('npm cannot resolve shared=workspace:^1.0.0 (a workspace-protocol specifier)', $t->detail);
        $this->assertSame('', $this->calls($log), 'belt and braces: npm install never runs, so no lockfile is created for --push to commit');
    }

    public function testGuardPurgeNamesTheLockfilesAWrongManagerRunMayCreate(): void
    {
        $root  = $this->pnpmTree();
        $ctx   = $this->context($root, ['--update']);
        $aud   = new NodeAuditor();
        $this->assertSame(NodeWorkspace::lockfiles(), $aud->guardPurge($ctx, 'apps/x'), 'a member owns no lockfile at all');
        $this->assertSame(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock'], $aud->guardPurge($ctx, ''),
            'the pnpm root keeps pnpm-lock.yaml, which `pnpm up` is meant to write');
        $outside = $this->scratchDir('plain');
        file_put_contents($outside . '/package.json', '{}');
        $this->assertSame([], $aud->guardPurge($this->context($outside, ['--update']), ''), 'npm keeps what it resolved outside any workspace');
    }

    public function testTheCorepackTiebreakerReadsTheVersionedField(): void
    {
        // "packageManager": "yarn@3.6.4" is what the field holds; the bare
        // names the old tiebreaker compared for never matched it, so every
        // such directory dispatched to npm
        $root = $this->scratchDir('declared');
        $this->silentShims(['npm', 'yarn', 'pnpm']);
        $aud = new NodeAuditor();

        file_put_contents($root . '/package.json', "{\"name\":\"solo\",\"packageManager\":\"yarn@3.6.4\"}\n");
        $this->assertSame('node:yarn', $aud->group($this->context($root, ['--update']), ''));
        file_put_contents($root . '/package.json', "{\"name\":\"solo\",\"packageManager\":\"pnpm@9.1.2\"}\n");
        $this->assertSame('node:pnpm', $aud->group($this->context($root, ['--update']), ''));
        file_put_contents($root . '/package.json', "{\"name\":\"solo\",\"packageManager\":\"npm@10.1.0\"}\n");
        $this->assertSame('node:npm', $aud->group($this->context($root, ['--update']), ''), 'npm stays npm, versioned or not');
        file_put_contents($root . '/package.json', "{\"name\":\"solo\",\"packageManager\":\"deno@2.0.0\"}\n");
        $this->assertSame('node:npm', $aud->group($this->context($root, ['--update']), ''), 'an unknown manager falls back as before');
    }

    public function testAYarnDeclaredRootWithoutALockfileAuditsWithYarnAndPurgesNpmLocks(): void
    {
        $log  = $this->silentShims(['npm', 'yarn', 'pnpm']);
        $root = $this->scratchDir('yarn-declared');
        file_put_contents($root . '/package.json', "{\"name\":\"r\",\"workspaces\":[\"packages/*\"],\"packageManager\":\"yarn@3.6.4\"}\n");
        mkdir($root . '/packages', 0775, true);
        $ctx = $this->context($root, ['--update']);
        $aud = new NodeAuditor();

        $aud->audit($ctx, '');
        $calls = $this->calls($log);
        $this->assertStringContainsString('yarn audit', $calls, 'the declared manager runs, npm is not tried');
        $this->assertStringNotContainsString('npm install', $calls);
        $this->assertSame(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml'], $aud->guardPurge($ctx, ''),
            'what npm would leave here is a foreign lock: the purge keeps yarn.lock and removes the rest');
    }

    public function testTheGuardRemovesACreatedLockfilePurgedEvenInUpdateMode(): void
    {
        $dir = $this->scratchDir('guard');
        file_put_contents($dir . '/package.json', '{}');
        file_put_contents($dir . '/pnpm-lock.yaml', "lockfileVersion: '9.0'\n"); // pre-existing: never touched
        $guard = new WorkspaceGuard($dir, false, NodeWorkspace::lockfiles());
        file_put_contents($dir . '/package-lock.json', '{}');
        $undone = $guard->restore();

        $this->assertFileDoesNotExist($dir . '/package-lock.json');
        $this->assertFileExists($dir . '/pnpm-lock.yaml', 'what existed before stays, purge covers created files only');
        $this->assertContains('removed package-lock.json', $undone);

        // without the purge list the update-mode default stands: new lockfiles are kept
        $guard = new WorkspaceGuard($dir, false);
        file_put_contents($dir . '/package-lock.json', '{}');
        $guard->restore();
        $this->assertFileExists($dir . '/package-lock.json');
    }

    // ── manifest classification ──────────────────────────────────────────────

    public function testWorkspaceLinksAreInternalNotCannotEdit(): void
    {
        foreach (['workspace:*', 'workspace:^', 'catalog:', 'catalog:libs'] as $spec) {
            $json = '{"dependencies": {"shared": "' . $spec . '"}}';
            $res  = ManifestEditor::apply('npm', 'package.json', $json, 'shared', '2.1.0');
            $this->assertSame(ManifestEditor::INTERNAL, $res['status'], $spec);
            $this->assertSame($json, $res['content'], 'the link is not rewritten');
            $this->assertSame($spec, ManifestEditor::declared('npm', 'package.json', $json, 'shared'));
        }
        // a real non-registry spec still reports cannot-edit, and a bumpable one still edits
        $this->assertSame(ManifestEditor::UNSUPPORTED,
            ManifestEditor::apply('npm', 'package.json', '{"dependencies": {"x": "git+https://github.com/a/b.git"}}', 'x', '2.0.0')['status']);
        $this->assertSame(ManifestEditor::OK,
            ManifestEditor::apply('npm', 'package.json', '{"dependencies": {"x": "^1.0.0"}}', 'x', '1.4.4')['status']);
    }

    // ── fixtures ─────────────────────────────────────────────────────────────

    /**
     * A pnpm monorepo: the root carries pnpm-workspace.yaml and pnpm-lock.yaml
     * (the only lockfile the repository ships), apps/x links a sibling with
     * workspace:*, packages/y resolves from the catalog, and packages/legacy
     * is negated out of the workspace.
     */
    private function pnpmTree(): string
    {
        $root = $this->scratchDir('pnpm-ws');
        file_put_contents($root . '/pnpm-workspace.yaml', "packages:\n  - apps/*\n  - packages/*\n  - '!packages/legacy'\n\nonlyBuiltDependencies: []\n");
        file_put_contents($root . '/pnpm-lock.yaml', "lockfileVersion: '9.0'\n");
        file_put_contents($root . '/package.json', "{\"name\": \"monorepo\", \"private\": true, \"packageManager\": \"pnpm@9.1.2\"}\n");
        mkdir($root . '/apps/x', 0775, true);
        file_put_contents($root . '/apps/x/package.json', "{\"name\": \"x\", \"dependencies\": {\"shared\": \"workspace:*\"}}\n");
        mkdir($root . '/packages/y', 0775, true);
        file_put_contents($root . '/packages/y/package.json', "{\"name\": \"y\", \"dependencies\": {\"qs\": \"catalog:\"}}\n");
        mkdir($root . '/packages/legacy', 0775, true);
        file_put_contents($root . '/packages/legacy/package.json', "{\"name\": \"legacy\", \"dependencies\": {\"left-pad\": \"^1.3.0\"}}\n");
        return $root;
    }

    /**
     * One log file; $tools succeed silently, recording every call — a test
     * asserting an empty log proves no command ran.
     *
     * @param list<string> $tools
     */
    private function silentShims(array $tools): string
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        foreach ($tools as $tool) {
            file_put_contents($bin . '/' . $tool, "#!/bin/sh\necho \"{$tool} \$*\" >> " . escapeshellarg($log) . "\n");
            chmod($bin . '/' . $tool, 0755);
        }
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        touch($log);
        return $log;
    }

    /**
     * A stand-in tool on PATH recording its calls; __LOG__ in the body is the
     * log file. Returns the log path.
     */
    private function shim(string $tool, string $body): string
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/' . $tool, "#!/bin/sh\n" . str_replace('__LOG__', escapeshellarg($log), $body) . "\n");
        chmod($bin . '/' . $tool, 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        touch($log);
        return $log;
    }

    private function calls(string $log): string
    {
        return implode("\n", file($log, FILE_IGNORE_NEW_LINES) ?: []);
    }

    /**
     * @param list<string> $args
     */
    private function context(string $root, array $args): Context
    {
        [$console, $runner] = $this->quietRunner(30);
        return new Context(Options::parse($args, []), $console, $runner, $root, $this->scratchDir('reports'), ManifestIndex::fromList($root, []));
    }
}
