<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\PythonAuditor;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\TargetResult;
use PHPUnit\Framework\TestCase;

/**
 * Which Python spellings are detected as projects, which of them pip-audit
 * can actually consume, and that a detected-but-unauditable directory is
 * surfaced by name instead of being invisible.
 */
class PythonAuditorTest extends TestCase
{
    use Fixtures;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testEveryPythonSpellingIsDetectedAsAProject(): void
    {
        $this->assertSame(
            ['requirements.txt', '*requirements*.txt', 'pyproject.toml', 'Pipfile', 'setup.py', 'setup.cfg', 'poetry.lock'],
            (new PythonAuditor())->manifests()
        );
    }

    public function testRequirementsSpellingsThatFlowIntoPipAudit(): void
    {
        foreach (['requirements.txt', 'requirements-dev.txt', 'dev-requirements.txt', 'test-requirements.txt', 'pip-requirements.txt'] as $ok) {
            $this->assertTrue(PythonAuditor::isRequirements($ok), $ok . ' is consumable with -r');
        }
        foreach (['requirements.pip', 'requirements.yml', 'pyproject.toml', 'setup.py', 'setup.cfg', 'poetry.lock', 'Pipfile'] as $no) {
            $this->assertFalse(PythonAuditor::isRequirements($no), $no . ' is not a requirements file');
        }
    }

    public function testThePlainRequirementsFileIsAuditedFirstAndTheRestByName(): void
    {
        $files = PythonAuditor::requirementsFiles(static fn (): array => [
            'setup.py', 'dev-requirements.txt', 'requirements-dev.txt', 'requirements.txt', 'README.md',
        ]);
        $this->assertSame(['requirements.txt', 'dev-requirements.txt', 'requirements-dev.txt'], $files);
    }

    public function testADirectoryWithoutAnyPythonManifestNamesNothing(): void
    {
        // Detection is the ManifestIndex's job; with no requirements file and
        // no other manifest in the directory the audit still says why
        $log  = $this->fakePipAudit();
        $root = $this->scratchDir('plain');
        file_put_contents($root . '/main.py', "print('hi')\n");

        $t = (new PythonAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertSame(TargetResult::SKIP, $t->status);
        $this->assertSame('no requirements file to audit', $t->detail);
        $this->assertFileDoesNotExist($log, 'pip-audit is never run');
    }

    public function testADetectedProjectWithoutARequirementsFileIsSkippedByName(): void
    {
        $log  = $this->fakePipAudit();
        $root = $this->scratchDir('pipeline');
        file_put_contents($root . '/pyproject.toml', "[project]\nname = 'pipeline'\n");
        file_put_contents($root . '/setup.cfg', "[options]\ninstall_requires = requests\n");

        $t = (new PythonAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertSame(TargetResult::SKIP, $t->status);
        $this->assertStringContainsString('(found pyproject.toml, setup.cfg; pip-audit reads requirements files)', $t->detail,
            'surfacing beats silence: the SKIP names what was found');
        $this->assertFileDoesNotExist($log, 'pip-audit is never run for files it cannot consume');
    }

    public function testEveryRequirementsFileInTheDirectoryIsAudited(): void
    {
        $log  = $this->fakePipAudit();
        $root = $this->scratchDir('reqs');
        file_put_contents($root . '/requirements.txt', "requests==2.31.0\n");
        file_put_contents($root . '/requirements-dev.txt', "pytest==7.0.0\n");

        $t = (new PythonAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $calls = file($log, FILE_IGNORE_NEW_LINES) ?: [];
        $this->assertCount(2, $calls);
        $this->assertStringContainsString('-r requirements.txt ', $calls[0]);
        $this->assertStringContainsString('-r requirements-dev.txt ', $calls[1], 'a vulnerable pin hiding in the dev file is still checked');
    }

    /**
     * @return string the call log, one line per pip-audit run
     */
    private function fakePipAudit(): string
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/pip-audit', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            echo '{"dependencies": [], "fixes": []}'
            SH);
        chmod($bin . '/pip-audit', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        return $log;
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
