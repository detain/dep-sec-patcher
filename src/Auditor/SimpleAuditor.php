<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\TargetResult;

/**
 * Ecosystems with no vulnerability audit of their own, only an outdated
 * listing (check mode) or an upgrade (update mode): Dart, Elixir, Swift, R.
 * A failure is a warning, not a vulnerability.
 */
final class SimpleAuditor extends Auditor
{
    /**
     * @param list<string>      $manifests
     * @param list<list<string>> $checkArgv  commands in check mode
     * @param list<list<string>> $updateArgv commands in update mode
     * @param ?string           $serialWhy  set when the tool must not run concurrently
     * @param list<string>      $versionArgv
     * @param list<string>      $prepareArgv one-off setup run in the parent
     * @param list<string>      $majorOnly  update-mode arguments dropped without --allow-major
     * @param ?\Closure(string): ?string $explain names a known failure from the tool's output
     */
    public function __construct(
        private string $name,
        private string $tool,
        private array $manifests,
        private array $checkArgv,
        private array $updateArgv,
        private ?string $serialWhy = null,
        private array $versionArgv = [],
        private array $prepareArgv = [],
        private string $note = '',
        private string $versionPattern = '/(\d+\.\d+(?:\.\d+)?)/',
        private array $majorOnly = [],
        private ?\Closure $explain = null,
    ) {
    }

    public static function dart(): self
    {
        return new self(
            'dart',
            'dart',
            ['pubspec.yaml'],
            [['dart', 'pub', 'outdated']],
            [['dart', 'pub', 'upgrade', '--major-versions']],
            'pub has no documented locking for concurrent runs against the shared pub cache (no fixed version known)',
            ['dart', '--version'],
            majorOnly: ['--major-versions'],
            explain: self::dartFailure(...),
        );
    }

    /**
     * Pub's refusal of a package that predates null safety: no `environment:
     * sdk:` lower bound of 2.12 (none at all reads as "<2.0.0"). Dart 3 only
     * runs null-safe code, so no upgrade can resolve it; the code has to be
     * migrated, or for a generated client, regenerated.
     */
    public static function dartFailure(string $output): ?string
    {
        if (preg_match("/Because (\\S+) doesn't support null safety|only supports null safety|or higher to enable null safety/", $output, $m) !== 1) {
            return null;
        }
        $pkg = $m[1] ?? 'the package';
        $sdk = preg_match('/"sdk: \'([^\']+)\'"/', $output, $c) === 1 ? "sdk '{$c[1]}'" : 'its SDK constraint';
        return "{$pkg} predates null safety ({$sdk}; Dart 3 needs >=2.12.0): not upgradable, "
            . 'the code must be migrated or, for a generated client, regenerated';
    }

    public static function elixir(): self
    {
        return new self(
            'elixir',
            'mix',
            ['mix.exs'],
            // hex.audit reads the fetched dependencies, so check mode fetches
            // them first (the workspace guard removes deps/ and _build/ again)
            [['mix', 'deps.get'], ['mix', 'hex.audit']],
            [['mix', 'deps.update', '--all'], ['mix', 'hex.audit']],
            'Hex\'s shared package cache has no documented concurrency guarantee (no fixed version known)',
            ['elixir', '--version'],
            ['mix', 'local.hex', '--force'],
            '',
            '/Elixir (\d+\.\d+(?:\.\d+)?)/'
        );
    }

    public static function swift(): self
    {
        return new self(
            'swift',
            'swift',
            ['Package.swift'],
            [['swift', 'package', 'show-dependencies']],
            [['swift', 'package', 'update']],
            'SwiftPM\'s shared dependency cache is not safe for concurrent resolution (no fixed version known)',
            ['swift', '--version']
        );
    }

    public static function r(): self
    {
        // The original shell script also ran update.packages() in update mode, which
        // upgraded the host's own R library and never touched a project's
        // DESCRIPTION; only the read-only listing is kept.
        return new self(
            'r',
            'Rscript',
            ['DESCRIPTION', 'renv.lock'],
            [['Rscript', '-e', 'old.packages()']],
            [['Rscript', '-e', 'old.packages()']],
            null,
            [],
            [],
            'lists outdated packages in the host R library'
        );
    }

    public function name(): string
    {
        return $this->name;
    }

    public function tool(): string
    {
        return $this->tool;
    }

    public function manifests(): array
    {
        return $this->manifests;
    }

    public function concurrency(Context $ctx): array
    {
        if ($this->serialWhy === null) {
            return parent::concurrency($ctx);
        }
        $version = $this->versionArgv === [] ? '' : $ctx->toolVersion($this->name, $this->versionArgv, $this->versionPattern);
        return [$this->name => ConcurrencyPolicy::serial($this->name, $version, $this->serialWhy)];
    }

    public function prepare(Context $ctx, array $targets): void
    {
        if ($this->prepareArgv !== []) {
            $r = $ctx->runner->run($this->prepareArgv, $ctx->root, ['label' => $this->name . ':setup']);
            if (!$r->ok()) {
                $ctx->console->warn(implode(' ', $this->prepareArgv) . ' ' . $r->failureReason());
            }
        }
    }

    public function audit(Context $ctx, string $dir): TargetResult
    {
        $steps = $ctx->checkMode() ? $this->checkArgv : $this->updateArgv;
        if (!$ctx->opt->allowMajor && $this->majorOnly !== []) {
            $steps = array_map(fn (array $argv): array => array_values(array_diff($argv, $this->majorOnly)), $steps);
        }
        foreach ($steps as $argv) {
            $r = $this->run($ctx, $dir, $argv);
            if (!$r->ok()) {
                $why = $this->explain !== null ? ($this->explain)(CommandResult::plain($r->output)) : null;
                $t   = new TargetResult(TargetResult::WARN, implode(' ', $argv) . ($why !== null ? ': ' . $why : ' ' . $r->failureReason()));
                $t->tail = $r->tail(15);
                return $t;
            }
        }
        $t = new TargetResult(TargetResult::PASS, implode(' ', $steps[count($steps) - 1]) . ' ok');
        if ($this->note !== '') {
            $t->note($this->note);
        }
        return $t;
    }
}
