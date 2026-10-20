<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Whether one security issue is resolved by what a checkout declares right
 * now, for close-fixed. Reads manifests and lockfiles under $root and
 * nothing else, so it can be run against a checkout outside a full run.
 *
 * Anything that cannot be checked is "unverifiable", never "resolved":
 * under-closing is recoverable, closing a live vulnerability is not.
 *
 * Need is one requirement of one issue (FixPlanner::issueRequirements
 * yields them); Verdict is what verify() answers, and what CloseState
 * remembers.
 *
 * @phpstan-type Need array{ecosystem: string, package: string, fixed_version: string, fix_versions: list<string>, manifest: string}
 * @phpstan-type Verdict array{ok: bool, reason: string, detail: string, evidence: string}
 */
final class IssueVerifier
{
    /** @var array<string, string> absolute path => contents */
    private array $contents = [];

    /**
     * @param callable(string): list<string> $listDir relative dir => basenames
     * @param callable(string): bool         $inScope whether a manifest is in the part scanned
     * @param (callable(string): ?string)|null $removedIn the commit on the checked-out branch
     *        that deleted a manifest no longer in it, or null when it was never there
     *        (a typo, a path from another branch, or history a shallow clone lacks)
     */
    public function __construct(
        private string $root,
        private $listDir,
        private $inScope,
        private string $subdir = '',
        private $removedIn = null
    ) {
    }

    /**
     * @param list<Need> $needs
     * @return Verdict
     *         reason: '' when ok, else unresolved / unverifiable / out-of-scope;
     *         evidence: markdown table rows for the closing comment
     */
    public function verify(array $needs): array
    {
        $evidence = '';
        foreach ($needs as $need) {
            if ($need['package'] === '') {
                continue;
            }
            // With --subdir, an issue is only judged when every manifest it
            // names is inside the scanned part
            if (!($this->inScope)($need['manifest'])) {
                return self::fail('out-of-scope', "{$need['manifest']} is outside {$this->subdir}");
            }
            if ($need['fixed_version'] === '') {
                return self::fail('unverifiable', "no fixed version is known for one of the {$need['package']} vulnerabilities");
            }
            $target = ManifestPaths::sourceManifestFor($need['manifest'], $this->listDir);
            $abs    = $this->insideRoot($target);
            // One fix per release line, any of which will do on its own line
            $required = implode(' or ', FixPlanner::fixes($need));
            if ($abs === null) {
                // A project deleted from the branch takes its dependencies
                // with it; a path that was never there proves nothing
                $commit = $this->removedIn !== null && $this->insideRoot($need['manifest']) === null ? ($this->removedIn)($target) : null;
                if ($commit === null || $commit === '') {
                    return self::fail('unverifiable', "manifest missing: {$target}");
                }
                $evidence .= "| `{$need['package']}` | {$required} | **manifest removed** in " . substr($commit, 0, 12) . " | `{$target}` |\n";
                continue;
            }
            // Where a lockfile exists, what it resolved is what gets installed
            $eco    = ManifestPaths::ecosystemFor($target);
            $locked = in_array($eco, ['npm', 'composer'], true) ? Lockfile::versions(dirname($abs), $eco, $need['package']) : null;
            if ($locked !== null && $locked !== []) {
                $behind = array_values(array_filter($locked, static fn (string $v): bool => !FixPlanner::requirementMet($v, $need)));
                if ($behind !== []) {
                    return self::fail('unresolved', "{$need['package']} is locked at " . implode(', ', $behind) . ', ' . FixPlanner::shortfall($behind, $need));
                }
                $evidence .= "| `{$need['package']}` | {$required} | **" . implode(', ', $locked) . " (locked)** | `{$target}` |\n";
                continue;
            }
            $this->contents[$abs] ??= (string)file_get_contents($abs);
            $cur = ManifestEditor::declared($need['ecosystem'], $target, $this->contents[$abs], $need['package']);
            if ($cur === '') {
                // A transitive dependency: only a lockfile could say what is
                // installed, and there is none this can read
                return self::fail('unverifiable', "{$need['package']} not declared in {$target}"
                    . ($locked === [] ? ' (nor in its lockfile)' : ' (transitive, and no lockfile to check)'));
            }
            if (!FixPlanner::requirementMet($cur, $need)) {
                return self::fail('unresolved', "{$need['package']} is {$cur}, " . FixPlanner::shortfall([$cur], $need));
            }
            // Record the evidence so the closing comment shows its working
            $evidence .= "| `{$need['package']}` | {$required} | **{$cur}** | `{$target}` |\n";
        }
        return ['ok' => true, 'reason' => '', 'detail' => '', 'evidence' => $evidence];
    }

    /**
     * @return Verdict
     */
    private static function fail(string $reason, string $detail): array
    {
        return ['ok' => false, 'reason' => $reason, 'detail' => $detail, 'evidence' => ''];
    }

    private function insideRoot(string $rel): ?string
    {
        $real = realpath($this->root . '/' . $rel);
        $root = realpath($this->root);
        if ($real === false || $root === false || !is_file($real) || !str_starts_with($real, rtrim($root, '/') . '/')) {
            return null;
        }
        return $real;
    }
}
