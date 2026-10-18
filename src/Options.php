<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use InvalidArgumentException;

/**
 * Command-line options. `--opt value` and `--opt=value` are both accepted.
 *
 * Precedence, lowest first: built-in defaults, the config file
 * (.dep-sec-patcher.json, see Config), the environment, then the command line.
 *
 * Pure: argv, environment and config in, value object out.
 */
final class Options
{
    public const ECOSYSTEMS = [
        'maven', 'gradle', 'sbt', 'node', 'php', 'python', 'ruby', 'go', 'rust', 'dotnet', 'dart', 'elixir', 'swift', 'r',
    ];
    public const SCANNERS = ['bandit', 'trivy', 'grype', 'netsec'];
    /** Scanner switches: the --only names plus gosec, which runs inside the go audit. */
    public const SCANNER_SWITCHES = ['bandit', 'trivy', 'gosec', 'grype', 'netsec'];

    public int $threads = 1;
    /** Positional TARGET: a directory, a git URL or an OWNER/NAME GitHub shorthand ('' = cwd). */
    public string $target = '';
    public string $subdir = '';
    public string $trivy = 'auto';
    public string $gosec = 'auto';
    public string $bandit = 'auto';
    public string $grype = 'auto';
    public string $netsec = 'auto';
    public string $cvssThreshold = '7.0';
    public bool $debug = false;
    public bool $verbose = false;
    public string $ghRepo = '';
    public string $vulnDb = '';
    public string $stateDir = '';
    public string $workdir = '';
    public string $configFile = '';
    public int $maxIssues = 300;
    public string $github = 'auto';
    public string $mergePrs = 'auto';
    public string $autoFix = 'auto';
    /** Let auto-fix move a declared dependency to a new major version. */
    public bool $allowMajor = false;
    public bool $applyStored = false;
    public bool $closeFixed = false;
    public string $closeLabel = 'security: verified fixed';
    public int $closeDelay = 5;
    public int $closeLimit = 400;
    public string $mode = 'update';
    public int $timeout = 1800;
    public int $nvdTimeout = 3600;
    public string $nvdApiKey = '';
    public string $reportDir = '';
    public bool $push = false;
    /** How --push publishes: 'branch', 'pr' (--pr) or 'direct' (--push-direct). */
    public string $pushMode = 'branch';
    /** --pr merge method: squash, merge, rebase, or none to leave the PR open. */
    public string $prMerge = 'squash';
    public string $branch = '';
    public bool $strict = false;
    public bool $help = false;
    public bool $version = false;
    /** @var array<string, bool> ecosystem => enabled */
    public array $ecosystems = [];
    /** @var list<string> */
    public array $only = [];
    /** @var list<string> extra directories to skip: names anywhere, or paths relative to the target */
    public array $excludeDirs = [];
    /** @var list<string> extra plain-HTTP URL prefixes the network scanner accepts */
    public array $allowHttp = [];

    /**
     * @param list<string>          $argv   arguments without the program name
     * @param array<string, string> $env
     * @param Config|null           $config defaults from the config file
     */
    public static function parse(array $argv, array $env = [], ?Config $config = null): self
    {
        $o = new self();
        foreach (self::ECOSYSTEMS as $eco) {
            $o->ecosystems[$eco] = true;
        }
        $config?->applyTo($o);

        $o->ghRepo  = $env['GH_REPO'] ?? $o->ghRepo;
        $o->vulnDb  = $env['VULN_DB'] ?? $o->vulnDb;
        $modeFromCli = null;
        $onlyFromCli = false;
        /** @var array<string, true> $pushFlags --pr / --push-direct / --pr-merge as given */
        $pushFlags = [];
        /** @var array<string, true> $disabledByCli */
        $disabledByCli = [];

        $args = $argv;
        for ($i = 0; $i < count($args); $i++) {
            $arg   = $args[$i];
            $value = null;
            if (str_starts_with($arg, '--') && str_contains($arg, '=')) {
                [$arg, $value] = explode('=', $arg, 2);
            }
            $take = static function () use (&$i, $args, $arg, &$value): string {
                if ($value !== null) {
                    return $value;
                }
                if (!array_key_exists($i + 1, $args)) {
                    throw new InvalidArgumentException("option {$arg} requires a value");
                }
                return $args[++$i];
            };

            if (str_starts_with($arg, '--no-') && in_array(substr($arg, 5), self::ECOSYSTEMS, true)) {
                $o->ecosystems[substr($arg, 5)] = false;
                $disabledByCli[substr($arg, 5)] = true;
                continue;
            }
            if (str_starts_with($arg, '--') && in_array(substr($arg, 2), self::SCANNER_SWITCHES, true)) {
                $o->setScanner(substr($arg, 2), 'yes');
                continue;
            }
            if (str_starts_with($arg, '--no-') && in_array(substr($arg, 5), self::SCANNER_SWITCHES, true)) {
                $o->setScanner(substr($arg, 5), 'no');
                $disabledByCli[substr($arg, 5)] = true;
                continue;
            }
            switch ($arg) {
                case '-t':
                case '--threads':
                    $o->threads = self::int($take(), $arg, 1);
                    break;
                case '-h':
                case '--help':
                    $o->help = true;
                    break;
                case '-V':
                case '--version':
                    $o->version = true;
                    break;
                case '-v':
                case '--verbose':
                    $o->verbose = true;
                    break;
                case '--cvss-threshold':
                    $o->cvssThreshold = self::cvss($take(), '--cvss-threshold');
                    break;
                case '--repo':
                    $o->ghRepo = $take();
                    break;
                case '--subdir':
                    $o->subdir = self::relativePath($take(), '--subdir');
                    break;
                case '--vuln-db':
                    $o->vulnDb = $take();
                    break;
                case '--state-dir':
                    $o->stateDir = $take();
                    break;
                case '--workdir':
                    $o->workdir = $take();
                    break;
                case '--config':
                    $o->configFile = $take();
                    break;
                case '--max-issues':
                    $o->maxIssues = self::int($take(), $arg, 0);
                    break;
                case '--no-github':
                    $o->github = 'no';
                    break;
                case '--no-merge-prs':
                    $o->mergePrs = 'no';
                    break;
                case '--no-auto-fix':
                    $o->autoFix = 'no';
                    break;
                case '--allow-major':
                    $o->allowMajor = true;
                    break;
                case '--apply-stored':
                    $o->applyStored = true;
                    break;
                case '--close-fixed':
                    $o->closeFixed = true;
                    break;
                case '--close-label':
                    $o->closeLabel = $take();
                    break;
                case '--close-delay':
                    $o->closeDelay = self::int($take(), $arg, 0);
                    break;
                case '--close-limit':
                    $o->closeLimit = self::int($take(), $arg, 0);
                    break;
                case '--timeout':
                    $o->timeout = self::int($take(), $arg, 0);
                    break;
                case '--nvd-timeout':
                    $o->nvdTimeout = self::int($take(), $arg, 0);
                    break;
                case '--nvd-api-key':
                    $o->nvdApiKey = $take();
                    break;
                case '--report-dir':
                    $o->reportDir = $take();
                    break;
                case '--exclude-dir':
                    $o->excludeDirs[] = self::relativePath($take(), '--exclude-dir');
                    break;
                case '--allow-http':
                    $o->allowHttp[] = self::httpPattern($take(), '--allow-http');
                    break;
                case '--only':
                    if (!$onlyFromCli) {
                        // The command line replaces the config file's list
                        $o->only     = [];
                        $onlyFromCli = true;
                    }
                    foreach (explode(',', $take()) as $name) {
                        $name = trim($name);
                        if ($name === '') {
                            continue;
                        }
                        self::assertCheckName($name, '--only');
                        $o->only[] = $name;
                    }
                    break;
                case '--push':
                    $o->push = true;
                    break;
                case '--pr':
                    $o->push     = true;
                    $o->pushMode = 'pr';
                    $pushFlags[$arg] = true;
                    break;
                case '--push-direct':
                    $o->push     = true;
                    $o->pushMode = 'direct';
                    $pushFlags[$arg] = true;
                    break;
                case '--pr-merge':
                    $o->prMerge = self::choice($take(), $arg, ['squash', 'merge', 'rebase', 'none']);
                    $pushFlags[$arg] = true;
                    break;
                case '--branch':
                    $o->branch = self::branchName($take());
                    break;
                case '--strict':
                    $o->strict = true;
                    break;
                case '--debug':
                    $o->debug = true;
                    break;
                case '--update':
                    $modeFromCli = 'update';
                    break;
                case '--check':
                    $modeFromCli = 'check';
                    break;
                default:
                    if (str_starts_with($arg, '-')) {
                        throw new InvalidArgumentException("unknown option: {$arg}");
                    }
                    if ($o->target !== '') {
                        throw new InvalidArgumentException("only one TARGET may be given (got '{$o->target}' and '{$arg}')");
                    }
                    $o->target = $arg;
            }
        }

        // Naming a check in --only overrides the config file disabling it;
        // an explicit --no-<name> on the command line still wins
        if ($onlyFromCli) {
            foreach ($o->only as $name) {
                if (isset($disabledByCli[$name])) {
                    continue;
                }
                if (in_array($name, self::ECOSYSTEMS, true)) {
                    $o->ecosystems[$name] = true;
                } elseif ($o->scanner($name) === 'no') {
                    $o->setScanner($name, 'auto');
                }
            }
        }

        if (isset($pushFlags['--pr'], $pushFlags['--push-direct'])) {
            throw new InvalidArgumentException('--pr and --push-direct cannot be combined');
        }
        if ($o->pushMode === 'direct' && $o->branch !== '') {
            throw new InvalidArgumentException('--push-direct commits to the checked-out branch, so it cannot be combined with --branch');
        }
        if (isset($pushFlags['--pr-merge']) && $o->pushMode !== 'pr') {
            throw new InvalidArgumentException('--pr-merge applies only with --pr');
        }

        // CLI option overrides the environment
        $o->mode = $modeFromCli ?? (($env['SECURITY_UPDATE_MODE'] ?? '') === 'check' ? 'check' : 'update');
        return $o;
    }

    /**
     * Whether a local check (ecosystem or scanner) should run.
     */
    public function wants(string $name): bool
    {
        if ($this->applyStored) {
            // --apply-stored replays the local database and nothing else
            return false;
        }
        if ($this->only !== [] && !in_array($name, $this->only, true)) {
            return false;
        }
        return match ($name) {
            'bandit' => $this->bandit !== 'no',
            'trivy'  => $this->trivy !== 'no',
            // grype also follows --no-trivy, as it always has
            'grype'  => $this->trivy !== 'no' && $this->grype !== 'no',
            'netsec' => $this->netsec !== 'no',
            default  => $this->ecosystems[$name] ?? false,
        };
    }

    public function githubEnabled(): bool
    {
        return $this->github !== 'no';
    }

    public function scanner(string $name): string
    {
        return match ($name) {
            'bandit' => $this->bandit,
            'trivy'  => $this->trivy,
            'gosec'  => $this->gosec,
            'grype'  => $this->grype,
            'netsec' => $this->netsec,
            default  => throw new InvalidArgumentException("unknown scanner '{$name}'"),
        };
    }

    public function setScanner(string $name, string $state): void
    {
        match ($name) {
            'bandit' => $this->bandit = $state,
            'trivy'  => $this->trivy = $state,
            'gosec'  => $this->gosec = $state,
            'grype'  => $this->grype = $state,
            'netsec' => $this->netsec = $state,
            default  => throw new InvalidArgumentException("unknown scanner '{$name}'"),
        };
    }

    public static function help(string $program): string
    {
        return <<<TXT
Usage: {$program} [OPTIONS] [TARGET]

Run security audits (and, in update mode, dependency updates) across every
language ecosystem found in a project tree, collect GitHub's view of its
vulnerabilities into a local database, apply fixes to the manifests and close
issues proven fixed.

TARGET       What to scan (default: the current directory):
               DIR                a local directory
               URL                a git URL (https://, ssh://, git@host:path,
                                  file://), cloned into a cache workdir
               OWNER/NAME         GitHub shorthand for https://github.com/OWNER/NAME
                                  (when no local directory of that name exists)

Target and state:
  --subdir PATH         Scan only PATH inside the target (relative). GitHub
                        manifest paths stay relative to the target root.
  --repo OWNER/NAME     GitHub repository for issues, Dependabot alerts,
                        advisories, settings checks and PR triage (default:
                        parsed from the target's origin remote when it is on
                        github.com; without one the GitHub steps are skipped)
  --state-dir DIR       Where the vulnerability database, reports, run lock and
                        clones live (default: \${XDG_STATE_HOME:-~/.local/state}/
                        dep-sec-patcher/<slug>, never inside the scanned tree)
  --vuln-db PATH        Local vulnerability database (default: STATE/vulns.json)
  --report-dir DIR      Where scan reports go (default: STATE/reports)
  --workdir DIR         Clone location for a remote TARGET (default: STATE/checkout)
  --config FILE         Config file (default: TARGET/.dep-sec-patcher.json if present)

Options:
  -t, --threads N       Concurrent audits (default: 1). Tools whose shared
                        cache is unsafe under concurrency still run one at a
                        time: Maven < 3.9, Yarn 1, Bundler < 2.6, sbt < 1.3, and
                        always composer, dotnet, dart, swift and mix. A warning
                        at startup names them and the version to upgrade to.
  --timeout SECONDS     Per-command timeout (default: 1800, 0 = none)
  --nvd-timeout SECONDS Timeout for the OWASP NVD database update (default: 3600)
  --nvd-api-key KEY     NVD API key for dependency-check (default: \$NVD_API_KEY,
                        also read from ~/.bashrc and friends for cron runs).
                        Without one NVD throttles hard and a full database
                        refresh can take hours.
  --only LIST           Run only these local checks (comma-separated ecosystems
                        and/or scanners: bandit, trivy, grype, netsec). GitHub
                        work is controlled separately (--no-github).
  --exclude-dir PATH    Skip a directory (a name anywhere in the tree, or a path
                        relative to the target root); repeatable
  --allow-http PATTERN  Accept plain-HTTP URLs starting with PATTERN (after
                        "http://"; * matches anything) in the netsec check; repeatable
  --strict              Exit with status 3 when any check fails
  -v, --verbose         Stream every tool's output as it runs
  --debug               Show the exact commands executed
  -V, --version         Show the version
  -h, --help            Show this help message

Scanners (default: auto = run if installed):
  --trivy / --no-trivy      Trivy filesystem scan (vulns, misconfig, secrets);
                            --no-trivy also disables grype
  --grype / --no-grype      grype scan of images built from Dockerfiles (needs docker)
  --gosec / --no-gosec      gosec Go source scanner
  --bandit / --no-bandit    bandit Python source scanner
  --netsec / --no-netsec    plain-HTTP endpoints, hardcoded credentials, old TLS
  --cvss-threshold N        Minimum CVSS score that fails a Maven audit (default: 7.0)

Ecosystem options (default: auto = run if the tool is installed):
  --no-maven  --no-gradle  --no-sbt   --no-node   --no-php    --no-python  --no-ruby
  --no-go     --no-rust    --no-dotnet --no-dart  --no-elixir --no-swift   --no-r

GitHub integration (requires the gh CLI):
  --max-issues N        Max security issues to scan (default: 300, 0 = unlimited)
  --no-github           Skip all GitHub API work
  --no-merge-prs        Do not merge Dependabot PRs or request rebases
  --no-auto-fix         Record vulnerabilities but never edit manifests
  --allow-major         Let auto-fix move a dependency to a new major version
                        when that is the only fix (default: such fixes are
                        reported and left pending)
  --apply-stored        Apply fixes from the local vuln DB only (no API calls,
                        no ecosystem audits)
  --close-fixed         Close security issues whose packages now meet the
                        required version in the manifests (verified per issue;
                        anything unverifiable is left open). Needs --update to
                        actually close; --check reports what it would close.
  --close-label NAME    Label applied before closing (default:
                        "security: verified fixed"; created if absent,
                        empty string disables labelling)
  --close-delay N       Seconds between closes (default 5). GitHub caps
                        content-creating calls at roughly 80/min and 500/hour.
  --close-limit N       Stop after N closes (default 400, 0 = unlimited) so a
                        run stays inside the hourly quota; re-run to continue.

Mode options:
  --update              Update dependencies and apply fixes, then audit (default)
  --check               Audit only: no dependency updates, PR merges or manifest
                        edits; anything a tool writes into the tree is undone
  --push                Update mode: commit the changes to a new branch and push
                        it to origin (needs a git TARGET that was clean at start)
  --pr                  Like --push, then open a pull request from the branch
                        into the branch the tree started on, merge it and
                        delete the branch (implies --push)
  --pr-merge METHOD     How --pr merges: squash (default), merge, rebase, or
                        none to leave the pull request open for review
  --push-direct         Like --push, but commit straight onto the checked-out
                        branch (master/main/...) and push it; no side branch
  --branch NAME         Branch for --push/--pr (default: dep-sec-patcher/<timestamp>)

Environment:
  SECURITY_UPDATE_MODE=update|check   default mode (CLI flag wins)
  GH_REPO / VULN_DB         defaults for --repo / --vuln-db
  GH_TOKEN / GITHUB_TOKEN   GitHub token (harvested from ~/.bashrc if unset)
  NVD_API_KEY               NVD API key (harvested from ~/.bashrc if unset)
  XDG_STATE_HOME            base of the default state directory

Exit status: 0 run completed, 1 usage/config/setup error, 3 failures with
--strict, 128+N when stopped by signal N.

TXT;
    }

    public static function assertCheckName(string $name, string $where): void
    {
        if (!in_array($name, self::ECOSYSTEMS, true) && !in_array($name, self::SCANNERS, true)) {
            throw new InvalidArgumentException("{$where}: unknown check '{$name}' (known: "
                . implode(', ', array_merge(self::ECOSYSTEMS, self::SCANNERS)) . ')');
        }
    }

    public static function int(string $value, string $option, int $min): int
    {
        if (preg_match('/^\d+$/', $value) !== 1 || (int)$value < $min) {
            throw new InvalidArgumentException(sprintf(
                '%s must be %s integer, got: %s',
                $option,
                $min > 0 ? 'a positive' : 'a non-negative',
                $value
            ));
        }
        return (int)$value;
    }

    /**
     * @param list<string> $choices
     */
    public static function choice(string $value, string $option, array $choices): string
    {
        if (!in_array($value, $choices, true)) {
            throw new InvalidArgumentException("{$option} must be one of " . implode(', ', $choices) . ", got: {$value}");
        }
        return $value;
    }

    public static function cvss(string $value, string $option): string
    {
        if (!is_numeric($value) || (float)$value < 0 || (float)$value > 10) {
            throw new InvalidArgumentException("{$option} must be a number from 0 to 10, got: {$value}");
        }
        return $value;
    }

    /**
     * A path relative to the target: no leading '/', no '..' segments, no
     * trailing slash.
     */
    public static function relativePath(string $value, string $option): string
    {
        $path = trim(str_replace('\\', '/', $value));
        $path = (string)preg_replace('#/+#', '/', $path);
        $path = (string)preg_replace('#^(\./)+#', '', $path);
        $path = rtrim($path, '/');
        if ($path === '' || $path === '.' || str_starts_with($path, '/')
            || preg_match('#(^|/)\.\.(/|$)#', $path) === 1 || str_contains($path, "\0")) {
            throw new InvalidArgumentException("{$option} must be a relative path inside the target, got: {$value}");
        }
        return $path;
    }

    /**
     * An --allow-http prefix: "http://" optional, no whitespace.
     */
    public static function httpPattern(string $value, string $option): string
    {
        $pattern = (string)preg_replace('#^http://#i', '', trim($value));
        if ($pattern === '' || preg_match('/[\s"\'<>]/', $pattern) === 1) {
            throw new InvalidArgumentException("{$option} must be a URL prefix without spaces or quotes, got: {$value}");
        }
        return $pattern;
    }

    public static function branchName(string $value): string
    {
        if (preg_match('#^(?!-)(?!.*(?:\.\.|//|@\{|\.lock$|/$|\.$))[A-Za-z0-9._/-]+$#', $value) !== 1) {
            throw new InvalidArgumentException("--branch is not a valid branch name: {$value}");
        }
        return $value;
    }
}
