# dep-sec-patcher

[![CI](https://github.com/detain/dep-sec-patcher/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/detain/dep-sec-patcher/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/detain/dep-sec-patcher/branch/master/graph/badge.svg)](https://codecov.io/gh/detain/dep-sec-patcher)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/dd2e8abafb0f4799b66d4fc920396793)](https://app.codacy.com/gh/detain/dep-sec-patcher/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Coverage](https://app.codacy.com/project/badge/Coverage/dd2e8abafb0f4799b66d4fc920396793)](https://app.codacy.com/gh/detain/dep-sec-patcher/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
[![PHPStan level 8](https://img.shields.io/badge/PHPStan-level%208-brightgreen.svg)](phpstan.neon.dist)
<br>
[![Latest Version](https://img.shields.io/packagist/v/detain/dep-sec-patcher.svg)](https://packagist.org/packages/detain/dep-sec-patcher)
[![Total Downloads](https://img.shields.io/packagist/dt/detain/dep-sec-patcher.svg)](https://packagist.org/packages/detain/dep-sec-patcher)
[![PHP Version](https://img.shields.io/packagist/php-v/detain/dep-sec-patcher.svg)](https://packagist.org/packages/detain/dep-sec-patcher)
[![License](https://img.shields.io/github/license/detain/dep-sec-patcher.svg)](LICENSE)

A command-line dependency security tool for polyglot repositories. One run:

1. finds every project in a tree (Maven, Gradle, sbt, npm/yarn/pnpm, Composer,
   pip, Bundler, Go, Cargo, .NET, Dart, Elixir, Swift, R) and audits each with
   that ecosystem's own tooling;
2. runs whole-tree scanners (Trivy, bandit, grype, gosec, and a built-in check
   for plain-HTTP endpoints, hardcoded credentials and old TLS versions);
3. collects GitHub's view of the repository's vulnerabilities (Dependabot
   alerts, security advisories and Mend/WhiteSource security issues) into a
   local vulnerability database;
4. in update mode, updates dependencies, applies the recorded fixes to the
   manifests, merges or rebases dependency-bot pull requests, and closes
   security issues once the manifests prove them fixed.

It targets a local directory, a git URL, or a GitHub `OWNER/NAME`. It is a
generalised port of a tool that maintained a repository of generated API SDK
samples in dozens of languages, so it was built for trees holding many projects
in different ecosystems, and for running unattended from cron.

The tool is written in PHP (8.1+) with no runtime dependencies. It drives the
ecosystem tools you already have installed and skips the ones you don't.

## Contents

- [Check mode and update mode](#check-mode-and-update-mode)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Targets, state and scope](#targets-state-and-scope)
- [Options](#options)
- [Config file](#config-file)
- [Ecosystems](#ecosystems)
- [Scanners](#scanners)
- [GitHub integration](#github-integration)
- [NVD API key](#nvd-api-key)
- [Vulnerability database](#vulnerability-database)
- [Reports](#reports)
- [Exit status](#exit-status)
- [Concurrency](#concurrency)
- [Safety guarantees](#safety-guarantees)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Development](#development)
- [Migrating from update-samples-security](#migrating-from-update-samples-security)

## Check mode and update mode

| | `--check` | `--update` (default) |
| --- | --- | --- |
| Ecosystem audits | yes | yes, after updating dependencies |
| Dependency updates (`npm update`, `composer update`, `mvn versions:use-latest-releases`, ...) | no | yes |
| Lockfiles created only so an audit can run | created, then removed | kept |
| Anything else a tool writes into the tree | undone | build/dependency directories removed, other changes kept |
| Scanners | yes | yes |
| GitHub collection into the vuln DB | yes | yes |
| Dependency-bot PRs | listed with their merge state | merged, auto-merged or asked to rebase |
| Fixes from the vuln DB applied to manifests | counted only | applied |
| `--close-fixed` | reports what it would close | labels and closes |
| `--push` | nothing | commits the changes to a new branch and pushes it |

Check mode is safe to run against a working tree you care about: every file a
tool changes is restored and every file it creates is deleted (see
[Safety guarantees](#safety-guarantees)). Update mode changes manifests and
lockfiles in place and expects you to review `git diff`, or to use `--push`.

The default is update mode, as it was in the original tool. Set
`SECURITY_UPDATE_MODE=check` in the environment to change the default.

## Requirements

- PHP 8.1 or newer with `ctype`, `json` and `mbstring`.
  - `pcntl` is needed for parallel audits (`-t N`) and to pass Ctrl-C on to
    running tools. Without it everything runs one job at a time.
  - `posix` lets a timeout kill a command's whole process tree and reap
    daemons that tools leave behind.
- Linux, or macOS with caveats: `setsid` (util-linux) must be on `PATH` for
  process-group kills, and macOS does not ship it. Windows is not supported.
- `git` for remote targets, `--push`, and reading the `origin` remote.
- [`gh`](https://cli.github.com/), authenticated, for the GitHub steps.
- The ecosystem tools you want audited (see [Ecosystems](#ecosystems)).
  Missing tools are skipped with a `[SKIP]` line.

## Installation

Global install with Composer (puts `dep-sec-patcher` in Composer's global `bin`
directory, usually `~/.config/composer/vendor/bin` or `~/.composer/vendor/bin`):

```bash
composer global require detain/dep-sec-patcher
```

As a development dependency of a project:

```bash
composer require --dev detain/dep-sec-patcher
vendor/bin/dep-sec-patcher --check
```

From a clone (no `composer install` is needed to run it, since the tool has no
runtime dependencies; install only to run the tests):

```bash
git clone https://github.com/detain/dep-sec-patcher.git
dep-sec-patcher/bin/dep-sec-patcher --help
```

Until a release is tagged, Composer installs need the development version:
`composer global require detain/dep-sec-patcher:dev-master`.

## Quick start

```bash
# Audit the current directory without changing anything
dep-sec-patcher --check

# Audit a GitHub repository (cloned into the state directory), 4 jobs at a time
dep-sec-patcher --check -t 4 owner/name

# One or two ecosystems, with every tool's output streamed live
dep-sec-patcher --check --only node,php -v

# Only part of a monorepo
dep-sec-patcher --check --subdir services/api ~/src/monorepo

# Update dependencies and apply stored fixes, then push the result to a branch
dep-sec-patcher --update --push owner/name

# Close Mend issues whose fixes the manifests already contain
dep-sec-patcher --update --close-fixed --no-merge-prs
```

A run prints one line per audited project (`[OK]`, `[FAIL]`, `[WARN]`,
`[SKIP]`), then a summary table and the path of the JSON report:

```text
[dep-sec-patcher] [FAIL] [node] web/frontend — npm audit: 9 vulnerabilities (8 high, 1 low) (8s)
[dep-sec-patcher] [OK]   [php] api — composer audit: no known vulnerabilities (4s)
[dep-sec-patcher] [FAIL] [maven] sdk/java — dependency-check: 4 vulnerabilities in 2 dependencies, 2 with CVSS >= 7 (10s)
...
[dep-sec-patcher] Ecosystem         Status   Vulnerabilities  Outdated
[dep-sec-patcher] node              FAIL     195              0
[dep-sec-patcher] maven             FAIL     1079             0
[dep-sec-patcher] php               PASS     0                0
```

## Targets, state and scope

**TARGET** is the positional argument (default: the current directory):

| TARGET | Meaning |
| --- | --- |
| `path/to/dir` | A local directory, scanned in place. It must not itself be a symlink. |
| `https://...`, `ssh://...`, `git://...`, `file://...`, `git@host:path` | A git remote, cloned into the workdir. |
| `owner/name` | GitHub shorthand for `https://github.com/owner/name.git`, used when no local directory of that name exists. |

A remote target is cloned into `STATE/checkout` (or `--workdir`). Every run
fetches it and resets it to the tip of the remote's default branch, deleting
untracked and ignored files, so a run always starts from a pristine tree.
Local changes left in the clone by an earlier run are discarded, with a
warning. The tool only resets a directory it cloned itself (it leaves a marker
in `.git/`), and refuses to reuse anything else. Check mode leaves the clone
pristine. Update mode leaves its changes there for you to inspect, or commits
and pushes them to a new branch with `--push`. Private repositories need git
credentials that work without a prompt: an SSH key, or `gh auth setup-git` for
HTTPS. Git runs with `GIT_TERMINAL_PROMPT=0` and SSH in batch mode, so a missing
credential fails instead of hanging.

**`--subdir PATH`** limits the scan to part of the target. Paths in the output,
in the reports and in the vulnerability database stay relative to the target
root, which is how GitHub reports manifest paths. Auto-fix and close-fixed only
act on manifests inside the subdirectory, and records for other manifests stay
pending. Pass the repository root as TARGET and narrow it with `--subdir`; the
tool warns when a TARGET lies inside a git work tree without being its root,
because GitHub's manifest paths would not line up.

**`--repo OWNER/NAME`** names the GitHub repository for the GitHub steps. By
default it is parsed from the target: the URL of a remote target, or the
`origin` remote of a local checkout (`git@github.com:o/n.git`,
`https://github.com/o/n`, `ssh://git@github.com/o/n` and so on). When the target
is not on github.com and no `--repo` is given, every GitHub step prints a
`[SKIP]` line saying why. GitHub Enterprise hosts are not detected
automatically; pass `--repo` and configure `gh` for the host.

**State** lives outside the scanned tree, by default in
`${XDG_STATE_HOME:-~/.local/state}/dep-sec-patcher/<slug>/`:

```text
<slug>/
├── vulns.json        vulnerability database (--vuln-db)
├── reports/          scan reports (--report-dir)
├── run.lock          one run per target at a time
└── checkout/         clone of a remote target (--workdir)
```

The slug is `owner__name` (lowercased) when there is a GitHub repository, and
`<directory-name>-<8 hex chars>` otherwise, where the hash comes from the
target's realpath or from its normalised URL. `--state-dir` moves the whole
directory, and `--vuln-db`, `--report-dir` and `--workdir` move individual
parts. A state directory, database or report directory inside the scanned tree
is refused: it would be audited, wiped by check mode, or committed.

## Options

`--opt value` and `--opt=value` are equivalent.

**Target and state**

| Option | Default | Description |
| --- | --- | --- |
| `TARGET` | current directory | Directory, git URL or `OWNER/NAME` to scan |
| `--subdir PATH` | | Scan only `PATH` inside the target |
| `--repo OWNER/NAME` | from the target's `origin` / URL | GitHub repository for the GitHub steps (env `GH_REPO`) |
| `--state-dir DIR` | `$XDG_STATE_HOME/dep-sec-patcher/<slug>` | Base for the database, reports, lock and clone |
| `--vuln-db PATH` | `STATE/vulns.json` | Vulnerability database (env `VULN_DB`) |
| `--report-dir DIR` | `STATE/reports` | Where reports are written |
| `--workdir DIR` | `STATE/checkout` | Clone location for a remote target |
| `--config FILE` | `TARGET/.dep-sec-patcher.json` if present | Config file |

**Mode**

| Option | Description |
| --- | --- |
| `--update` | Update dependencies, apply fixes, merge bot PRs, then audit (default; env `SECURITY_UPDATE_MODE`) |
| `--check` | Audit only; anything a tool writes into the tree is undone |
| `--push` | Update mode: commit the changes to a new branch and push it to `origin` (the tree must have been clean at the start) |
| `--branch NAME` | Branch for `--push` (default `dep-sec-patcher/<UTC timestamp>`) |
| `--apply-stored` | Only apply fixes recorded in the vuln DB: no audits, scanners or API collection |
| `--strict` | Exit with status 3 when any check fails |

**Running**

| Option | Default | Description |
| --- | --- | --- |
| `-t, --threads N` | 1 | Concurrent audits (see [Concurrency](#concurrency)) |
| `--timeout SECONDS` | 1800 | Per-command timeout, `0` = none |
| `--nvd-timeout SECONDS` | 3600 | Timeout for the NVD database update |
| `--nvd-api-key KEY` | `$NVD_API_KEY` | NVD API key for OWASP dependency-check |
| `--only LIST` | | Run only these local checks: ecosystem names and/or `bandit`, `trivy`, `grype`, `netsec` |
| `--exclude-dir PATH` | | Skip a directory: a bare name anywhere in the tree, or a path relative to the target (repeatable) |
| `--allow-http PATTERN` | | Accept plain-HTTP URLs starting with `PATTERN` in the netsec check (repeatable; `*` matches anything) |
| `-v, --verbose` | | Stream every tool's output as it runs |
| `--debug` | | Print each command before running it, and what check mode undid |
| `-V, --version` | | Print the version |
| `-h, --help` | | Print the help |

**Ecosystems and scanners**

| Option | Description |
| --- | --- |
| `--no-maven` `--no-gradle` `--no-sbt` `--no-node` `--no-php` `--no-python` `--no-ruby` `--no-go` `--no-rust` `--no-dotnet` `--no-dart` `--no-elixir` `--no-swift` `--no-r` | Skip an ecosystem |
| `--trivy` / `--no-trivy` | Trivy filesystem scan; `--no-trivy` also disables grype |
| `--grype` / `--no-grype` | grype scan of images built from Dockerfiles |
| `--gosec` / `--no-gosec` | gosec, run inside the Go audit |
| `--bandit` / `--no-bandit` | bandit Python source scan |
| `--netsec` / `--no-netsec` | Built-in plain-HTTP / credential / TLS check |
| `--cvss-threshold N` | Minimum CVSS score that fails a Maven audit (default 7.0) |

Every check is "auto" by default: it runs when its tool is installed and
something in the tree needs it.

**GitHub**

| Option | Default | Description |
| --- | --- | --- |
| `--max-issues N` | 300 | Maximum open issues to read (`0` = unlimited) |
| `--no-github` | | Skip every GitHub step |
| `--no-merge-prs` | | Do not merge, auto-merge or ask for rebases on bot PRs |
| `--no-auto-fix` | | Record vulnerabilities but never edit manifests |
| `--close-fixed` | | Close security issues whose fixes the manifests now declare |
| `--close-label NAME` | `security: verified fixed` | Label added before closing (created if missing; empty disables) |
| `--close-delay N` | 5 | Seconds between closes |
| `--close-limit N` | 400 | Stop after N closes (`0` = unlimited) |

**Environment**

| Variable | Use |
| --- | --- |
| `SECURITY_UPDATE_MODE` | `check` or `update`: the default mode |
| `GH_REPO`, `VULN_DB` | Defaults for `--repo` and `--vuln-db` |
| `GH_TOKEN`, `GITHUB_TOKEN` | GitHub token for `gh` (also read from shell rc files, see below) |
| `NVD_API_KEY` | NVD API key (also read from shell rc files) |
| `XDG_STATE_HOME` | Base of the default state directory |
| `HOME`, `GOPATH`, `GOBIN`, `CARGO_HOME`, `DOTNET_CLI_HOME`, `SDKMAN_DIR` | Used to find per-user tool installs |

Cron and systemd start with a minimal `PATH`, so the tool puts the usual
per-user tool locations in front of it when they exist: `/usr/local/go/bin`,
`$GOBIN`, `$GOPATH/bin` (or `~/go/bin`), `$CARGO_HOME/bin` (or `~/.cargo/bin`),
`~/.dotnet/tools`, and every SDKMAN candidate's `current/bin`.

## Config file

Option defaults can live in `.dep-sec-patcher.json` in the target root, or in
any file passed with `--config`. Precedence, lowest first: built-in defaults,
the config file, the environment, the command line. On the command line
`--only` replaces the config's list and re-enables anything it names that the
config disabled, and `--exclude-dir` / `--allow-http` add to the config's lists.

```json
{
  "$schema": "ignored: keys starting with $ or _ are comments",
  "ecosystems": { "r": false, "swift": false },
  "scanners": { "trivy": true, "grype": false, "netsec": true },
  "only": ["maven", "node", "php", "netsec"],
  "threads": 4,
  "timeout": 1800,
  "nvd-timeout": 3600,
  "cvss-threshold": 7.0,
  "max-issues": 300,
  "close-label": "security: verified fixed",
  "close-delay": 5,
  "close-limit": 400,
  "allow-http": ["intranet.example.com/", "*.corp.example/"],
  "exclude-dirs": ["docs", "test/fixtures"]
}
```

| Key | Type | CLI equivalent |
| --- | --- | --- |
| `ecosystems` | object, ecosystem name to `true`/`false` | `--no-<name>` |
| `scanners` | object: `bandit`, `trivy`, `gosec`, `grype`, `netsec` to `true`/`false` | `--<name>` / `--no-<name>` |
| `only` | list of check names | `--only` |
| `threads` | integer >= 1 | `-t` |
| `timeout`, `nvd-timeout`, `max-issues`, `close-delay`, `close-limit` | integer >= 0 | same name |
| `cvss-threshold` | number 0 to 10 | `--cvss-threshold` |
| `close-label` | string | `--close-label` |
| `allow-http` | list of URL prefixes | `--allow-http` |
| `exclude-dirs` | list of directory names or relative paths | `--exclude-dir` |

Unknown keys, unknown ecosystem or scanner names, and values of the wrong type
are errors (exit status 1) that name the file and key, so a typo cannot fall
back silently to a default. For a remote target the file is read from the clone.
Paths such as the state directory cannot be set from the config file, because
it belongs to the scanned tree.

## Ecosystems

Each ecosystem finds its targets by manifest name in the tree. Dependency and
build directories (`node_modules`, `vendor`, `target`, `.git`, `.venv`,
`_build`, ...) are never descended into, symlinked directories are not
followed, and `--exclude-dir` adds more.

| Name | Detected by | Tools | Check mode runs | Update mode changes | Concurrent runs |
| --- | --- | --- | --- | --- | --- |
| `maven` | `pom.xml` | `mvn`, OWASP `dependency-check-maven` | `dependency-check:check` against the database refreshed once per run (`autoUpdate=false`) | `versions:use-latest-releases` (falling back to `use-latest-versions`) rewrites `pom.xml` | Maven >= 3.9.0, with resolver file locks; serial below |
| `gradle` | `gradlew` | `gradlew` (or `gradle`) | `dependencyUpdates` if the ben-manes versions plugin is applied, else SKIP | resolves dependencies (informational) | yes |
| `sbt` | `build.sbt` | `sbt` + `sbt-updates` plugin | `dependencyUpdates` if the plugin is configured, else SKIP | `dependencyUpdates` (informational) | sbt >= 1.3.0 (Coursier); serial below |
| `node` | `package.json` | `npm`, or `yarn`/`pnpm` when their lockfile is present | lockfile-only resolve, then `npm audit --omit=dev` / `yarn audit` / `yarn npm audit` / `pnpm audit` | `npm update` and `npm audit fix --force` (lockfile only, scripts disabled), `yarn upgrade` (Yarn 1), `pnpm up --latest` | npm, pnpm: yes; yarn >= 2.0.0, serial for Yarn 1 |
| `php` | `composer.json` | `composer` | `composer update --no-install` if there is no lockfile, then `composer audit --locked` | `composer update -W --no-install` rewrites `composer.lock` | always serial |
| `python` | `requirements.txt` (`pyproject.toml`/`Pipfile` directories are found but SKIP) | `pip-audit`, or `safety` | `pip-audit -r requirements.txt` | `pip-audit --fix` rewrites `requirements.txt` | yes |
| `ruby` | `Gemfile` | `bundle`, `bundle-audit` (installed with `gem` if missing) | `bundle lock` if there is no lockfile, then `bundle-audit check` | `bundle lock --update` rewrites `Gemfile.lock` (no gems installed) | Bundler >= 2.6.0; serial below |
| `go` | `go.mod` | `go`, `govulncheck`, optional `gosec` | `go list -m -u all` (outdated count), `govulncheck` (reachable code, falling back to `-scan module` when the package does not build) | `go get -u ./...` and `go mod tidy` | yes |
| `rust` | `Cargo.toml` | `cargo`, `cargo-audit` | `cargo generate-lockfile` if needed, then `cargo audit` | `cargo update` rewrites `Cargo.lock` | yes |
| `dotnet` | `*.sln`, `*.csproj`, `*.fsproj` (a solution owns the projects it references) | `dotnet`, `dotnet-outdated` | `dotnet restore`, `dotnet list package --vulnerable --include-transitive` | `dotnet-outdated -u:Auto` rewrites project files | always serial |
| `dart` | `pubspec.yaml` | `dart` | `dart pub outdated` (informational, no advisory database) | `dart pub upgrade --major-versions` | always serial |
| `elixir` | `mix.exs` | `mix` | `mix deps.get`, then `mix hex.audit` (retired packages) | `mix deps.update --all`, then `mix hex.audit` | always serial |
| `swift` | `Package.swift` | `swift` | `swift package show-dependencies` (informational) | `swift package update` | always serial |
| `r` | `DESCRIPTION`, `renv.lock` | `Rscript` | `old.packages()` on the host R library (informational) | same; nothing is written | yes |

A FAIL result means vulnerabilities at or above the threshold were found:
critical/high/unrated findings for most tools, and CVSS >= `--cvss-threshold`
for Maven. Lower findings are WARN. A tool that crashes or times out is shown as
`[FAIL] ... [tool error]` with the end of its output. Go standard-library
findings belong to the local Go toolchain and are reported as a note, without
failing the project.

## Scanners

| Scanner | Runs | Result |
| --- | --- | --- |
| `trivy` | `trivy fs --scanners vuln,misconfig,secret` over the scanned tree, once. If Maven Central rate-limits its POM lookups (HTTP 429), a `Retry-After` of up to 5 minutes is waited out and the scan retried once; a longer block, or a second 429, reruns it with `--offline-scan` | Secrets or high/critical vulnerabilities fail; misconfigurations warn. An offline fallback adds "offline scan" to the result. Report `trivy/_root/trivy-fs-results.json`. |
| `bandit` | `bandit -r .` once, when there are `.py` files | HIGH findings fail, others warn. Report `bandit/_root/bandit-results.json`. |
| `grype` | Builds an image from each of up to 5 `Dockerfile`s and scans it; needs `grype` and `docker`; images are removed afterwards | By severity. Skipped silently when either tool is missing. |
| `gosec` | Inside each Go audit | Finding count as a note; report under `gosec/`. |
| `netsec` | Built in, over every indexed file | See below. |

`netsec` looks for:

- plain `http://` URLs in `.yaml`, `.yml`, `.json` and `.toml` files whose path
  does not contain `example` or `test` (WARN). Identifier-like URLs are allowed:
  `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`, `www.w3.org/`,
  `json-schema.org/`, `www.apache.org/licenses`, `opensource.org/`,
  `maven.apache.org/`, `xmlns.*`, `schemas.*`, `purl.org/`, `example.com`,
  `example.org`, `example.net` and `petstore.swagger.io`. Extend the list with
  `--allow-http` or the config's `allow-http`;
- hardcoded `password`, `api_key`, `secret`, `token`, AWS access keys and
  private keys, ignoring placeholders such as `password_example` or
  `YOUR_API_KEY` (FAIL);
- `TLSv1.0`, `TLSv1.1` or `sslversion` in config and `.properties` files (WARN).

Lockfiles are not scanned.

## GitHub integration

All GitHub work goes through the [`gh`](https://cli.github.com/) CLI. Each call
has a timeout, and failures are reported as "could not list ..." rather than
read as "nothing found".

**Authentication.** When `gh auth status` fails, the tool looks for
`export GH_TOKEN=...` or `export GITHUB_TOKEN=...` in `~/.bashrc`,
`~/.bash_profile`, `~/.profile` and `~/.zshrc`, takes the last assignment, and
retries. Cron jobs therefore work without sourcing the rc file. The same
harvesting finds `NVD_API_KEY`. Without `gh`, or without a working token, the
GitHub steps print `[SKIP]` or `[WARN]` lines and the local audits still run.

**Repository.** `--repo`, otherwise the target's GitHub origin (see
[Targets](#targets-state-and-scope)), canonicalised through `gh api repos/...`
so that a renamed repository resolves to its current name.

**Collection** (every mode except `--apply-stored`):

- *Dependabot alerts*: `repos/{repo}/dependabot/alerts?state=open`, all pages.
  This needs a token that can read security alerts (repository admin, or the
  `security_events` scope).
- *Repository security advisories*: published, draft and triage advisories. A
  404 counts as none.
- *Security issues*: up to `--max-issues` open issues. Bodies in the Mend Bolt
  / WhiteSource format ("Path to dependency file", "Fix Resolution",
  "Direct dependency fix Resolution", and the bare coordinate lists) become one
  remediation record per package, fix version and manifest. Listing is retried
  three times before the issue set is given up for the run.

The records are merged into the [vulnerability database](#vulnerability-database).

**Repository settings.** Reports whether secret scanning, Dependabot security
updates and code-scanning default setup are enabled. Secret scanning off is a
FAIL line.

**Dependency-bot PR triage.** Only non-draft PRs whose author matches
`dependabot`, `renovate`, `mend` or `snyk` are considered; a human's PR is never
touched. GitHub computes mergeability lazily, so it is polled for up to 12
seconds. Check mode only lists each PR with its state. In update mode:

- mergeable PRs are squash-merged (branch deleted), or set to auto-merge when
  required checks are still pending;
- a PR that is behind its base, or has conflicts, gets one `@dependabot rebase`
  or `@renovatebot rebase` comment. The comment carries a hidden
  `<!-- security-update:rebase -->` marker, and no new request is posted until
  the branch has moved;
- conflicting PRs from bots without a rebase command get manual rebase
  instructions;
- PRs the bot refuses to rebase, and PRs blocked by branch protection, are
  reported for a human.

**Auto-fix.** Pending records are grouped per manifest and package. For each
group:

- a lockfile path is redirected to its source manifest (`package-lock.json` to
  `package.json`, `composer.lock` to `composer.json`, `packages.lock.json` to the
  `.csproj`, and so on);
- the version the manifest declares is read, and the fix is chosen per advisory:
  the lowest fix that clears the declared version on its own release line (a
  project on Tomcat 9.0 gets the 9.0 fix, not the 11.0 one), then the highest
  of those across advisories;
- nothing is written when the declared version already satisfies every
  advisory, when a Maven/NuGet range already admits a fixed version, or when
  the fix would move a declared version backwards;
- a transitive dependency is pinned instead: npm `overrides` (plus `resolutions`
  when there is a `yarn.lock`), or Maven `<dependencyManagement>`;
- JSON manifests keep their indentation and `^`/`~` range style;
- Maven `${property}` versions are bumped at the property definition.

Supported manifests: `package.json`, `composer.json`, `requirements*.txt`,
`pyproject.toml`, `Pipfile`, `pom.xml`, `build.gradle(.kts)`, `go.mod`,
`mix.exs`, `*.csproj`/`*.fsproj`/`*.nuspec`/`packages.config`, `pubspec.yaml`,
`Gemfile` and `Cargo.toml`. Each record's outcome (`applied` or `skipped`, with a
note) is written back to the database. Check mode only counts pending fixes.

**Close-fixed** (`--close-fixed`). For every open issue that has records in the
database, each package it reports is looked up in the current manifests. The
issue is closed only when every one of them declares a version at or above the
required fix, or at or above the fix on its own release line. Anything
unverifiable (manifest gone, package not declared) stays open. The issue is
labelled `--close-label` first, then closed with a comment holding the evidence
table (package, required version, declared version, manifest) and a hidden
`<!-- security-update:closed-verified -->` marker. GitHub limits
content-creating calls to roughly 80 a minute and 500 an hour, so closes are
paced (`--close-delay`), back off on "submitted too quickly" responses (1, 4,
then 9 minutes), and stop at `--close-limit`. Re-run to continue. In check mode
it lists what it would close.

## NVD API key

Maven projects are checked with OWASP dependency-check, which needs a local
copy of the NVD vulnerability database. Without an API key NVD throttles a
client to about 5 requests every 30 seconds. Once the local copy is more than
120 days old, a refresh is a full download of roughly 370,000 records, which
takes hours without a key and minutes with one. An interrupted refresh records
nothing, so the next run starts again from scratch. A keyless run therefore
looks hung.

The tool refreshes the database **once per run**, before any project is
checked, using `dependency-check:update-only` with `--nvd-timeout` (default one
hour). Every project is then checked with `-DautoUpdate=false`. If the refresh
fails, the checks run against the existing copy and are marked as possibly
stale.

Get a free key at <https://nvd.nist.gov/developers/request-an-api-key>, then
either `export NVD_API_KEY=...` (in `~/.bashrc` is enough for cron) or pass
`--nvd-api-key`. The key reaches Maven through the environment
(`-DnvdApiKeyEnvironmentVariable=NVD_API_KEY`), never on the command line,
where other users could read it with `ps`. The run warns when no key is set.

## Vulnerability database

`STATE/vulns.json` (or `--vuln-db`) is a JSON file:

```json
{
  "schema": 1,
  "repo": "owner/name",
  "updated": "2026-10-16T20:00:00Z",
  "vulns": {
    "npm|qs|web/package-lock.json|GHSA-xxxx-xxxx-xxxx": {
      "key": "npm|qs|web/package-lock.json|GHSA-xxxx-xxxx-xxxx",
      "source": "dependabot",
      "id": "GHSA-xxxx-xxxx-xxxx",
      "cve": "CVE-2025-0000",
      "ref": 324,
      "refs": [324],
      "ecosystem": "npm",
      "package": "qs",
      "manifest": "web/package-lock.json",
      "manifests": ["web/package-lock.json"],
      "scope": "runtime",
      "severity": "medium",
      "cvss": 5.3,
      "vulnerable_range": "< 6.15.2",
      "fixed_version": "6.15.2",
      "fix_versions": ["6.15.2"],
      "direct": true,
      "summary": "...",
      "url": "https://github.com/owner/name/security/dependabot/324",
      "first_seen": "2026-10-01T00:00:00Z",
      "last_seen": "2026-10-16T20:00:00Z",
      "state": "pending",
      "applied_at": null,
      "note": ""
    }
  }
}
```

- `source` is `dependabot`, `advisory` or `issue`. Keys are
  `ecosystem|package|manifest|id` for alerts, `ecosystem|package||ghsa` for
  advisories, and `manifest|package|id` for issues. An issue refiled for the
  same CVE, package and manifest therefore updates the existing record, and its
  number is added to `refs`.
- `state` is `pending` until auto-fix handles the record, then `applied` or
  `skipped`, with the reason in `note`. Re-collecting a record keeps
  `first_seen`, `state`, `applied_at` and `note`, and unions `refs` and
  `fix_versions`.
- Writes are atomic (a temp file in the same directory, renamed over the
  original) and the file is mode 0600. A corrupt file is reported and replaced
  with an empty database.
- `--apply-stored` replays the database without any network calls.

## Reports

Everything is written under the report directory, never into the scanned tree:

```text
reports/
├── security-scan-report.json
├── maven/<project path, / replaced by __>/dependency-check-report.json
├── gosec/<project path>/gosec-results.json
├── bandit/_root/bandit-results.json
└── trivy/_root/trivy-fs-results.json
```

`security-scan-report.json` summarises the run:

```json
{
  "tool": "dep-sec-patcher 0.1.0",
  "scan_timestamp": "2026-10-16T20:00:00Z",
  "root_dir": "/path/to/target",
  "subdir": "",
  "target": "/path/to/target",
  "github_repo": "owner/name",
  "mode": "check",
  "cvss_threshold": 7.0,
  "summary": { "pass": 26, "fail": 33, "warn": 4, "skip": 16, "info": 24 },
  "ecosystems": {
    "node": { "status": "FAIL", "vulnerabilities": 195, "outdated_packages": 0, "last_scan": "2026-10-16T20:00:00Z" }
  },
  "tools": { "trivy": { "enabled": true }, "gosec": { "enabled": true }, "bandit": { "enabled": true },
             "grype": { "enabled": true }, "netsec": { "enabled": true } }
}
```

`ecosystems` holds one row per ecosystem, scanner and GitHub step (`dependabot`,
`advisories`, `sec-issues`, `secret-scanning`, `dep-prs`, `auto-fix`,
`close-fixed`, `push`). With several projects per ecosystem the worst status
wins and the counts are added.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | The run completed, whatever it found |
| 1 | Usage, config or setup error: unknown option, invalid config file, target not found, clone failed, state inside the tree, or another run holds the lock |
| 3 | `--strict` and at least one check failed |
| 129, 130, 143 | Stopped by SIGHUP, SIGINT or SIGTERM; running tools were stopped too |

## Concurrency

`-t N` runs up to N audits at once in forked workers, and reports results as
they finish. Some package managers corrupt a shared cache when two copies run
at the same time, so each tool has a concurrency group with its own limit, and
a job only starts when its group has room. Jobs from different groups still
overlap: a serialised Maven build runs alongside npm audits.

| Tool | Concurrent from | Below that, or always |
| --- | --- | --- |
| Maven | 3.9.0 (resolver named file locks, enabled with `-Daether.syncContext.named.factory=file-lock`) | serial: no cross-process locking on `~/.m2` |
| Yarn | 2.0.0 | serial: Yarn 1 can corrupt its cache |
| Bundler | 2.6.0 | serial: unprotected compact-index cache |
| sbt | 1.3.0 (Coursier) | serial: Ivy cache |
| Composer, dotnet/NuGet, dart, swift, mix | | always serial: no concurrency-safe release known |
| npm, pnpm, Gradle, Cargo, Go, pip-audit, R | always | |

At startup a `[WARN]` line names each version-limited tool, its detected
version and the version to upgrade to, for example:

```text
[WARN] maven 3.8.7 runs one job at a time: Maven before 3.9 has no cross-process locking on the
       shared ~/.m2 repository, so concurrent runs can corrupt downloaded artifacts. Upgrade to
       maven >= 3.9.0 to run it concurrently.
[INFO] One job at a time regardless of version (no concurrency-safe release known): composer 2.10.1, dotnet 10.0.112
```

Without the `pcntl` extension, or with `-t 1`, everything runs one job at a time
in-process.

## Safety guarantees

- **Timeouts.** Every external command has a timeout (`--timeout`, and
  `--nvd-timeout` for the NVD refresh). A command that times out gets SIGTERM,
  then SIGKILL 10 seconds later.
- **Process groups.** Each command runs in its own session (`setsid`), so a
  timeout or Ctrl-C stops the whole tree it started, not just the top process.
  Anything a command leaves running in its session after it exits (MSBuild
  nodes, compiler servers) is killed. .NET runs with node reuse and build
  servers disabled.
- **No prompts.** stdin is `/dev/null`, git runs with `GIT_TERMINAL_PROMPT=0`
  and SSH in batch mode, and package managers run non-interactively. A tool
  that wants input fails; it does not wait.
- **Progress.** A command that has been silent for 60 seconds produces a
  "still running after ..." line. `-v` streams all output.
- **Workspace guard.** Before each audit the project directory's top level (and
  sbt's `project/`) is snapshotted. In check mode, afterwards, every new entry is
  deleted and every changed file restored. In update mode only new build and
  dependency directories are removed (`node_modules`, `vendor`, `target`,
  `obj`, `bin`, `build`, ...). Entries that existed before are never deleted.
  Read-only directories left by Go and Cargo are made writable before removal.
- **Third-party code.** npm runs with `--ignore-scripts` and lockfile-only;
  Composer with `--no-scripts --no-plugins --no-install`; Bundler resolves
  without installing gems.
- **Run lock.** One run per target at a time (`STATE/run.lock`, `flock`). The
  lock is opened close-on-exec, so a daemon a tool leaves behind cannot keep
  holding it.
- **Workers.** A forked worker writes its result to a temp file and then kills
  itself with SIGKILL, so shutdown handlers and destructors inherited from the
  parent never run twice. SIGINT, SIGTERM and SIGHUP are passed on to workers
  and to every running command.
- **State stays outside the tree**, a symlinked TARGET is refused, `--subdir`
  cannot escape the target, and only clones the tool made itself are ever reset.
- **Secrets.** `-D...key/token/password/secret=` arguments and URL credentials
  are masked in printed commands; the NVD key is passed through the
  environment.

## Troubleshooting

**It looks hung.** Almost always the NVD refresh without an API key: see
[NVD API key](#nvd-api-key). Run with `-v` to watch each tool's output, or
`--debug` to see each command. Every command prints a "still running" line
after a minute of silence, and nothing runs longer than `--timeout`.

**The first run is slow.** The first run fills several caches: the NVD
database, `~/.m2`, the npm, Composer, Cargo and Go module caches, and the
Trivy, govulncheck and bundler-audit advisory databases. Later runs reuse them.

**Directories that cannot be deleted** after a run was killed with SIGKILL:
Go's module cache and some Cargo outputs are read-only. Use
`chmod -R u+w DIR && rm -rf DIR`, or `go clean -modcache` for the Go cache.
Normal runs clean up after themselves.

**`another run is already in progress (pid N)`.** Another run holds this
target's lock. If that process is gone, the lock was already released when it
exited (the lock is an `flock`, not the file's existence).

**`Dependabot: could not list alerts`.** The token cannot read the repository's
security alerts. That needs admin access or the `security_events` scope.

**`gh is installed but not authenticated`.** Run `gh auth login`, or put
`export GH_TOKEN=...` in `~/.bashrc`.

**`refusing to use DIR: it exists and is not a clone made by dep-sec-patcher`.**
`--workdir` points at a directory the tool did not create. Choose an empty or
non-existent directory.

**Trivy says "offline scan".** Maven Central answered Trivy's parent-POM
lookups with `429 Too Many Requests`. It rate-limits by IP, and the Maven
audits earlier in the same run count against the limit. A block of up to five
minutes is waited out once; anything longer (Central has asked for 1600
seconds) makes Trivy rescan with `--offline-scan`. That run still reports
vulnerabilities, misconfigurations and secrets, but Java dependencies that
only resolve through a remote parent POM can be missing. The next run, once
the block has cleared, scans online again.

**A project is SKIPped.** The reason is on the line: tool not installed, no
lockfile to audit, or a Gradle/sbt plugin that is not applied. Install the tool,
or silence it with `--no-<ecosystem>` or the config file.

## Architecture

```text
bin/dep-sec-patcher        finds an autoloader (Composer's, or a built-in PSR-4 one)
src/Application            options, TARGET/state resolution, config, lock, signals
src/Options, Config        command line and config file, merged in precedence order
src/GitUrl, Target,        remote URL parsing, TARGET classification and cache clones,
    TargetResolver,        state directory derivation, tool PATH
    StatePaths, Environment
src/SecurityRun            the run: audits, scanners, GitHub, auto-fix, close-fixed, push, summary
src/ProcessRunner          timeouts, process groups, heartbeat, output capture
src/ForkPool               forked workers with per-group concurrency limits
src/WorkspaceGuard         undoes what tools write into the tree
src/ManifestIndex          one walk of the tree shared by every ecosystem
src/Auditor/*              one class per ecosystem (SimpleAuditor covers dart, elixir, swift, r)
src/Scanner/*              trivy, bandit, grype, and the netsec checks
src/GitHub, TokenHarvester gh wrapper and token discovery
src/IssueParser,           GitHub data to vulnerability records
    RecordNormalizer
src/VulnDb, FixPlanner     the database and the fix/close decisions
src/Version                GNU `sort -V` port, semver prereleases, Maven/NuGet ranges
src/ManifestEditor         reads and rewrites declared versions in 13 manifest formats
src/BranchPublisher        --push
```

The pure classes (Version, IssueParser, RecordNormalizer, VulnDb, FixPlanner,
ManifestEditor, ManifestPaths, JsonFile, GitUrl, StatePaths, Config, Options,
NetworkScanner) do no I/O and carry most of the tests. Comments that mention
"the original shell script" describe the bash implementation this replaced, and
explain why the code does what it does.

## Development

```bash
composer install
composer test            # PHPUnit
composer test:coverage   # PHPUnit with a Clover report in build/logs/clover.xml (needs pcov or xdebug)
composer analyse         # PHPStan, level 8, no baseline
```

The tests need `git` and a POSIX shell and do not use the network: a local bare
repository stands in for a remote, and the end-to-end tests run only the checks
that need no external tools. CI runs the suite and PHPStan on PHP 8.1 to 8.4,
and uploads coverage from the PHP 8.3 job.

## Migrating from update-samples-security

dep-sec-patcher replaces MyAdmin's `scripts/api/update-samples-security.sh`.
Every option keeps its name and meaning, except for the project profiles, which
were specific to that repository.

| update-samples-security | dep-sec-patcher |
| --- | --- |
| `update-samples-security.sh [DIR]` | `dep-sec-patcher [TARGET]`; TARGET may also be a git URL or `OWNER/NAME` |
| Default root: the detected profile's samples checkout | Default TARGET: the current directory |
| `--profile NAME`, `--project DIR`, `--list-profiles` | Removed. Pass the directory as TARGET, and narrow it with `--subdir` |
| `API_SAMPLES_PROFILE`, `API_SAMPLES_PROJECT` | Removed (ignored) |
| `--repo` default: origin remote, then the profile's samples repo | Origin remote only; without one the GitHub steps SKIP |
| Vuln DB default: the parent project's `logs/security-vulns.json` | `STATE/vulns.json`. Pass `--vuln-db` to keep using an existing database: the format is unchanged |
| Reports: `logs/security-reports/` beside the database | `STATE/reports/` |
| Lock: `.update-samples-security.lock` in the report directory | `STATE/run.lock` |
| Output prefix `[security-update]` | `[dep-sec-patcher]` |
| Always exits 0 after a run | Still 0; `--strict` adds status 3 on failures |
| | New: `--subdir`, `--state-dir`, `--workdir`, `--config`, `--exclude-dir`, `--allow-http`, `--grype`/`--no-grype`, `--netsec`/`--no-netsec`, `--push`, `--branch`, `--strict`, `-V` |
| PR markers `<!-- security-update:rebase -->` and `<!-- security-update:closed-verified -->` | Unchanged, so rebase requests posted by the old tool are still recognised |

The old default run is equivalent to:

```bash
dep-sec-patcher PROJECT/vendor/detain/interserver-api-samples \
    --vuln-db PROJECT/logs/security-vulns.json \
    --report-dir PROJECT/logs/security-reports
```

## License

MIT, see [LICENSE](LICENSE).
