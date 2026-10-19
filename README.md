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

**Find, fix and ship dependency security updates across every language in a repository.**

dep-sec-patcher is a command-line tool for repositories that hold projects in
many languages. Point it at a directory, a git URL or a GitHub `owner/name`,
and one run will:

1. **audit** every project it finds with that ecosystem's own tooling
   (`npm audit`, `composer audit`, `pip-audit`, `govulncheck`, `cargo audit`,
   OWASP dependency-check and more);
2. **scan** the whole tree with Trivy, bandit, grype and gosec, plus a built-in
   check for plain-HTTP endpoints, hardcoded credentials and old TLS versions;
3. **collect** GitHub's view of the repository (Dependabot alerts, security
   advisories and Mend/WhiteSource issues) into a local vulnerability database;
4. in update mode, **fix**: update dependencies, write the recorded fixes into
   the manifests, merge or rebase dependency-bot pull requests, and close
   security issues once the manifests prove them fixed;
5. optionally **ship** the result: push a branch, open and merge a pull
   request, or commit straight onto the current branch.

It is a generalised port of a tool that maintained a repository of generated
API SDK samples in dozens of languages, so it was built for trees holding many
projects in different ecosystems, and for running unattended from cron. It is
written in PHP (8.1+) with no runtime dependencies, drives the ecosystem tools
you already have installed, and skips the ones you don't.

## Contents

- [At a glance](#at-a-glance)
- [Quick start](#quick-start)
- [Check mode and update mode](#check-mode-and-update-mode)
- [Supported languages and ecosystems](#supported-languages-and-ecosystems)
  - [Manifests auto-fix can edit](#manifests-auto-fix-can-edit)
- [Tools it uses](#tools-it-uses)
  - [Core](#core)
  - [Ecosystem tools](#ecosystem-tools)
  - [Scanners and their tools](#scanners-and-their-tools)
  - [Installing the optional tools](#installing-the-optional-tools)
  - [When a tool is missing](#when-a-tool-is-missing)
- [Installation](#installation)
- [Targets, state and scope](#targets-state-and-scope)
- [Options](#options)
- [Config file](#config-file)
- [Scanners](#scanners)
- [GitHub integration](#github-integration)
  - [Publishing the changes](#publishing-the-changes)
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
- [License](#license)

## At a glance

- **One command, 14 ecosystems.** Maven, Gradle, sbt, npm / Yarn / pnpm,
  Composer, pip, Bundler, Go, Cargo, .NET, Dart, Elixir, Swift and R projects
  are found anywhere in the tree and checked with their own tools.
- **Whole-tree scanners.** Trivy (vulnerabilities, misconfigurations and
  secrets), bandit, grype on images built from your Dockerfiles, gosec, and a
  built-in network-security check.
- **GitHub's findings, kept locally.** Dependabot alerts, repository security
  advisories and Mend/WhiteSource issues are merged into a JSON database that
  remembers what has already been fixed.
- **Fixes written into the manifests.** For each package it writes the smallest
  bump that clears every advisory, staying on your current release line where a
  fix exists there. Transitive dependencies are pinned with npm `overrides` /
  `resolutions` or Maven `<dependencyManagement>`, on the line the lockfile
  holds or, without one, the line the issue found in use. A version is never
  moved backwards, and never to a new major version unless you pass
  `--allow-major`.
- **Dependency-bot PRs handled.** Dependabot, Renovate, Mend and Snyk PRs are
  merged, set to auto-merge, or asked to rebase. Only PRs from those GitHub App
  bots are touched, never a human's.
- **Issues closed on evidence.** `--close-fixed` closes a security issue only
  when every manifest (and, for npm and Composer, every lockfile) it names
  holds a fixed version, and leaves the evidence in a comment.
- **Ships the result.** `--push` pushes a branch, `--pr` opens and merges a
  pull request, and `--push-direct` commits straight onto the checked-out
  branch.
- **Tells you what to do next.** When a run finds fixes it did not apply or
  publish, it ends with a "Next steps" section that explains why and prints the
  exact command to run next.
- **Safe to point at your work.** Check mode undoes whatever tools write into
  the tree. Every command has a timeout, nothing can block on a prompt, npm and
  Composer run without third-party scripts, and state lives outside the scanned
  tree.
- **Any target.** A local directory, a git URL or `owner/name`. Narrow a
  monorepo with `--subdir`.
- **Built for cron.** It finds `GH_TOKEN` and `NVD_API_KEY` in your shell rc
  files, adds per-user tool directories to `PATH`, runs audits in parallel
  within per-tool concurrency limits, and holds a lock so two runs on one target
  never collide.

A run goes through these steps in order: **GitHub collection → auto-fix →
ecosystem updates and audits → scanners → repository settings →
dependency-bot PRs → publish → close-fixed → summary → next steps → JSON
report.** The
fixes GitHub knows about are written into the manifests first, so the
ecosystem updates regenerate the lockfiles from the fixed manifests and the
audits report the result. When the run is going to publish, the
dependency-bot PRs are handled before everything else, so the run's own
updates are made on top of whatever they merged. Ecosystems, scanners, PR
triage and auto-fix each have a `--no-...` switch, `--no-github` skips every
GitHub step, and publishing and close-fixed only run when asked for.

## Quick start

Install it with Composer. No release is tagged yet, so ask for the development
version (see [Installation](#installation) for other ways):

```bash
composer global require detain/dep-sec-patcher:dev-master
```

**Look, don't touch.** Check mode audits and reports, and leaves the tree as
it found it:

```bash
dep-sec-patcher --check                                  # the current directory
dep-sec-patcher --check -t 4 owner/name                  # a GitHub repository, cloned for the run and deleted afterwards, 4 audits at a time
dep-sec-patcher --check --only node,php -v               # only two ecosystems, streaming every tool's output
dep-sec-patcher --check --subdir services/api ~/src/monorepo   # only part of a monorepo
```

**Fix.** Update mode (the default) updates dependencies and applies the stored
fixes in place, for you to review with `git diff`:

```bash
dep-sec-patcher --update                                 # update, fix, merge bot PRs
dep-sec-patcher --update --allow-major                   # also apply fixes that need a new major version
```

**Fix and ship.** Commit the run's changes and push them:

```bash
dep-sec-patcher --update --push owner/name               # to a new branch
dep-sec-patcher --update --pr owner/name                 # to a new branch, then open a PR and squash-merge it
dep-sec-patcher --update --pr --pr-merge none owner/name # open the PR, but leave it for review
dep-sec-patcher --update --push-direct                   # straight onto the checked-out branch
dep-sec-patcher --update --pr --close-fixed owner/name   # ...then close the Mend issues the merged fixes resolve
```

**Unattended.** A nightly cron job (tokens are read from `~/.bashrc`, see
[GitHub integration](#github-integration)):

```text
30 3 * * *  $HOME/.config/composer/vendor/bin/dep-sec-patcher --update --pr -t 4 owner/name >> $HOME/dep-sec-patcher.log 2>&1
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

When the run found fixes it did not apply or publish, a **Next steps** section
follows. It says why, and prints the command to run next, built from your own
command line: the same target and options, with the mode and publishing flags
swapped for `--update --pr` (plus `--push-direct` and `--push` as
alternatives), and `--allow-major` or `--close-fixed` added when they are what
is missing. For example, after `dep-sec-patcher --check -t 4 owner/name`:

```text
[dep-sec-patcher] ── Next steps ──────────────────────────────────────────────────
[dep-sec-patcher] [INFO] the audits found 1274 vulnerabilities; update mode updates the dependencies and audits again
[dep-sec-patcher] [INFO] 12 fix(es) from GitHub's alerts and issues would be written into the manifests
[dep-sec-patcher] [INFO] 3 dependency-bot pull request(s) can be merged
[dep-sec-patcher] [INFO] 1 fix(es) or bot pull request(s) need a major version upgrade, which may break the code that uses them
[dep-sec-patcher] [INFO] security issues are recorded; --close-fixed closes the ones the manifests prove fixed
[dep-sec-patcher]   Apply the fixes, commit them, open a pull request and merge it:
[dep-sec-patcher]     dep-sec-patcher --update --pr --allow-major --close-fixed -t 4 owner/name
[dep-sec-patcher]   Or commit straight to the default branch:
[dep-sec-patcher]     dep-sec-patcher --update --push-direct --allow-major --close-fixed -t 4 owner/name
[dep-sec-patcher]   Or push a branch for review only:
[dep-sec-patcher]     dep-sec-patcher --update --push --allow-major --close-fixed -t 4 owner/name
```

It appears after a check run that found vulnerabilities, fixes it would write
or mergeable bot PRs; after an update run without a push that left
changes in the tree; when issues could be closed, fixes need a major upgrade,
or issues are recorded without `--close-fixed`. A target with no GitHub
repository or git checkout gets a plain `--update` suggestion instead. The
suggestion never repeats `--nvd-api-key`, drops `--branch` for `--push-direct`,
and drops `--pr-merge` without `--pr`.

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
| Fixes from the vuln DB applied to manifests | counted only | applied (a new major version only with `--allow-major`) |
| `--close-fixed` | reports what it would close | labels and closes |
| `--push` | nothing | commits the changes to a new branch and pushes it |
| `--pr` | nothing | as `--push`, then opens a pull request and merges it |
| `--push-direct` | nothing | commits the changes onto the checked-out branch and pushes it |

Check mode is safe to run against a working tree you care about: every file a
tool changes is restored and every file it creates is deleted, so `git status`
(ignored files included) is the same afterwards (see
[Safety guarantees](#safety-guarantees)). One exception: a build or cache
directory that already existed before the run (`obj/`, `.build/`,
`node_modules/`, ...) is left in place, and tools may refresh cache files
inside it (NuGet restore metadata, SwiftPM lock files). Update mode changes
manifests and lockfiles in place and expects you to review `git diff`, or to
publish them with `--push`, `--pr` or `--push-direct`.

The default is update mode, as it was in the original tool. Set
`SECURITY_UPDATE_MODE=check` in the environment to change the default; `--check`
or `--update` on the command line always wins.

## Supported languages and ecosystems

Each ecosystem finds its projects by manifest name anywhere in the tree.
Dependency and build directories (`node_modules`, `vendor`, `target`, `.git`,
`.venv`, `_build`, ...) are never descended into, symlinked directories are not
followed, and `--exclude-dir` adds more. The **Name** column is what
`--no-<name>`, `--only` and the config file's `ecosystems` key use.

| Language | Name | Detected by | Vulnerability audit | Update mode |
| --- | --- | --- | --- | --- |
| Java | `maven` | `pom.xml` | OWASP dependency-check (NVD); fails at CVSS >= `--cvss-threshold` | `versions:use-latest-releases` and `versions:update-properties` rewrite `pom.xml` |
| Java, Kotlin | `gradle` | `gradlew` | none: outdated report only (`dependencyUpdates`) | resolves dependencies (informational) |
| Scala | `sbt` | `build.sbt` | none: outdated report only (`dependencyUpdates`) | `dependencyUpdates` (informational) |
| JavaScript, TypeScript | `node` | `package.json` | `npm audit`, `yarn audit` / `yarn npm audit`, or `pnpm audit` | `npm update` + `npm audit fix` (`--force` with `--allow-major`), `yarn upgrade` (Yarn 1), `pnpm up` (`--latest` with `--allow-major`) |
| PHP | `php` | `composer.json` | `composer audit` (also lists abandoned packages) | `composer update -W` rewrites `composer.lock` |
| Python | `python` | `requirements.txt` | `pip-audit`, or `safety` | `pip-audit --fix` rewrites `requirements.txt` |
| Ruby | `ruby` | `Gemfile` | `bundle-audit` (bundler-audit) | `bundle lock --update` rewrites `Gemfile.lock` |
| Go | `go` | `go.mod` | `govulncheck` (plus a `gosec` source scan) | `go get -u ./...` and `go mod tidy` |
| Rust | `rust` | `Cargo.toml` | `cargo audit` | `cargo update` rewrites `Cargo.lock` |
| C#, F# (.NET) | `dotnet` | `*.sln`, `*.csproj`, `*.fsproj` | `dotnet list package --vulnerable --include-transitive` | `dotnet-outdated -u:Auto` rewrites project files, then each package still vulnerable goes to the newest release on its major line (any line with `--allow-major`) via `dotnet add package`, a transitive one pinned by a direct reference |
| Dart | `dart` | `pubspec.yaml` | none: outdated report only (`dart pub outdated`) | `dart pub upgrade` (`--major-versions` with `--allow-major`) |
| Elixir | `elixir` | `mix.exs` | `mix hex.audit` (retired packages) | `mix deps.update --all` |
| Swift | `swift` | `Package.swift` | none: dependency listing only | `swift package update` |
| R | `r` | `DESCRIPTION`, `renv.lock` | none: lists outdated packages in the host R library | nothing written |

Notes:

- **Node** uses Yarn for a project with a `yarn.lock` and pnpm for one with a
  `pnpm-lock.yaml` when that tool is installed, and npm otherwise. Yarn 2+ is
  audited but not upgraded.
- **Python** directories that only have a `pyproject.toml` or `Pipfile` are
  found but skipped (`no requirements.txt to audit`). Auto-fix still edits
  those files.
- **Gradle** in check mode needs the ben-manes gradle-versions-plugin for its
  report; without it the project is SKIPped with that reason. **sbt** needs
  sbt-updates: when neither the project nor the global plugins have it, the
  tool adds it for the one command (sbt 1.4 and later, sbt 2 included), and
  only an older sbt is SKIPped, with the line to add. See
  [Ecosystem tools](#ecosystem-tools).
- **Gradle** runs on Java only up to the release its version predates (Gradle
  7.0 up to Java 16, 8.5 up to 21; on a newer JVM a wrapper fails with
  "Unsupported class file major version"). Such a wrapper runs on the newest
  JDK under `/usr/lib/jvm` it supports, with a note, or is SKIPped naming the
  Java it needs. A failed Gradle build shows its "What went wrong" section
  rather than the end of a stack trace.
- Trivy and the GitHub collection run whatever the per-ecosystem audits find
  or skip.

A FAIL result means vulnerabilities at or above the threshold were found:
critical, high or unrated findings for most tools (`pip-audit` reports no
severity, so each of its findings counts), and CVSS >= `--cvss-threshold` for
Maven. Lower findings are WARN, and so is a failed step in an ecosystem that has
no advisory database. A tool that crashes or times out is shown as
`[FAIL] ... [tool error]` with the end of its output. Go standard-library
findings belong to the local Go toolchain and are reported as a note, without
failing the project.

<details>
<summary><b>Per-ecosystem details: the exact commands, and concurrency</b></summary>

<br>

| Name | Tools | Check mode runs | Update mode changes | Concurrent runs |
| --- | --- | --- | --- | --- |
| `maven` | `mvn`, OWASP `dependency-check-maven` (`--enable-native-access=ALL-UNNAMED` is added to `MAVEN_OPTS` when mvn runs on Java 17+) | `dependency-check:check` against the database refreshed once per run (`autoUpdate=false`) | `versions:use-latest-releases` (falling back to `use-latest-versions` only if that fails), then `versions:update-properties` for versions taken from `<properties>`, rewrite `pom.xml`; both with `-DallowMajorUpdates=false` unless `--allow-major`, and both pass over milestones, release candidates, alphas, betas and other prereleases (`-Dmaven.version.ignore`), which the plugin otherwise counts as releases | Maven >= 3.9.0, with resolver file locks; serial below |
| `gradle` | the project's `gradlew`, run with `sh` (or `bash` when its first line names bash) | `dependencyUpdates` if the ben-manes versions plugin is applied, else SKIP | `dependencies` (resolves; informational) | yes |
| `sbt` | `sbt` + `sbt-updates` plugin, always in the foreground (`--server` on sbt 2, `SBT_NATIVE_CLIENT=false`), so no sbt server is left running | `dependencyUpdates`; without the plugin in `project/*.sbt` or the global plugins, it is added with `--addPluginSbtFile` (sbt 1.4+), else SKIP. sbt before 1.6 on Java 18 to 23 gets `-Djava.security.manager=allow`, without which it cannot start. A build without `project/build.properties` runs on sbt 1.10.11 under sbt 2's runner, since sbt 2 cannot load an sbt 1 build definition, and `-Dsbt.skip.version.write=true` keeps sbt from writing a `build.properties` into it | `dependencyUpdates` (informational) | sbt >= 1.3.0 (Coursier); serial below |
| `node` | `npm`, or `yarn` / `pnpm` when their lockfile is present | npm: `npm install --package-lock-only`, then `npm audit --omit=dev`; Yarn 1: `yarn audit`; Yarn 2+: `yarn npm audit --all`; pnpm: `pnpm audit` | `npm update` and `npm audit fix` (lockfile only, scripts disabled; `--force`, which makes major upgrades, only with `--allow-major`; when vulnerabilities remain, a note says how many need a major upgrade and how many have no fix), Yarn 1: `yarn install` then `yarn upgrade` (scripts disabled), `pnpm up` (scripts disabled; `--latest` only with `--allow-major`). When `package.json` itself has conflicting peer dependencies (npm `ERESOLVE`), every npm step is retried with `--legacy-peer-deps` and a note says so | npm, pnpm: yes; yarn >= 2.0.0, serial for Yarn 1 |
| `php` | `composer` | `composer update -W --no-install` if there is no lockfile, then `composer audit --locked`; a lockfile created for the audit is deleted afterwards | `composer update -W --no-install` rewrites `composer.lock`, or creates one for the audit and deletes it afterwards when the project had none (so `--push` never commits it). If Composer refuses because only versions with security advisories meet a requirement, the update is retried with its advisory blocking off, and a note says so | always serial |
| `python` | `python3`, plus `pip-audit` or `safety` | `pip-audit -r requirements.txt` (or `safety check -r requirements.txt`) | `pip-audit --fix` rewrites `requirements.txt` (`safety` changes nothing) | yes |
| `ruby` | `bundle`, `bundle-audit` (installed with `gem` if missing) | advisory database refreshed once, `bundle lock` if there is no lockfile, then `bundle-audit check` | `bundle lock --update` rewrites `Gemfile.lock` (no gems installed) | Bundler >= 2.6.0; serial below |
| `go` | `go`, `govulncheck`, optional `gosec` | `go list -m -u all` (outdated count), `govulncheck` (reachable code, falling back to `-scan module` when the package does not build) | `go get -u ./...` and `go mod tidy` | yes |
| `rust` | `cargo`, `cargo-audit` | `cargo generate-lockfile` if needed, then `cargo audit` | `cargo update` rewrites `Cargo.lock` | yes |
| `dotnet` | `dotnet`, `dotnet-outdated` | `dotnet restore`, `dotnet list package --vulnerable --include-transitive` (a solution owns the projects it references, so they are audited once) | `dotnet-outdated -u:Auto` rewrites project files; packages still listed as vulnerable are moved with `dotnet add package --version` (newest release, major line kept unless `--allow-major`; transitive ones get a direct PackageReference) and the audit reruns | always serial |
| `dart` | `dart` | `dart pub outdated` (informational, no advisory database) | `dart pub upgrade`, with `--major-versions` only under `--allow-major` | always serial |
| `elixir` | `mix` (Hex set up once with `mix local.hex --force`) | `mix deps.get`, then `mix hex.audit` (retired packages) | `mix deps.update --all`, then `mix hex.audit` | always serial |
| `swift` | `swift` | `swift package show-dependencies` (informational) | `swift package update` | always serial |
| `r` | `Rscript` | `old.packages()` on the host R library (informational) | same; nothing is written | yes |

</details>

### Manifests auto-fix can edit

Auto-fix writes the fixes recorded in the [vulnerability database](#vulnerability-database)
into these files (see [GitHub integration](#github-integration) for how a
version is chosen):

| Manifest | Ecosystem | Version written as |
| --- | --- | --- |
| `package.json` | npm | a declared dependency (including `optionalDependencies`) keeps its `^` / `~` / `>=` prefix; `*`, `x`, `latest` or an empty spec becomes `>=X.Y.Z`; unions (`\|\|`), git / file / alias specs and dist-tags are left alone. A transitive dependency gets a caret pin `^X.Y.Z`: in `resolutions` when there is a `yarn.lock`, and in `overrides` when there is a `package-lock.json` / `npm-shrinkwrap.json` or no `yarn.lock` |
| `composer.json` | Composer | `^X.Y.Z` in `require` or `require-dev`; `*` becomes `>=X.Y.Z`; unions and `dev-` branches are left alone |
| `requirements*.txt`, `constraints*.txt` | pip | `name==X.Y.Z`, keeping extras, environment markers and comments. The name must match whole (`boto` is not `boto3`); a file using `--hash` is left alone |
| `pyproject.toml`, `Pipfile` | pip | the existing operator kept (`>=` when there is none) |
| `pom.xml` | Maven | the literal `<version>`, or the `${property}` it refers to; a transitive dependency goes into `<dependencyManagement>` |
| `build.gradle`, `build.gradle.kts` | Gradle | `"group:artifact:X.Y.Z"` string coordinates |
| `go.mod` | Go | `vX.Y.Z` on `require` lines for the exact module path; `exclude` and `replace` lines are untouched and `+incompatible` is kept |
| `mix.exs` | Hex | `~> X.Y.Z` |
| `*.csproj`, `*.fsproj`, `*.nuspec`, `packages.config` | NuGet | the `Version` / `version` attribute |
| `pubspec.yaml` | pub | `^X.Y.Z`, for first-level entries under `dependencies`, `dev_dependencies` and `dependency_overrides` |
| `Gemfile` | RubyGems | `~> X.Y.Z` |
| `Cargo.toml` | Cargo | `"X.Y.Z"` or `{ version = "X.Y.Z" }` |

A fix reported against a lockfile is redirected to its source manifest:
`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml` to
`package.json`, `composer.lock` to `composer.json`, `Gemfile.lock` to `Gemfile`,
`Cargo.lock` to `Cargo.toml`, `go.sum` to `go.mod`, `mix.lock` to `mix.exs`,
`pubspec.lock` to `pubspec.yaml`, `Pipfile.lock` to `Pipfile`, `poetry.lock` to
`pyproject.toml`, and `packages.lock.json` to the `.csproj` / `.fsproj` beside
it. JSON manifests keep their indentation.

The editor is chosen by the manifest's file name, so GitHub's ecosystem names
do not matter (it reports Cargo as `rust`, Mix as `erlang`, and Gradle builds as
`maven`). Package names and versions that do not look like names and versions
are never written, and a manifest path is resolved (symlinks included) and must
lie inside the tree before it is edited. A fix the editor cannot make is
reported as "cannot edit" and stays `pending`.

**Major versions.** By default auto-fix does not move a declared dependency, or
a transitive one whose version in use is known, to a new major version. Below
1.0 a new minor version counts as major, the way npm's caret treats it (`0.8.x`
to `0.9.0`). Such a fix prints a `[WARN]`, stays `pending` with a note, and is
applied by a later run with `--allow-major` (or `"allow-major": true` in the
config file).

**Transitive dependencies.** For npm the lockfile is read first: `yarn.lock`
(v1 and Berry), `package-lock.json` / `npm-shrinkwrap.json` (v1 to v3) or
`pnpm-lock.yaml`. An npm package the lockfile holds no copy of is not pinned
(nothing installs it). Without a lockfile, for npm and Maven, the versions the
security issue found in use stand in for it (Mend names the path of each copy,
such as `~/.m2/repository/io/netty/netty-codec-http2/4.1.76.Final/`). When
every copy already clears the advisories, the record is marked applied without
a pin. When the copies span several major lines, nothing is pinned and the
record stays `pending` ("pin it by hand"). Otherwise the pin is chosen on the
line in use, from the newest copy, so it moves none of them back: netty 4.1.76
gets 4.1.135.Final, not 4.2.15.Final. With no version in use known, the pin is
the highest fix any advisory suggested for that package.

## Tools it uses

dep-sec-patcher bundles no scanners: it drives the tools installed on the
host. Every check is *auto* by default, which means it runs when its tool is on
`PATH` and something in the tree needs it. A missing tool never stops the run;
see [When a tool is missing](#when-a-tool-is-missing).

### Core

| Tool | Needed for | Without it |
| --- | --- | --- |
| PHP 8.1+ with `ctype`, `json` and `mbstring` | running dep-sec-patcher | nothing runs |
| PHP `pcntl` extension (optional) | parallel audits (`-t N`), and passing Ctrl-C on to running tools | everything runs one job at a time |
| PHP `posix` extension and `setsid` from util-linux (optional) | running each command in its own session, so a timeout or Ctrl-C stops the whole process tree and leftover daemons are reaped | a timeout can only signal the command's own process, and without `posix` not even that |
| `git` | remote targets, reading the `origin` remote, `--push` / `--pr` / `--push-direct` | remote targets and publishing fail; a local target needs `--repo` for the GitHub steps |
| [`gh`](https://cli.github.com/), authenticated | every GitHub step, and `--pr` | the GitHub steps print `[SKIP]` or `[WARN]`; the local audits still run |

Linux is supported, and macOS with caveats: `setsid` (util-linux) must be on
`PATH` for process-group kills, and macOS does not ship it. Windows is not
supported.

### Ecosystem tools

| Name | Needs (else the ecosystem is SKIPped) | Optional extras | Get it |
| --- | --- | --- | --- |
| `maven` | `mvn` | none to install: Maven fetches the OWASP `dependency-check-maven` and `versions-maven-plugin` plugins itself. An [NVD API key](#nvd-api-key) is strongly recommended | [maven.apache.org](https://maven.apache.org/install.html) |
| `gradle` | a `gradlew` wrapper in the project (run with `sh`, or `bash` when it is a bash script, so it need not be executable) | the [gradle-versions-plugin](https://github.com/ben-manes/gradle-versions-plugin) (`com.github.ben-manes.versions`), applied in `build.gradle(.kts)`, `settings.gradle(.kts)` or `~/.gradle/init.d/`, for the check-mode report | ships with the project |
| `sbt` | `sbt` | none for sbt 1.4+ and 2: the [sbt-updates](https://github.com/rtimush/sbt-updates) plugin is used from `project/*.sbt` or the global plugins (`~/.sbt/1.0/plugins/`; sbt 2 has none), and otherwise added for the command. Older sbt needs it in `~/.sbt/0.13/plugins/` or `project/`, else its projects are SKIPped | [scala-sbt.org](https://www.scala-sbt.org/download/) |
| `node` | `npm` | `yarn` and `pnpm`, for projects with their lockfile (npm is used otherwise) | [nodejs.org](https://nodejs.org/) |
| `php` | `composer` | | [getcomposer.org](https://getcomposer.org/download/) |
| `python` | `python3`, plus `pip-audit` or `safety` | `pip-audit` is preferred: it lists each finding and `--fix` updates `requirements.txt`. `safety` is a check-only fallback | [pip-audit](https://github.com/pypa/pip-audit) |
| `ruby` | `bundle`, which must run | `bundle-audit`: installed automatically with `gem install bundler-audit` when `gem` is available; without it Gemfiles are resolved but not audited (`[WARN]`) | [bundler-audit](https://github.com/rubysec/bundler-audit) |
| `go` | `go` | `govulncheck` (without it projects are not audited, `[WARN]`), `gosec` | [go.dev](https://go.dev/dl/) |
| `rust` | `cargo` | `cargo-audit` (without it projects are not audited, `[WARN]`) | [rustup.rs](https://rustup.rs/) |
| `dotnet` | `dotnet` | `dotnet-outdated`, which upgrades packages in update mode; without it the audit still runs | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) |
| `dart` | `dart` | | [dart.dev](https://dart.dev/get-dart) |
| `elixir` | `mix` | Hex is installed or updated with `mix local.hex --force` before the first project | [elixir-lang.org](https://elixir-lang.org/install.html) |
| `swift` | `swift` | | [swift.org](https://www.swift.org/install/) |
| `r` | `Rscript` | | [r-project.org](https://cran.r-project.org/) |

### Scanners and their tools

| Scanner | Needs | Without it | Get it |
| --- | --- | --- | --- |
| Trivy | `trivy` | `[SKIP] trivy (trivy not installed)` | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| bandit | `bandit` | `[SKIP] bandit (bandit not installed)` | [PyCQA/bandit](https://github.com/PyCQA/bandit) |
| grype | `grype` and `docker`, with the daemon running | skipped without a line when either is missing, with one SKIP line when the daemon cannot be reached | [anchore/grype](https://github.com/anchore/grype), [Docker](https://docs.docker.com/engine/install/) |
| gosec | `gosec` (runs inside the Go audit) | not run, without a line | [securego/gosec](https://github.com/securego/gosec) |
| govulncheck | `govulncheck` (the Go audit) | Go projects are not audited, `[WARN]` | [golang.org/x/vuln](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) |
| OWASP dependency-check | `mvn` (the Maven audit) | the `maven` ecosystem is SKIPped | fetched by Maven |
| netsec | nothing: built in | always available | |

### Installing the optional tools

The official install methods for the extras, in one place. Install only what
your repositories need:

```bash
# GitHub CLI (https://cli.github.com/), then log in, or put export GH_TOKEN=... in ~/.bashrc
gh auth login

# Python: pip-audit and bandit (pipx keeps them out of the system Python; into ~/.local/bin)
pipx install pip-audit
pipx install bandit

# Go: govulncheck and gosec (into ~/go/bin)
go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Rust: cargo-audit (into ~/.cargo/bin)
cargo install cargo-audit --locked

# Ruby: bundler-audit (also installed automatically when gem is available)
gem install bundler bundler-audit

# .NET: dotnet-outdated (into ~/.dotnet/tools)
dotnet tool install --global dotnet-outdated-tool

# Node: Yarn and pnpm, if your projects use them
npm install -g yarn pnpm

# Trivy and grype, with their official install scripts (grype also needs Docker)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

Cron and systemd start with a minimal `PATH`, so the tool adds the usual
per-user tool locations that exist. In front of `PATH`: `/usr/local/go/bin`,
`$GOBIN`, `$GOPATH/bin` (or `~/go/bin`), `$CARGO_HOME/bin` (or `~/.cargo/bin`),
`~/.dotnet/tools`, and every SDKMAN candidate's `current/bin`. Behind it, to
fill gaps without overriding your own choices: `/usr/local/bin` (cron's
default `PATH` is only `/usr/bin:/bin`), `~/.local/bin` (pipx,
`pip --user`), `~/.yarn/bin`, `~/.local/share/swiftly/bin`, `$PNPM_HOME` (or
`~/.local/share/pnpm`), `$GEM_HOME/bin`, and the newest Node.js installed with
nvm (`$NVM_DIR`, or `~/.nvm`).

### When a tool is missing

| You see | What it means |
| --- | --- |
| `[SKIP] go (go not installed)` | the ecosystem's main tool is missing, so none of its projects run |
| `[SKIP] maven (no pom.xml found)` | nothing in the tree needs that ecosystem |
| `[SKIP] [sbt] svc — sbt-updates plugin not configured for sbt 0.13.15 (...): add addSbtPlugin(...) to ~/.sbt/0.13/plugins/sbt-updates.sbt` | the project needs a plugin or a file it does not have; the line says what to add |
| `[WARN] [go] api — govulncheck not installed, not audited` | the project was updated or listed, but its optional audit tool is missing |
| `[SKIP] gh (not installed - GitHub checks unavailable)` | the GitHub steps are skipped; everything local still runs |

Install the tool, or silence the line with `--no-<name>` or the config file.

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

## Targets, state and scope

**TARGET** is the positional argument (default: the current directory):

| TARGET | Meaning |
| --- | --- |
| `path/to/dir` | A local directory, scanned in place. It must not itself be a symlink. |
| `https://...`, `ssh://...`, `git://...`, `file://...`, `git@host:path` | A git remote, cloned into the workdir. |
| `owner/name` | GitHub shorthand for `https://github.com/owner/name.git`, used when no local directory of that name exists. |

**Remote targets.** A remote target is cloned into `STATE/checkout` (or
`--workdir`) for the run and deleted when the run ends, however it ends: after
the summary, after an error, or on Ctrl-C. Update mode's changes are deleted
with it, so publish them with `--push`, `--pr` or `--push-direct`.
`--keep-clone` keeps the clone instead, for inspecting what update mode did;
the next run then fetches it and resets it to the tip of the remote's default
branch, deleting untracked and ignored files and warning about local changes,
so a run always starts from a pristine tree. The tool only resets or deletes a
directory it cloned itself (it leaves a marker in `.git/`) or one that was
empty, and refuses to use anything else. Private
repositories need git credentials that work without a prompt: an SSH key, or
`gh auth setup-git` for HTTPS. When `GH_TOKEN` or `GITHUB_TOKEN` is set (or
harvested, see [GitHub integration](#github-integration)) and `gh` is
installed, git authenticates to github.com over HTTPS through `gh` with that
token, ahead of any stored credential, so clones and pushes use the same
account as the GitHub steps. Git runs with `GIT_TERMINAL_PROMPT=0` and SSH in
batch mode, so a missing credential fails instead of hanging.

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

**State** lives outside the scanned tree, by default under
`${XDG_STATE_HOME:-~/.local/state}/dep-sec-patcher/`:

```text
dep-sec-patcher/
├── vulns/
│   └── <slug>.json   vulnerability database, kept between runs (--vuln-db)
└── <slug>/
    ├── reports/      the latest run's reports (--report-dir)
    ├── run.lock      only while a run is going
    └── checkout/     a remote target's clone, only while a run is going (--workdir, --keep-clone)
```

Nothing a rerun needs is in `<slug>/`: the lock and the clone are deleted when
the run ends, and the directory itself when nothing is left in it (the reports
stay until the next run replaces them). The tools' own advisory databases (the
NVD copy dependency-check keeps, Trivy's, govulncheck's, ...) are in each tool's
cache and shared by every target. A database left at the old default,
`<slug>/vulns.json`, is moved to `vulns/<slug>.json` by the next run.

The slug is `owner__name` (lowercased) when there is a GitHub repository, and
`<directory-name>-<8 hex chars>` otherwise, where the hash comes from the
target's realpath or from its normalised URL. `--state-dir` puts everything,
the database included (`STATE/vulns.json`), in one directory of your choosing,
which is never deleted. `--vuln-db`, `--report-dir` and `--workdir` move
individual parts. A state directory, database or report directory inside the
scanned tree is refused: it would be audited, wiped by check mode, or committed.

## Options

`--opt value` and `--opt=value` are equivalent. `dep-sec-patcher --help` prints
the same list.

### Target and state

| Option | Default | Description |
| --- | --- | --- |
| `TARGET` | current directory | Directory, git URL or `OWNER/NAME` to scan |
| `--subdir PATH` | | Scan only `PATH` inside the target |
| `--repo OWNER/NAME` | from the target's `origin` / URL | GitHub repository for the GitHub steps (env `GH_REPO`) |
| `--state-dir DIR` | `$XDG_STATE_HOME/dep-sec-patcher/<slug>` | Base for the reports, lock and clone, and with this option the database too |
| `--vuln-db PATH` | `$XDG_STATE_HOME/dep-sec-patcher/vulns/<slug>.json` (`STATE/vulns.json` with `--state-dir`) | Vulnerability database (env `VULN_DB`) |
| `--report-dir DIR` | `STATE/reports` | Where reports are written |
| `--workdir DIR` | `STATE/checkout` | Clone location for a remote target, deleted when the run ends |
| `--keep-clone` | | Keep a remote target's clone after the run; the next run refreshes and reuses it |
| `--config FILE` | `TARGET/.dep-sec-patcher.json` if present | Config file |

### Mode

| Option | Description |
| --- | --- |
| `--update` | Update dependencies, apply fixes, merge bot PRs, then audit (default; env `SECURITY_UPDATE_MODE`) |
| `--check` | Audit only; anything a tool writes into the tree is undone |
| `--apply-stored` | Only apply fixes recorded in the vuln DB: no audits, scanners or GitHub collection |
| `--strict` | Exit with status 3 when any check fails |

### Publishing

Update mode only (they do nothing with `--check`), and command line only. See
[Publishing the changes](#publishing-the-changes).

| Option | Default | Description |
| --- | --- | --- |
| `--push` | | Commit the run's changes to a new branch, push it to `origin`, and check the starting branch out again. The tree must have been clean at the start |
| `--pr` | | Implies `--push`. Then open a pull request from that branch into the branch the tree started on, merge it, and delete the branch |
| `--pr-merge METHOD` | `squash` | How `--pr` merges: `squash`, `merge`, `rebase`, or `none` to open the PR and leave it for review. Only valid with `--pr` |
| `--push-direct` | | Implies `--push`. Commit straight onto the checked-out branch and push it: no side branch, no PR (a commit that cannot land is pushed to a side branch instead). Cannot be combined with `--pr` or `--branch` |
| `--branch NAME` | `dep-sec-patcher/<UTC timestamp>` | Branch for `--push` and `--pr` (the default looks like `dep-sec-patcher/20261018-033000`) |

### Running

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

### Ecosystems and scanners

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
something in the tree needs it. `--<scanner>` turns a scanner back on when the
config file turned it off.

### GitHub

| Option | Default | Description |
| --- | --- | --- |
| `--max-issues N` | 0 | Maximum open issues to read, newest first (`0` = all; read 100 per GraphQL page, about a minute for 6,000 issues) |
| `--no-github` | | Skip every GitHub step |
| `--no-merge-prs` | | Skip dependency-bot PR triage: no merges, auto-merges or rebase requests |
| `--no-auto-fix` | | Record vulnerabilities but never edit manifests |
| `--allow-major` | | Let auto-fix move a dependency to a new major version when that is the only fix (by default such fixes are reported and left pending), and let the updaters cross major lines (Maven's versions plugin, `npm audit fix --force`, `pnpm up --latest`, `dart pub upgrade --major-versions`) |
| `--close-fixed` | | Close security issues whose fixes the manifests now declare |
| `--close-label NAME` | `security: verified fixed` | Label added before closing (created if missing; empty disables) |
| `--close-delay N` | 5 | Seconds between closes |
| `--close-limit N` | 400 | Stop after N closes (`0` = unlimited) |

### Environment

| Variable | Use |
| --- | --- |
| `SECURITY_UPDATE_MODE` | `check` or `update`: the default mode |
| `GH_REPO`, `VULN_DB` | Defaults for `--repo` and `--vuln-db` |
| `GH_TOKEN`, `GITHUB_TOKEN` | GitHub token for `gh` (also read from shell rc files, see [GitHub integration](#github-integration)) |
| `NVD_API_KEY` | NVD API key (also read from shell rc files) |
| `XDG_STATE_HOME` | Base of the default state directory |
| `HOME`, `GOPATH`, `GOBIN`, `CARGO_HOME`, `DOTNET_CLI_HOME`, `SDKMAN_DIR`, `PNPM_HOME`, `GEM_HOME`, `NVM_DIR` | Used to find per-user tool installs (see [Tools it uses](#installing-the-optional-tools)) |

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
  "exclude-dirs": ["docs", "test/fixtures"],
  "allow-major": false
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
| `allow-major` | `true` / `false` | `--allow-major` |

Unknown keys, unknown ecosystem or scanner names, and values of the wrong type
are errors (exit status 1) that name the file and key, so a typo cannot fall
back silently to a default. For a remote target the file is read from the clone.
The config file belongs to the scanned tree, so some options cannot be set
there: the paths (state directory, database, reports, workdir), the mode, and
the publishing options (`--push`, `--pr`, `--pr-merge`, `--push-direct`,
`--branch`), so that a scanned tree can never turn on pushing.

## Scanners

| Scanner | Runs | Result |
| --- | --- | --- |
| `trivy` | `trivy fs --scanners vuln,misconfig,secret` over the scanned tree, once. If Maven Central rate-limits its POM lookups (HTTP 429), a `Retry-After` of up to 5 minutes is waited out and the scan retried once; a longer block, or a second 429, reruns it with `--offline-scan` | Secrets or high/critical vulnerabilities fail; misconfigurations warn. An offline fallback adds "offline scan" to the result. Report `trivy/_root/trivy-fs-results.json`. |
| `bandit` | `bandit -r .` once, when there are `.py` files | HIGH findings fail, others warn. Report `bandit/_root/bandit-results.json`. |
| `grype` | Builds an image from each of up to 5 `Dockerfile`s and scans it; needs `grype` and `docker`; images are removed afterwards | By severity. Skipped silently when either tool is missing, and with one SKIP line when the docker daemon is not reachable. |
| `gosec` | Inside each Go audit | Finding count as a note; report under `gosec/`. |
| `netsec` | Built in, over every indexed file | See below. |

OWASP dependency-check and govulncheck are not separate scanners: they run as
part of the Maven and Go audits (see
[Supported languages and ecosystems](#supported-languages-and-ecosystems)).

`netsec` looks for:

- plain `http://` URLs in `.yaml`, `.yml`, `.json` and `.toml` files whose path
  does not contain `example` or `test` (WARN);
- hardcoded `password`, `api_key`, `secret`, `token`, AWS access keys and
  private keys, ignoring placeholders such as `password_example` or
  `YOUR_API_KEY` (FAIL);
- `TLSv1.0`, `TLSv1.1` or `sslversion` in config and `.properties` files (WARN).

Lockfiles, binary files and files over 2 MB are not scanned.

<details>
<summary><b>Plain-HTTP URLs netsec accepts by default</b></summary>

<br>

Identifier-like URLs are not endpoints, so these prefixes (after `http://`) are
allowed: `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`, `www.w3.org/`,
`json-schema.org/`, `www.apache.org/licenses`, `opensource.org/`,
`maven.apache.org/`, `xmlns.*`, `schemas.*`, `purl.org/`, `example.com`,
`example.org`, `example.net` and `petstore.swagger.io`. Extend the list with
`--allow-http` or the config's `allow-http`.

</details>

## GitHub integration

All GitHub work goes through the [`gh`](https://cli.github.com/) CLI. Each call
has a timeout, and failures are reported as "could not list ..." rather than
read as "nothing found".

**Authentication.** When gh's active account has no working token
(`gh auth status --active`, or plain `gh auth status` on gh before 2.40), the
tool looks for `export GH_TOKEN=...` or `export GITHUB_TOKEN=...` in
`~/.bashrc`, `~/.bash_profile`, `~/.profile` and `~/.zshrc`, takes the last
assignment, and retries. Cron jobs therefore work without sourcing the rc file.
The same harvesting finds `NVD_API_KEY`. Without `gh`, or without a working
token, the GitHub steps print `[SKIP]` or `[WARN]` lines and the local audits
still run.

**Repository.** `--repo`, otherwise the target's GitHub origin (see
[Targets](#targets-state-and-scope)), canonicalised through `gh api repos/...`
so that a renamed repository resolves to its current name.

**Collection** (every mode except `--apply-stored`):

- *Dependabot alerts*: `repos/{repo}/dependabot/alerts?state=open`, all pages.
  This needs a token that can read security alerts (repository admin, or the
  `security_events` scope).
- *Repository security advisories*: published, draft and triage advisories. A
  404 counts as none.
- *Security issues*: every open issue by default, newest first, read 100 at a
  time through GraphQL (a failed page is retried on its own with a smaller page,
  and a rate limit waits for the reset). `--max-issues N` stops after N (a WARN
  says so; the rest are read as earlier ones close). Their bodies become
  manifest edits, so only issues opened by a GitHub App bot whose login starts
  with `mend`, `whitesource`, `snyk`, `renovate` or `dependabot` (optionally
  prefixed `app/`) are read; anything a person could have written is ignored.
  Two Mend Bolt / WhiteSource formats are parsed:
  - the per-CVE format ("Path to dependency file", "Fix Resolution",
    "Direct dependency fix Resolution", and the bare coordinate lists): one
    remediation record per package, fix version and manifest. A bare list
    names packages loosely, so it is narrowed to the libraries the issue
    reports, taken in full from the paths Mend found them at (a Maven, Gradle or
    Ivy cache path gives the groupId, a `node_modules` path the npm scope, the
    Go module cache the module path). Alternatives that no manifest uses are
    dropped (`bcprov-lts8on` beside `bcprov-jdk18on`, `tools.jackson.core`
    beside `com.fasterxml.jackson.core`); a bare version or a tarball name gets
    its full name (`core-7.29.0.tgz` is `@babel/core`, not the npm package
    `core`); and a repository URL (`https://github.com/netty/netty.git - 4.1.135.Final`)
    becomes the version of the libraries built there, never a package named
    after the repository. For a Maven or Go library, whose next major can be
    published under another name, a repository tag is only taken on a major
    line in use, or where the list names a sister package with the same
    groupId at that version: jackson-databind's 3.x tags are
    `tools.jackson.core` releases. An npm, PyPI or NuGet package keeps its
    name, so `multiparty.git - 4.3.0` is multiparty's fix whatever line is in
    use. Each record also keeps the versions the issue found in use in that
    manifest;
  - the grouped format, one issue per library (such as
    "axios-1.3.5.tgz: 40 vulnerabilities (highest severity is: 9.3)") with a
    "Sample Path to Dependency File", a summary table and a `<details>` section
    per CVE: one record per CVE. A CVE whose section GitHub truncated is taken
    from the table's "Fixed in (X version)" column, and a CVE with no known fix
    becomes a record without a fixed version (state `skipped`), which keeps
    close-fixed from closing that issue.

  Versions from issue bodies must look like versions, and manifest paths that
  climb out of the tree are dropped. Listing is retried three times before the
  issue set is given up for the run.

The records are merged into the [vulnerability database](#vulnerability-database),
and records GitHub no longer reports are marked `resolved` (see there). On gh
before 2.48, which has no `api --slurp`, the paginated listings fall back to
`--jq`.

**Repository settings.** Reports whether secret scanning, Dependabot security
updates and code-scanning default setup are enabled. Secret scanning or
Dependabot security updates being off is a FAIL line.

**Dependency-bot PR triage.** Only non-draft PRs opened by a GitHub App bot
whose login starts with `dependabot`, `renovate`, `mend`, `whitesource` or
`snyk` (optionally prefixed `app/`) are considered; a human's PR is never
touched, even one from an account named like a bot. GitHub computes mergeability lazily, so it is polled for up to 12
seconds. Check mode only lists each PR with its state. In update mode:

- mergeable PRs are squash-merged (branch deleted), or set to auto-merge when
  required checks are still pending;
- a PR whose checks are failing or still running (GitHub's `UNSTABLE` state) is
  left for a later run rather than merged;
- a PR that moves a dependency to a new major version (below 1.0, a new minor
  one) is not merged without `--allow-major`. The bumps are read from
  Dependabot's title and its "Updates \`x\` from A to B" lines, and from
  Renovate's `` `A` -> `B` `` table rows;
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
- the version the manifest declares is read (for a transitive npm dependency,
  the versions its lockfile holds), and the fix is chosen per advisory: the
  lowest fix that clears the declared version on its own release line (a
  project on Tomcat 9.0 gets the 9.0 fix, not the 11.0 one), then the highest
  of those across advisories;
- nothing is written when the declared version already satisfies every
  advisory, when a Maven/NuGet range already admits a fixed version, or when
  the fix would move a declared version backwards;
- a prerelease that sorts above every fix without being known to include one
  (netty `5.0.0.Alpha2` against `4.1.137.Final` / `4.2.17.Final`) has no fix
  to move up to, and going back to a release is not done unasked: it stays
  pending with a note and a warning saying so;
- a fix that needs a new major version is held back unless `--allow-major` is
  given;
- a transitive dependency is pinned instead: npm `overrides` / `resolutions`,
  or Maven `<dependencyManagement>`, on the line its lockfile or, without one,
  its issue says is in use. An npm package that the lockfile holds no copy of
  is not pinned at all (nothing installs it), and a pin never goes to a
  prerelease when a release fixes the same advisories;
- Maven `${property}` versions are bumped at the property definition.

The files it can edit, how each writes the version, and the rules for major
versions and transitive npm dependencies are in
[Manifests auto-fix can edit](#manifests-auto-fix-can-edit). Each record's
outcome is written back to the database: `applied`, `skipped` with the reason
in `note`, or still `pending` with a note when it needs a major upgrade, cannot
be edited, or needs a pin by hand. The step ends with a line such as
`auto-fix: applied=3 already-ok=5 not-declared=1 missing-manifest=0 cannot-edit=1 needs-major=2`.
Check mode works out the same edits without writing anything: it prints
`would set npm qs -> 6.15.2 in package.json` lines and an
`auto-fix (check mode): would-apply=…` summary, and the
[Next steps](#quick-start) section turns them into a command line.

<details>
<summary><b>How versions are compared</b></summary>

<br>

- A declared requirement is reduced to the lowest version it admits, counting
  only lower bounds and exact pins: `^4.17.1` and `>= 4.17.1` give `4.17.1`,
  `<1.27,>=1.21.1` gives `1.21.1`, and `<2` gives nothing (it admits any old
  version, so an issue is never closed on the strength of it).
- A union (`^5.4 || ^6.0`, Composer's `|`, Maven's `[1,2),[3,)`) counts as its
  lowest alternative.
- Pre-releases rank below their release, including the forms without a dash:
  `4.2rc1`, `2.0.0.dev1`, `7.0.0.rc1`, `1.0.M1`.
- An advisory lists one fix per release line. A version is fixed when it is at
  or above the fix on its own line (Tomcat `9.0.110` against `9.0.106` /
  `10.1.42` / `11.0.8`), or above every fix. Being above some other line's fix
  is not enough: netty `4.2.5.Final` is above `4.1.137.Final` and still waits
  for `4.2.17.Final`.
- A prerelease above every fix may still predate them all (netty
  `5.0.0.Alpha2` is from 2015), so it only counts when its major line had a
  release before it and no fix was listed for that line: spring-boot
  `4.2.0-M2` against a fix in `3.0.0` does, spring `7.1.0-M2` against `7.0.8`
  does not. Qualifiers that name a flavour of a release (`33.4.0-jre`,
  `4.1.42.Final`) are not prereleases.
- `1.2` and `1.2.0` are the same version.
- Otherwise versions compare like GNU `sort -V`, with semver pre-release
  ordering.

</details>

**Close-fixed** (`--close-fixed`). For every open issue that has records in the
database, each package it reports is looked up in the current manifests. For
npm and Composer, when a lockfile beside the manifest (including
`composer.lock`) holds the package, every locked copy must meet the fix
instead, and the evidence shows it as `x.y.z (locked)`. The issue is closed
only when every package is fixed by the rules under "How versions are
compared" above: at or above the fix on its own
release line, or above every fix (a prerelease only as described there). With
`--debug`, each issue left open says what it still needs
(`io.netty:netty-codec-http is 4.2.16.Final, needs >= 4.1.137.Final or 4.2.17.Final`).
Anything unverifiable (manifest gone, package not
declared, a CVE with no known fix) stays open. The issue is labelled
`--close-label` first, then closed with a comment holding the evidence table
(package, required version, declared version, manifest) and a hidden
`<!-- security-update:closed-verified -->` marker. GitHub limits
content-creating calls to roughly 80 a minute and 500 an hour, so closes are
paced (`--close-delay`), back off on "submitted too quickly" responses (1, 4,
then 9 minutes), and stop at `--close-limit`. Re-run to continue. If the list
of open issues cannot be fetched, close-fixed is skipped rather than working
through every issue ever recorded.

It only closes issues on the strength of changes that are on the base branch.
In check mode it lists what it would close. When the run publishes, it runs
after publishing and closes only once the changes landed (pushed with
`--push-direct`, merged by `--pr` during the run, or nothing needed changing);
otherwise it lists what it would close. In an update run without a publishing
option, a tree left with uncommitted changes also only gets the list: commit
and push them, or use `--push-direct` or `--pr`.

### Publishing the changes

In update mode, `--push`, `--pr` and `--push-direct` turn the run's changes
into a commit on `origin`:

| | `--push` | `--pr` | `--push-direct` |
| --- | --- | --- | --- |
| **The commit lands on** | a new branch: `--branch NAME`, or `dep-sec-patcher/<UTC timestamp>` | a new branch, as with `--push` | the checked-out branch (for a remote target, the default branch) |
| **Pull request** | none; with a GitHub repository, the run prints the `gh pr create` command to open one by hand | opened with `gh pr create` into the branch the tree started on (for a remote target, the default branch) | none |
| **Merge** | | `gh pr merge` with the `--pr-merge` method (default `squash`), then the branch is deleted on `origin` and locally. With `--pr-merge none` the PR is left open for review and the branch is kept | |
| **If `origin` moved during the run** | the commit is rebased onto `origin`'s copy of the starting branch before the push; if it conflicts, it is pushed un-rebased so the conflict shows up in review | as with `--push` | the commit is rebased onto `origin`'s copy and the push retried once |
| **When it cannot go through** | the failed push is reported | blocked by required checks: auto-merge is enabled instead, and the run says so. Conflicting, or not mergeable at all: the PR is left open and reported | a conflict, a protected branch or a rejected push: the commit is moved to `dep-sec-patcher/<UTC timestamp>` and pushed there for you to merge by hand, and the local branch is reset to where it started |
| **The working tree afterwards** | back on the branch it started on | back on the branch it started on; after a merge, a local checkout's base branch is fast-forwarded to the merged result when possible | on the same branch, with the new commit |
| **Needs** | push access to `origin` | push access, plus `gh` authenticated for a GitHub repository; without them the branch is still pushed and the run says to open the PR by hand | push access to the branch, and a checked-out branch (a detached HEAD is refused) |

All three:

- need TARGET to be the top of a git work tree that was **clean when the run
  started**, checked before anything touches it (a remote target's clone always
  is clean), so nothing but this run's changes can end up in the commit.
  Otherwise nothing is committed and the run says why;
- change the order of the run: dependency-bot PRs are triaged first and the
  checked-out branch is fast-forwarded to `origin`'s copy (unless it has
  diverged), so the dependency updates are made on top of the bot PRs just
  merged instead of conflicting with them;
- commit everything the run changed: updated manifests and lockfiles,
  lockfiles update mode created, and the fixes auto-fix wrote. When the run
  changed nothing, nothing is committed;
- write a commit message (and, for `--pr`, a PR body) that lists the fixes
  auto-fix applied, such as `npm qs -> 6.15.2 in web/package.json`, and the
  files changed;
- commit with `git commit --no-verify` (hooks do not run), as
  `dep-sec-patcher <dep-sec-patcher@users.noreply.github.com>` when git has no
  `user.email` configured;
- can only be given on the command line, never in the config file, because the
  config file belongs to the scanned tree;
- do nothing in check mode.

The outcome is the `push` row of the summary and the JSON report: PASS when the
commit was pushed (for `--pr`: and the PR was merged, set to auto-merge, or
left open with `--pr-merge none`), SKIP when nothing changed, and FAIL when the
push, the pull request or its merge failed, or `--push-direct` had to fall back
to a side branch. `--close-fixed` runs after publishing and only closes issues
once the changes are on the base branch (see
[Close-fixed](#github-integration) above).

`--pr-merge` is only valid with `--pr`, and `--push-direct` cannot be combined
with `--pr` or `--branch`; these are usage errors (exit status 1).

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

`dep-sec-patcher/vulns/<slug>.json` (`STATE/vulns.json` with `--state-dir`, or
`--vuln-db`) is a JSON file per target holding one record per vulnerability,
package and manifest. It is per target because its records are: they name that
repository's manifest paths and issue numbers, and what was applied there.

- `source` is `dependabot`, `advisory` or `issue`. Keys are
  `ecosystem|package|manifest|id` for alerts, `ecosystem|package||ghsa` for
  advisories, and `manifest|package|id` for issues. An issue refiled for the
  same CVE, package and manifest therefore updates the existing record, and its
  number is added to `refs`.
- `state` is `pending` until auto-fix handles the record, then `applied` or
  `skipped`, with the reason in `note`; a fix held back (a major upgrade, a
  spec it cannot edit) stays `pending` with a note. A record can also arrive
  with its own state, such as a Mend CVE with no known fix (`skipped`).
  Re-collecting a record keeps `first_seen`, `state`, `applied_at` and `note`,
  and unions `refs` and `fix_versions`.
- An issue read again replaces what it reported before: a record it no longer
  yields (the bot edited the issue, or an older version of this tool named the
  wrong package, such as `babel` for `@babel/core`) drops that issue from its
  `refs`, and is deleted when no issue is left. Records of issues not read in
  the run are untouched.
- After a complete listing, a `pending` Dependabot record whose alert is no
  longer open, and a `pending` issue record none of whose issues is still open,
  become `resolved` with a note. Issue records are only retired when every open
  issue was listed, so a listing cut short by `--max-issues` retires nothing.
- Writes are atomic (a temp file in the same directory, renamed over the
  original) and the file is mode 0600. A corrupt file is reported and treated
  as an empty database, which the next save replaces.
- `--apply-stored` replays the database without collecting from GitHub or
  running audits and scanners. `--close-fixed` and the publishing options still
  work alongside it.

<details>
<summary><b>File format</b></summary>

<br>

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

</details>

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

`security-scan-report.json` summarises the run. Its `ecosystems` object holds
one row per ecosystem, scanner and GitHub step: the ecosystem names, `bandit`,
`trivy`, `grype`, `network-security` (the netsec check), `dependabot`,
`advisories`, `sec-issues`, `secret-scanning`, `dep-prs`, `auto-fix`,
`close-fixed` and `push`. With several projects per ecosystem the worst status
wins and the counts are added.

<details>
<summary><b>Example report</b></summary>

<br>

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

</details>

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | The run completed, whatever it found |
| 1 | Usage, config or setup error: unknown option, conflicting options, invalid config file, target not found, clone failed, state inside the tree, or another run holds the lock |
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

Two audits of the same directory, such as a `package.json` and a
`composer.json` side by side, never run at the same time, whatever `-t` is.
Without the `pcntl` extension, or with `-t 1`, everything runs one job at a time
in-process.

## Safety guarantees

- **Timeouts.** Every external command has a timeout (`--timeout`, and
  `--nvd-timeout` for the NVD refresh). A command that times out gets SIGTERM,
  then SIGKILL 10 seconds later.
- **Process groups.** With `setsid` and the `posix` extension available, each
  command runs in its own session, so a timeout or Ctrl-C stops the whole tree
  it started, not just the top process.
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
  deleted and every changed file restored. The contents of build and
  dependency directories that already existed are not snapshotted, so a tool
  may refresh caches inside them. In update mode only new build and
  dependency directories are removed (`node_modules`, `vendor`, `target`,
  `obj`, `bin`, `build`, ...), and a `project/` that sbt created for nothing
  but its own output goes with them, so `--push` cannot commit it. Entries that
  existed before are never deleted, and a `project` that is a symlink is never
  looked into. Read-only directories left by Go and Cargo are made writable
  before removal.
- **Third-party code.** npm runs with `--ignore-scripts` and lockfile-only;
  Composer with `--no-scripts --no-plugins --no-install`; Bundler resolves
  without installing gems.
- **Run lock.** One run per target at a time (`STATE/run.lock`, `flock`). The
  lock is opened close-on-exec, so a daemon a tool leaves behind cannot keep
  holding it. The run deletes the file while still holding the lock, and a
  starting run checks that the file it locked is still the one at that path,
  so two runs never hold locks on different files.
- **Deleting the clone.** The clone is moved aside before it is deleted, so a
  deletion cut short never leaves a half-deleted tree in the next run's way.
  Symlinks inside it are unlinked, never followed or `chmod`ed (a cloned
  repository can link anywhere on the host), and only a clone the tool made,
  or an empty directory, is ever deleted.
- **Workers.** A forked worker writes its result to a temp file and then kills
  itself with SIGKILL, so shutdown handlers and destructors inherited from the
  parent never run twice. SIGINT, SIGTERM and SIGHUP are passed on to workers
  and to every running command; the handlers are installed before the first
  clone, so Ctrl-C during it stops git too. Before exiting, a stopped worker
  runs the workspace guard of the audit it was in, so Ctrl-C in check mode
  still undoes that audit's changes.
- **Untrusted input.** Issue bodies are only read from GitHub App bots, and
  dependency-bot PRs are only touched when a GitHub App bot opened them. Package
  names and versions taken from issues and advisories must look like names and
  versions before they reach a manifest, and every manifest path is resolved
  and must lie inside the tree before it is edited.
- **State stays outside the tree**, a symlinked TARGET is refused, `--subdir`
  cannot escape the target, and only clones the tool made itself are ever reset.
- **Publishing is opt-in and contained.** Nothing is committed or pushed
  without `--push`, `--pr` or `--push-direct` on the command line, only the
  paths the run changed that were clean before it are committed (whatever was
  already uncommitted stays out of the commit and in the tree, and a file that
  was dirty and that the run changed too is left out with a warning), and the
  config file cannot enable any of it.
- **Secrets.** `-D...key/token/password/secret=` arguments and URL credentials
  are masked in printed commands; the NVD key is passed through the
  environment.
- **Terminal output.** A tool's output is printed without its colour codes and
  other escape sequences, so a build in a cloned repository cannot set the
  terminal's title, hyperlinks or cursor through this tool.

## Troubleshooting

**It looks hung.** Almost always the NVD refresh without an API key: see
[NVD API key](#nvd-api-key). Run with `-v` to watch each tool's output, or
`--debug` to see each command. Every command prints a "still running" line
after a minute of silence, and nothing runs longer than `--timeout`.

**The first run is slow.** The first run fills several caches: the NVD
database, `~/.m2`, the npm, Composer, Cargo and Go module caches, and the
Trivy, govulncheck and bundler-audit advisory databases. Later runs reuse them.

**A fix stays `pending`.** The auto-fix line and the record's `note` say why:
it needs a major upgrade (rerun with `--allow-major`), the declared spec is one
it cannot edit (a union, a git or file spec, a dist-tag, a `--hash` file), or
the lockfile (or the issue) has the package in use on several major lines and
it needs a pin by hand. The "Next steps" section at the end of the run suggests
the command.

**`Gradle X runs on Java N at most`.** The project's wrapper predates the
host's Java and no JDK under `/usr/lib/jvm` is old enough for it. Install one
(`apt install openjdk-17-jdk-headless`, for instance, covers Gradle 7.3 to
8.4), or update the wrapper.

**A project is SKIPped.** The reason is on the line: tool not installed, no
lockfile to audit, or a Gradle/sbt plugin that is not applied. Install the tool
(see [Tools it uses](#tools-it-uses)), or silence it with `--no-<ecosystem>` or
the config file.

**Nothing was pushed.** The publishing options only act in update mode, on a
TARGET that is the top of a git work tree, when the run changed something in
a path that was clean before it; the run prints which of these stopped it, and
names the paths it left out because they were already uncommitted.
`--push-direct` also needs a checked-out branch rather than a detached HEAD.

**Directories that cannot be deleted** after a run was killed with SIGKILL:
Go's module cache and some Cargo outputs are read-only. Use
`chmod -R u+w DIR && rm -rf DIR`, or `go clean -modcache` for the Go cache.
Normal runs clean up after themselves.

**`another run is already in progress (pid N)`.** Another run holds this
target's lock. If that process is gone, the lock was already released when it
exited (the lock is an `flock`, not the file's existence; a run that was
killed with SIGKILL leaves the file, and the next run simply takes it).

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

## Architecture

```text
bin/dep-sec-patcher        finds an autoloader (Composer's, or a built-in PSR-4 one)
src/Application            options, TARGET/state resolution, config, lock, signals
src/Options, Config        command line and config file, merged in precedence order
src/GitUrl, Target,        remote URL parsing, TARGET classification and clones,
    TargetResolver,        state directory derivation, tool PATH
    StatePaths, Environment
src/Filesystem             recursive deletion that never follows symlinks
src/SecurityRun            the run: audits, scanners, GitHub, auto-fix, close-fixed, publishing, summary
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
src/Version                GNU `sort -V` port, prereleases, floors, unions, Maven/NuGet ranges
src/ManifestEditor         reads and rewrites declared versions in each supported manifest format
src/Lockfile               versions a yarn/npm/pnpm/composer lockfile resolved a package to
src/BranchPublisher        git side of --push, --pr and --push-direct: commit, rebase, push
src/NextSteps              the command a "Next steps" section suggests
```

The pure classes (Version, IssueParser, RecordNormalizer, VulnDb, FixPlanner,
ManifestEditor, ManifestPaths, JsonFile, GitUrl, StatePaths, Config, Options,
NetworkScanner, NextSteps) do no I/O and carry most of the tests. Comments that mention
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
| Vuln DB default: the parent project's `logs/security-vulns.json` | `$XDG_STATE_HOME/dep-sec-patcher/vulns/<slug>.json`. Pass `--vuln-db` to keep using an existing database: the format is unchanged |
| Reports: `logs/security-reports/` beside the database | `STATE/reports/` |
| Lock: `.update-samples-security.lock` in the report directory | `STATE/run.lock` |
| Output prefix `[security-update]` | `[dep-sec-patcher]` |
| Always exits 0 after a run | Still 0; `--strict` adds status 3 on failures |
| | New: `--subdir`, `--state-dir`, `--workdir`, `--keep-clone`, `--config`, `--exclude-dir`, `--allow-http`, `--grype`/`--no-grype`, `--netsec`/`--no-netsec`, `--push`, `--pr`, `--pr-merge`, `--push-direct`, `--branch`, `--allow-major`, `--strict`, `-V` |
| PR markers `<!-- security-update:rebase -->` and `<!-- security-update:closed-verified -->` | Unchanged, so rebase requests posted by the old tool are still recognised |

The old default run is equivalent to:

```bash
dep-sec-patcher PROJECT/vendor/detain/interserver-api-samples \
    --vuln-db PROJECT/logs/security-vulns.json \
    --report-dir PROJECT/logs/security-reports
```

## License

MIT, see [LICENSE](LICENSE).
