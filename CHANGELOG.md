# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

First release: a standalone, generic port of MyAdmin's
`update-samples-security` tool.

### Added

- Composer package `detain/dep-sec-patcher` with the `dep-sec-patcher` command
  (works from a clone without `composer install`, as a project dependency, or
  installed globally).
- Positional TARGET: a local directory, a git URL, or a GitHub `OWNER/NAME`.
  Remote targets are cloned into a cache workdir that is reset to the remote's
  default branch on every run.
- `--subdir` to scan part of a repository while keeping manifest paths
  relative to its root; auto-fix and close-fixed act only inside it.
- The GitHub repository is taken from `--repo` or the target's `origin`
  remote; without one, the GitHub steps print a SKIP line.
- Per-target state under `${XDG_STATE_HOME:-~/.local/state}/dep-sec-patcher/<slug>/`
  (vulnerability database, reports, run lock, clone), with `--state-dir`,
  `--vuln-db`, `--report-dir` and `--workdir` overrides. State inside the
  scanned tree is refused.
- Optional `.dep-sec-patcher.json` config file (or `--config`) for option
  defaults, validated strictly.
- `--exclude-dir` and `--allow-http` (also in the config file), `--grype` /
  `--no-grype`, `--netsec` / `--no-netsec`.
- `--push` / `--branch`: in update mode, commit the changes to a new branch and
  push it to `origin`.
- `--pr`: push the branch, open a pull request into the branch the tree started
  on, merge it (`--pr-merge squash|merge|rebase|none`, default `squash`; auto-merge
  when required checks are pending) and delete the branch.
- `--push-direct`: commit straight onto the checked-out branch and push it. If
  the commit cannot land there, it is pushed to a fallback branch instead and
  the local branch is put back.
- When pushing, origin's moves during the run are handled: bot PRs are merged
  and pulled in before the updates, and the commit is rebased onto anything
  merged since. The commit message and PR body list the applied fixes and the
  changed files.
- `--allow-major` (config `allow-major`): without it, auto-fix leaves fixes
  that need a new major version pending, and PR triage does not merge bot PRs
  that are major upgrades.
- A "Next steps" section at the end of a run that found fixes it did not
  apply or publish, with the exact command line that would.
- Mend's grouped issue format (one issue per library, a summary table and
  per-CVE details, possibly truncated) is parsed into one record per CVE; a
  CVE with no known fix keeps its issue open.
- npm and Composer lockfiles (yarn.lock, package-lock.json, pnpm-lock.yaml,
  composer.lock) are read: transitive npm fixes pin only when the lockfile
  still holds a vulnerable copy, on that copy's release line, and close-fixed
  judges npm and Composer packages by the versions they are locked at.
- `--strict`: exit status 3 when any check fails.
- `-V` / `--version`.
- Tests for target resolution, state paths, URL parsing, the config file,
  `--push` and the command end to end; PHPStan level 8; CI on PHP 8.1 to 8.4
  with Codecov and Codacy coverage uploads.

### Changed (compared with update-samples-security)

- The MyAdmin project profiles (`--profile`, `--project`, `--list-profiles`,
  `API_SAMPLES_PROFILE`, `API_SAMPLES_PROJECT`) are removed.
- Default state location (see above) and output prefix `[dep-sec-patcher]`.
- The netsec plain-HTTP allow-list is a documented default that can be extended.
- The no-`pcntl` fallback no longer references `SIGTERM`/`SIGKILL`, which are
  only defined when `pcntl` is loaded.
- Trivy no longer aborts when Maven Central rate-limits its POM lookups
  (HTTP 429): a `Retry-After` of up to 5 minutes is waited out and the scan
  retried once, otherwise it reruns with `--offline-scan` and says so.
- Elixir check mode runs `mix deps.get` before `mix hex.audit`, which needs
  the fetched dependencies (it always warned before). The workspace guard
  removes `deps/` and `_build/` afterwards.
- GitHub alerts are collected and auto-fix applied before the ecosystem
  updates, so lockfiles are regenerated from the fixed manifests in the same
  run and the audits report the result.
- close-fixed runs after the push, and with `--push`/`--pr`/`--push-direct` only
  closes issues once the changes have reached the base branch.
- `--push` checks that the tree was clean before the ecosystem updates run
  (it checked afterwards, so any run that updated a dependency refused to push).
- Composer 2.9+ advisory blocking no longer fails the whole `composer update`
  when only an insecure version meets a requirement: the update is retried
  with blocking off and the audit reports what stayed insecure.
- The gh check uses `gh auth status --active`, so a stale inactive account in
  `hosts.yml` no longer skips every GitHub step.
- With a GitHub token in the environment, git authenticates to github.com over
  HTTPS through `gh`, ahead of stored credentials for another account.
- `/usr/local/bin`, nvm, Yarn, pnpm, swiftly, `~/.local/bin` and
  `$GEM_HOME/bin` installs are appended to `PATH` for cron runs.
- Only GitHub App bots are trusted: issue bodies from anyone else are not
  parsed, and PR triage no longer matches any login containing "mend",
  "renovate", "dependabot" or "snyk". Versions and manifest paths from issue
  bodies are validated, and manifests are edited only inside the tree.
- PRs whose checks are failing or still running are not merged.
- Version floors only count lower bounds ("<2" has none); unions take their
  lowest alternative; PEP 440 / RubyGems / Maven pre-releases without a dash
  rank below their release; 1.2 equals 1.2.0.
- Manifest edits: the editor follows the file name (GitHub's "rust", "erlang"
  and Gradle-as-"maven" alerts now apply); npm and Composer "*" become
  ">=FIX"; npm unions, git/file/alias specs and Composer dev branches are left
  alone; optionalDependencies count; npm pins are caret ranges in
  "resolutions" (yarn) or "overrides" (npm); requirements files keep markers
  and comments and hashed files are left alone; go.mod edits only require
  lines and keeps +incompatible; pubspec edits only first-level entries.
- check mode works out what auto-fix would change without writing it.
- close-fixed is skipped when the open issues cannot be listed (it fell back
  to every recorded issue), and does not close on uncommitted edits.
- The vulnerability database retires pending records whose alert or issue
  has closed.
- Yarn 1 update mode runs `yarn install` before `yarn upgrade`; Maven gets
  `--enable-native-access` only on Java 17+; gh before 2.48 is supported.
- Two audits of the same directory never run at once, and a signal restores
  the workspace guard of the audit it interrupted.

### Kept

- Every other option, its default and its meaning; the vulnerability database
  format; the PR and issue marker comments; the NVD single-refresh handling,
  timeouts, process-group kills, workspace guard, run lock and per-tool
  concurrency limits.
