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

### Kept

- Every other option, its default and its meaning; the vulnerability database
  format; the PR and issue marker comments; the NVD single-refresh handling,
  timeouts, process-group kills, workspace guard, run lock and per-tool
  concurrency limits.
