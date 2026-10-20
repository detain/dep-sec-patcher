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
  Remote targets are cloned for the run, and the clone is deleted when the run
  ends, also after an error or Ctrl-C. `--keep-clone` keeps it; the next run
  resets it to the remote's default branch and reuses it.
- `--subdir` to scan part of a repository while keeping manifest paths
  relative to its root; auto-fix and close-fixed act only inside it.
- The GitHub repository is taken from `--repo` or the target's `origin`
  remote; without one, the GitHub steps print a SKIP line.
- State under `${XDG_STATE_HOME:-~/.local/state}/dep-sec-patcher/`: each
  target's vulnerability database in `vulns/<slug>.json`, kept between runs,
  and a `<slug>/` directory holding the latest reports, plus the run lock and
  the clone only while a run is going (the directory goes too once empty). A
  database at the old default, `<slug>/vulns.json`, is moved on the next run.
  `--state-dir` (everything, the database included, in one directory that is
  never deleted), `--vuln-db`, `--report-dir` and `--workdir` override it.
  State inside the scanned tree is refused.
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
- Deleting a directory (the workspace guard's build directories, the clone)
  unlinks symlinks without `chmod`ing their targets, which made a linked
  private file world-readable.
- Composer: a project without `composer.lock` is audited from a fresh
  `composer update -W --no-install` in both modes, and the lockfile is deleted
  afterwards, so update mode no longer leaves one for `--push` to commit.
- sbt: when neither the project nor the global plugins have sbt-updates, it
  is added for the one command with `--addPluginSbtFile` (sbt 1.4+), which is
  the only way on sbt 2 (it ignores global plugins); older sbt is SKIPped with
  the line to add and where. sbt always runs in the foreground (`--server` on
  sbt 2, `SBT_NATIVE_CLIENT=false`), so sbt 2 no longer leaves a server JVM
  running after every project. Update mode no longer sets an `onlyEval` key
  sbt-updates does not have (every project failed), and sbt before 1.6 on
  Java 18 to 23 gets `-Djava.security.manager=allow` so it can start.
- Maven update mode also runs `versions:update-properties`, so versions
  declared through `${...}` properties move too.
- `--allow-major` now also governs the updaters: Maven's versions plugin gets
  `-DallowMajorUpdates=false`, `npm audit fix` runs without `--force`, `pnpm up`
  without `--latest` and `dart pub upgrade` without `--major-versions` unless
  it is given. (`npm audit fix --force` had moved `@babel/cli` to 8 beside
  `@babel/core` 7, a peer conflict that broke `npm install`.)
- npm steps are retried with `--legacy-peer-deps` when `package.json` has
  conflicting peer dependencies (`ERESOLVE`), instead of failing the audit.
- Auto-fix no longer pins an npm package its lockfile holds no copy of, and
  a pin prefers the highest release over a prerelease (it had written
  `"babel": "^8.0.0-rc.6"` and `"multer": "^3.0.0-alpha.2"` overrides).
- A WARN says when the issue listing stopped at `--max-issues`.
- grype checks the docker daemon once and SKIPs with the reason, instead of
  a tool error per Dockerfile; a bash `gradlew` is run with bash; govulncheck's
  module-level fallback is explained in a note.
- Mend's bare "Fix Resolution:" lists are narrowed to the libraries the issue
  reports, named in full from the paths Mend found them at (Maven, Gradle and
  Ivy caches give the groupId, `node_modules` the npm scope, the Go module
  cache the module path). A repository URL no longer becomes a package named
  after the repository (`spring-framework`, `netty`, `net`, `grpc-go`, and
  `babel`, which auto-fix had pinned as an npm override), but the version of
  the libraries built there, and only on a major line in use or vouched for by
  a sister package. Alternatives no manifest uses (`bcprov-lts8on`,
  `tools.jackson.core` beside `com.fasterxml.jackson.core`) are dropped, and a
  bare version or tarball name gets its full name (`core-7.29.0.tgz` is
  `@babel/core`; the unscoped `json-schema-ref-parser` had been given
  `@apidevtools/json-schema-ref-parser`'s 15.3.6, which does not exist, and
  `npm install` failed). Only for Maven and Go libraries, whose next major can
  ship under another name, is a repository tag held to the lines in use;
  npm, PyPI and NuGet packages keep their names (`multiparty.git - 4.3.0` is
  multiparty's fix).
- An issue read again replaces the records it yielded before, so records named
  by an earlier parser are dropped rather than holding their issues open.
- Records keep the versions their issue found in use. Without a lockfile, a
  transitive npm or Maven pin follows them: it stays on the line in use (netty
  4.1.76 gets 4.1.135.Final, not 4.2.x), never moves a copy back, and needs
  `--allow-major` to cross a major line, as a declared bump does (spring-webmvc
  in use at 5.1 had been pinned to 7.0). A lockfile-held npm pin is likewise
  chosen from the newest locked copy.
- Maven's versions plugin no longer moves to milestones, release candidates or
  other prereleases (it had written spring-webmvc 7.1.0-M2 and spring-boot
  4.2.0-M2); it counts anything but `-SNAPSHOT` as a release.
- Gradle: a wrapper too old for the host's Java runs on the newest JDK under
  `/usr/lib/jvm` it supports, or is SKIPped naming the Java it needs, instead
  of failing with "Unsupported class file major version". A failed build shows
  Gradle's "What went wrong" section.
- sbt: a build without `project/build.properties` runs on sbt 1.10.11 under sbt
  2's runner (sbt 2 cannot load an sbt 1 build), in the foreground (the runner
  had handed it to a background server that outlived the run), and sbt no
  longer writes a `build.properties` into it. The workspace guard removes a
  `project/` that sbt created only for its output, and no longer looks inside
  a symlinked `project`.
- `npm audit fix` exiting 1 because vulnerabilities remain is reported as what
  remains (how many need a major upgrade, how many have no fix) rather than
  "exit 1".
- Tool output is printed without colour codes and other terminal escape
  sequences.
- The vulnerability database's directory is created mode 0700.
- close-fixed no longer closes an issue because the declared version is above
  one release line's fix: that was the fix the issue happened to list last,
  and netty `4.2.16.Final` counted as fixed by `4.1.137.Final` with
  `4.2.17.Final` still to come. A version must be at or above the fix on its
  own line, or above every fix.
- A prerelease above every fix no longer counts as fixed unless its major line
  had a release before it that no fix was listed for. close-fixed would have
  closed issues on netty `5.0.0.Alpha2` (from 2015) and spring `7.1.0-M2`
  (against `7.0.8`), neither known to include the fix; spring-boot `4.2.0-M2`
  against a fix in `3.0.0` still counts. `33.4.0-jre` and `4.1.42.Final` are
  releases.
  Auto-fix no longer reports such a prerelease as "already satisfied": it has
  no fix to move up to, so it stays pending with a warning to move it to a
  release by hand.
- close-fixed's log and closing comment give every release line's fix
  (`needs >= 4.1.137.Final or 4.2.17.Final`), not one of them.
- Node: pnpm/yarn/npm workspaces are understood. A workspace member is no
  longer audited as its own npm project — `npm install` there failed with
  EUNSUPPORTEDPROTOCOL on every `workspace:*`/`catalog:` specifier linking a
  sibling — it is SKIPped as covered by the root's audit, which reports the
  whole graph; the root dispatches to the workspace tool even before its
  lockfile exists (a root `packageManager` field is the tiebreaker), npm
  refuses any manifest with workspace-protocol specifiers even in a
  workspace outside the scanned tree, lockfiles a stray run creates inside a
  pnpm/yarn workspace are removed again so `--push` cannot commit them, and
  auto-fix counts `workspace:`/`catalog:` declarations as not-declared links
  rather than cannot-edit failures.

### Kept

- Every other option, its default and its meaning; the vulnerability database
  format; the PR and issue marker comments; the NVD single-refresh handling,
  timeouts, process-group kills, workspace guard, run lock and per-tool
  concurrency limits.
