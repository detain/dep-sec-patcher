<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use JsonException;

/**
 * Reads and rewrites the version a manifest declares for one package.
 *
 * declared() is the inverse of apply(): it is what lets a fix be skipped as
 * already satisfied, and an issue be closed on evidence rather than on the
 * assumption that an earlier run worked.
 *
 * Package names and versions come from issue bodies written by third-party
 * bots, so they only ever reach a regex through preg_quote().
 *
 * Pure: content in, content out.
 */
final class ManifestEditor
{
    public const OK        = 'ok';
    public const REFUSED   = 'refused';      // would move a declared version backwards
    public const UNSUPPORTED = 'unsupported'; // file type or package shape not handled
    public const INTERNAL  = 'internal';     // workspace:/catalog: link: no upstream version to bump

    /** What a version written into a manifest may look like: no quotes, spaces or code. */
    private const VERSION_RX = '/^[0-9A-Za-z][0-9A-Za-z.+_~-]*$/';
    /** npm (@scope/name), Maven (group:artifact), Go module paths, PyPI, NuGet, gems, crates. */
    private const PACKAGE_RX = '#^[A-Za-z0-9@_][A-Za-z0-9@/._:+~-]*$#';
    private const NPM_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

    /**
     * @return array{status: string, content: string}
     */
    public static function apply(
        string $ecosystem,
        string $path,
        string $content,
        string $pkg,
        string $version,
        string $globalMax = '',
        bool $hasYarnLock = false,
        bool $hasNpmLock = false,
        bool $allowDowngrade = false
    ): array {
        // Both come from advisory feeds and bot-written issue bodies: anything
        // that is not plainly a name or a version never reaches a manifest
        if (preg_match(self::PACKAGE_RX, $pkg) !== 1 || preg_match(self::VERSION_RX, $version) !== 1
            || ($globalMax !== '' && preg_match(self::VERSION_RX, $globalMax) !== 1)) {
            return ['status' => self::UNSUPPORTED, 'content' => $content];
        }
        try {
            return self::dispatch(self::ecosystem($ecosystem, $path), $path, $content, $pkg, $version, $globalMax, $hasYarnLock, $hasNpmLock, $allowDowngrade);
        } catch (\RuntimeException $e) {
            // A regex that blew its backtrack limit returns null; writing that
            // back would empty the manifest, so leave the file untouched
            return ['status' => self::UNSUPPORTED, 'content' => $content];
        }
    }

    /**
     * @return array{status: string, content: string}
     */
    private static function dispatch(
        string $ecosystem,
        string $path,
        string $content,
        string $pkg,
        string $version,
        string $globalMax,
        bool $hasYarnLock,
        bool $hasNpmLock,
        bool $allowDowngrade
    ): array {
        switch ($ecosystem) {
            case 'npm':
                return self::applyNpm($content, $pkg, $version, $globalMax !== '' ? $globalMax : $version, $hasYarnLock, $hasNpmLock);
            case 'composer':
                return self::applyComposer($content, $pkg, $version);
            case 'pip':
                return self::applyPip(basename($path), $content, $pkg, $version);
            case 'maven':
                // The hard downgrade guard: a fix that compares below the
                // version the pom declares (guava 28.1-jre -> r09) is a bad
                // candidate, not an upgrade, whatever the ordering above
                // believed. Only the deliberate prerelease-to-release channel
                // (allowDowngrade, maven-only) may move a version back.
                $declared = self::declaredMaven($content, $pkg);
                if (!$allowDowngrade && $declared !== '' && !str_contains($declared, '$')
                    && preg_match(self::VERSION_RX, $declared) === 1 && preg_match('/[0-9]/', $declared) === 1
                    && Version::compareMaven($version, $declared) < 0) {
                    return ['status' => self::REFUSED, 'content' => $content];
                }
                return self::ok(self::applyMaven($content, $pkg, $version));
            case 'gradle':
                if (!str_contains($pkg, ':')) {
                    return ['status' => self::UNSUPPORTED, 'content' => $content];
                }
                [$g, $a] = self::splitCoordinate($pkg);
                return self::ok(self::eachLine($content, static function (string $line) use ($g, $a, $version): string {
                    $rx = '/(["\'])' . preg_quote($g, '/') . ':' . preg_quote($a, '/') . ':[^"\']+\1/';
                    return self::sub($rx, static fn ($m) => $m[1] . "{$g}:{$a}:{$version}" . $m[1], $line);
                }));
            case 'go':
                // Exact module-path match only: bot-derived short names such as
                // "net" must never be allowed to rewrite golang.org/x/net. Only
                // require lines: an exclude or replace line naming the module
                // must keep its version
                $v = str_starts_with($version, 'v') ? $version : 'v' . $version;
                return self::ok(self::eachGoRequire($content, static function (string $line) use ($pkg, $v): string {
                    $rx = '/^(\s*(?:require\s+)?)' . preg_quote($pkg, '/') . '(\s+)(v[^\s\/]+)(.*)$/';
                    return self::sub($rx, static function ($m) use ($pkg, $v): string {
                        // A v2+ module without a /vN path keeps its +incompatible marker
                        $new = str_ends_with($m[3], '+incompatible') && !str_contains($v, '+') ? $v . '+incompatible' : $v;
                        return $m[1] . $pkg . $m[2] . $new . $m[4];
                    }, $line, 1);
                }));
            case 'hex':
                return self::ok(self::eachLine($content, static function (string $line) use ($pkg, $version): string {
                    $rx = '/(\{\s*:' . preg_quote($pkg, '/') . '\s*,\s*")[^"]*(")/';
                    return self::sub($rx, static fn ($m) => $m[1] . '~> ' . $version . $m[2], $line);
                }));
            case 'nuget':
                return self::ok(self::applyNuget($content, $pkg, $version));
            case 'pub':
                $section = '';
                return self::ok(self::eachLine($content, static function (string $line) use ($pkg, $version, &$section): string {
                    if (preg_match('/^(\S[^:]*):/', $line, $sm) === 1) {
                        $section = $sm[1];
                    }
                    if (!in_array($section, ['dependencies', 'dev_dependencies', 'dependency_overrides'], true)) {
                        return $line;
                    }
                    // A first-level entry only, never a nested "path:" or "version:" key
                    $rx = '/^( {2}|\t)(' . preg_quote($pkg, '/') . ':\s*)[\^~<>=0-9"\'].*$/';
                    return self::sub($rx, static fn ($m) => $m[1] . $m[2] . '^' . $version, $line, 1);
                }));
            case 'rubygems':
                return self::ok(self::eachLine($content, static function (string $line) use ($pkg, $version): string {
                    $rx = '/^(\s*gem\s+["\']' . preg_quote($pkg, '/') . '["\']\s*,\s*["\'])[^"\']*(["\'])/';
                    return self::sub($rx, static fn ($m) => $m[1] . '~> ' . $version . $m[2], $line, 1);
                }));
            case 'cargo':
                return self::ok(self::eachLine($content, static function (string $line) use ($pkg, $version): string {
                    $q    = preg_quote($pkg, '/');
                    $line = self::sub('/^(\s*' . $q . '\s*=\s*")[^"]*(")/', static fn ($m) => $m[1] . $version . $m[2], $line, 1);
                    return self::sub('/^(\s*' . $q . '\s*=\s*\{[^}]*?version\s*=\s*")[^"]*(")/', static fn ($m) => $m[1] . $version . $m[2], $line, 1);
                }));
            default:
                return ['status' => self::UNSUPPORTED, 'content' => $content];
        }
    }

    /**
     * The version a manifest declares for a package, or '' when it is not
     * declared there.
     */
    public static function declared(string $ecosystem, string $path, string $content, string $pkg): string
    {
        switch (self::ecosystem($ecosystem, $path)) {
            case 'npm':
                $doc = self::decode($content);
                foreach (array_merge(self::NPM_SECTIONS, ['overrides', 'resolutions']) as $section) {
                    $value = $doc->{$section}->{$pkg} ?? null;
                    if ($value !== null && $value !== false) {
                        return self::tostring($value);
                    }
                }
                return '';
            case 'composer':
                $doc = self::decode($content);
                foreach (['require', 'require-dev'] as $section) {
                    $value = $doc->{$section}->{$pkg} ?? null;
                    if ($value !== null && $value !== false) {
                        return self::tostring($value);
                    }
                }
                return '';
            case 'pip':
                // The whole specifier, so Version::floor can tell "<2" (no
                // lower bound) from ">=2"; the name must end where the
                // package's does, or "boto" would read "boto3==1.26.0"
                $clause = '[=<>!~^]=?\s*[^",;#\s]+';
                $rx = '/^\s*"?' . self::pypiPattern($pkg) . '(?![A-Za-z0-9._-])"?\s*(?:\[[^\]]*\])?\s*(?:=\s*")?\s*'
                    . '(' . $clause . '(?:\s*,\s*' . $clause . ')*|[0-9][^",;\s]*)/i';
                return self::firstLineMatch($content, $rx);
            case 'maven':
                return self::declaredMaven($content, $pkg);
            case 'gradle':
                if (!str_contains($pkg, ':')) {
                    return '';
                }
                [$g, $a] = self::splitCoordinate($pkg);
                return self::firstLineMatch($content, '/["\']' . preg_quote($g, '/') . ':' . preg_quote($a, '/') . ':([^"\']+)["\']/');
            case 'go':
                $found = '';
                self::eachGoRequire($content, static function (string $line) use ($pkg, &$found): string {
                    if ($found === '' && preg_match('/^\s*(?:require\s+)?' . preg_quote($pkg, '/') . '\s+v(\S+)/', $line, $m) === 1) {
                        $found = (string)preg_replace('/\+incompatible$/', '', $m[1]);
                    }
                    return $line;
                });
                return $found;
            case 'hex':
                return self::firstLineMatch($content, '/\{\s*:' . preg_quote($pkg, '/') . '\s*,\s*"[^0-9"]*([0-9][^"]*)"/');
            case 'nuget':
                $q = preg_quote($pkg, '/');
                foreach ([
                    '/<PackageReference\s+Include="' . $q . '"[^>]*?\sVersion="([^"]*)"/is',
                    '/<dependency\s+id="' . $q . '"[^>]*?\sversion="([^"]*)"/is',
                    '/<package\s+id="' . $q . '"[^>]*?\sversion="([^"]*)"/is',
                ] as $rx) {
                    if (preg_match($rx, $content, $m) === 1) {
                        return $m[1];
                    }
                }
                return '';
            case 'pub':
                return self::firstLineMatch($content, '/^\s+' . preg_quote($pkg, '/') . ':\s*\S*?([0-9][0-9A-Za-z.+-]*)/');
            case 'rubygems':
                return self::firstLineMatch($content, '/^\s*gem\s+["\']' . preg_quote($pkg, '/') . '["\']\s*,\s*["\'][^0-9"\']*([0-9][^"\']*)["\']/');
            case 'cargo':
                $q = preg_quote($pkg, '/');
                foreach (self::lines($content) as $line) {
                    if (preg_match('/^\s*' . $q . '\s*=\s*"([^"]*)"/', $line, $m) === 1
                        || preg_match('/^\s*' . $q . '\s*=\s*\{[^}]*?version\s*=\s*"([^"]*)"/', $line, $m) === 1) {
                        return $m[1];
                    }
                }
                return '';
            default:
                return '';
        }
    }

    // ── npm / composer ───────────────────────────────────────────────────────

    /**
     * @return array{status: string, content: string}
     */
    private static function applyNpm(string $content, string $pkg, string $version, string $globalMax, bool $hasYarnLock, bool $hasNpmLock): array
    {
        $doc = self::decode($content);
        if (!$doc instanceof \stdClass) {
            return ['status' => self::UNSUPPORTED, 'content' => $content];
        }

        $section  = null;
        $declared = '';
        foreach (self::NPM_SECTIONS as $name) {
            if (isset($doc->{$name}) && $doc->{$name} instanceof \stdClass && property_exists($doc->{$name}, $pkg)) {
                $section  = $name;
                $declared = self::tostring($doc->{$name}->{$pkg});
                break;
            }
        }

        if ($section !== null) {
            if (self::npmWildcard($declared)) {
                // "*" already admits the fix; give it a floor and keep it open-ended
                $doc->{$section}->{$pkg} = '>=' . $version;
                return self::ok(JsonFile::encode($doc, JsonFile::detectIndent($content)), $content, $doc);
            }
            // A workspace-protocol specifier links the package to a sibling
            // or the root's catalog: the version lives in that package, not
            // here, and rewriting the link would break it
            if (preg_match(NodeWorkspace::PROTOCOL_RX, $declared) === 1) {
                return ['status' => self::INTERNAL, 'content' => $content];
            }
            // A git/file/alias spec or a tag names no registry version to
            // bump, and one version cannot replace every alternative of a union
            if (Version::isUnion($declared) || preg_match('/^[\s0-9A-Za-z.^~<>=*+-]+$/', $declared) !== 1
                || preg_match('/[0-9]/', $declared) !== 1) {
                return ['status' => self::UNSUPPORTED, 'content' => $content];
            }
            // Refuse to move a declared dependency backwards. Advisory feeds list
            // the fix for the branch the CVE was filed against, which for an old
            // CVE can be far below what the project uses (express 4.0.0 vs ^4.16.0).
            $floor = Version::floor($declared);
            if ($floor !== '' && $floor !== $version && Version::gte($floor, $version)) {
                return ['status' => self::REFUSED, 'content' => $content];
            }
            // Bump in place, keeping its ^ / ~ / >= range style
            $prefix = preg_match('/^(\^|~|>=)\s*/', trim($declared), $m) === 1 ? trim($m[1]) : '';
            $doc->{$section}->{$pkg} = $prefix . $version;
            return self::ok(JsonFile::encode($doc, JsonFile::detectIndent($content)), $content, $doc);
        }

        // Transitive: pin it package-wide, the only way to force a nested
        // version without touching the upstream package. A caret range keeps
        // later patch and minor releases flowing; the caller picks the
        // version on the release line the lockfile holds. npm reads
        // "overrides", yarn "resolutions".
        $pin = '^' . $globalMax;
        if ($hasNpmLock || !$hasYarnLock) {
            $doc->overrides = self::withKey($doc->overrides ?? null, $pkg, $pin);
        }
        if ($hasYarnLock) {
            $doc->resolutions = self::withKey($doc->resolutions ?? null, $pkg, $pin);
        }
        return self::ok(JsonFile::encode($doc, JsonFile::detectIndent($content)), $content, $doc);
    }

    /**
     * An npm range that admits any version: "*", "x", "", "latest", "^*".
     */
    private static function npmWildcard(string $spec): bool
    {
        return preg_match('/^\s*(?:[\^~]|>=\s*)?(?:\*|x|X|latest|0|0\.0\.0)?\s*$/', $spec) === 1;
    }

    /**
     * @return array{status: string, content: string}
     */
    private static function applyComposer(string $content, string $pkg, string $version): array
    {
        $doc = self::decode($content);
        if (!$doc instanceof \stdClass) {
            return ['status' => self::UNSUPPORTED, 'content' => $content];
        }
        $declared = self::declared('composer', 'composer.json', $content, $pkg);
        $wildcard = preg_match('/^\s*\*?\s*$/', $declared) === 1;
        if ($declared !== '' && !$wildcard) {
            // Branch names ("dev-master") have no version to compare, and one
            // version cannot replace every alternative of a union
            if (Version::isUnion($declared) || preg_match('/[0-9]/', $declared) !== 1 || str_contains($declared, 'dev-')) {
                return ['status' => self::UNSUPPORTED, 'content' => $content];
            }
            $floor = Version::floor($declared);
            if ($floor !== '' && $floor !== $version && Version::gte($floor, $version)) {
                return ['status' => self::REFUSED, 'content' => $content];
            }
        }
        // The original shell script looked up require-dev as `.[".require-dev"]` (note
        // the stray dot), so dev requirements were never bumped
        foreach (['require', 'require-dev'] as $section) {
            if (isset($doc->{$section}) && $doc->{$section} instanceof \stdClass && property_exists($doc->{$section}, $pkg)) {
                // "*" stays open-ended, with the fix as its floor
                $doc->{$section}->{$pkg} = ($wildcard ? '>=' : '^') . $version;
                return self::ok(JsonFile::encode($doc, JsonFile::detectIndent($content)), $content, $doc);
            }
        }
        return ['status' => self::OK, 'content' => $content];
    }

    // ── pip ──────────────────────────────────────────────────────────────────

    /**
     * @return array{status: string, content: string}
     */
    private static function applyPip(string $base, string $content, string $pkg, string $version): array
    {
        $rx = self::pypiPattern($pkg);
        if ($base === 'pyproject.toml' || $base === 'Pipfile') {
            // TOML tables ( pytest = ">= 8.4.2" ): the requirements-style
            // rewrite would emit `pytest==9.0.3`, which is not valid TOML, so
            // keep the key and quoting and swap only the specifier
            return self::ok(self::eachLine($content, static function (string $line) use ($rx, $pkg, $version): string {
                $line = self::sub(
                    '/^(\s*"?' . $rx . '"?\s*=\s*")([<>=~^!\s]*)[0-9][^"]*(")/i',
                    static fn ($m) => $m[1] . ($m[2] === '' ? '>=' : $m[2]) . $version . $m[3],
                    $line,
                    1
                );
                // "pytest>=8.4.2",  ->  "pytest>=9.0.3",   (PEP 621 array entry)
                return self::sub(
                    '/^(\s*")' . $rx . '([<>=~!]+)[0-9][^"]*(")/i',
                    static fn ($m) => $m[1] . $pkg . $m[2] . $version . $m[3],
                    $line,
                    1
                );
            }));
        }
        if (preg_match('/requirements.*\.txt$|constraints.*\.txt$/', $base) !== 1) {
            return ['status' => self::UNSUPPORTED, 'content' => $content];
        }
        // pip checks --hash pins against the downloaded file; the old hashes
        // cannot match a new version, so a hashed file is left to its tool
        if (preg_match('/--hash[=\s]/', $content) === 1) {
            return ['status' => self::UNSUPPORTED, 'content' => $content];
        }
        return self::ok(self::eachLine($content, static function (string $line) use ($rx, $pkg, $version): string {
            // name [extras] specifier ; marker  # comment: only the specifier changes
            $re = '/^([ \t]*)' . $rx . '(?![A-Za-z0-9._-])[ \t]*(\[[^\]]*\])?[ \t]*(?:[=<>!~][^;#\r\n]*?)?'
                . '([ \t]*(?:;[^#\r\n]*)?(?:#[^\r\n]*)?)(\r?\n)?$/iD';
            if (preg_match($re, $line, $m) === 1) {
                return $m[1] . $pkg . $m[2] . '==' . $version . $m[3] . ($m[4] ?? '');
            }
            return $line;
        }));
    }

    /**
     * PyPI names are case-insensitive and treat - _ . as equivalent.
     */
    private static function pypiPattern(string $pkg): string
    {
        return (string)preg_replace('/\\\\?[-_.]/', '[-_.]', preg_quote($pkg, '/'));
    }

    // ── maven ────────────────────────────────────────────────────────────────

    /**
     * Pattern matching a <dependency> block for the coordinate, up to and
     * including its "<version>" opening tag and any whitespace after it.
     */
    private static function mavenDependencyPattern(string $pkg): string
    {
        [$g, $a] = self::splitCoordinate($pkg);
        $blk = '(?:(?!<\/dependency>).)*?';
        // Advisory feeds often name only the artifact ("jackson-databind");
        // within a single pom a bare artifactId is effectively unique
        return $g !== ''
            ? '<dependency>' . $blk . '<groupId>\s*' . preg_quote($g, '#') . '\s*<\/groupId>' . $blk
                . '<artifactId>\s*' . preg_quote($a, '#') . '\s*<\/artifactId>' . $blk . '<version>\s*'
            : '<dependency>' . $blk . '<artifactId>\s*' . preg_quote($a, '#') . '\s*<\/artifactId>' . $blk . '<version>\s*';
    }

    private static function applyMaven(string $content, string $pkg, string $version): string
    {
        [$g, $a] = self::splitCoordinate($pkg);
        $dep     = self::mavenDependencyPattern($pkg);
        $xmlv    = htmlspecialchars($version, ENT_XML1);
        $changed = 0;

        // Literal <version>: [^<$] keeps this off ${property} references
        $content = self::sub(
            '#(' . $dep . ')([^<$]*?)(\s*<\/version>)#s',
            static fn ($m) => $m[1] . $xmlv . $m[3],
            $content,
            -1,
            $count
        );
        $changed += $count;

        // ${property} indirection: bump the property definition, not the reference
        preg_match_all('#' . $dep . '\$\{([^<]+?)\}\s*<\/version>#s', $content, $props);
        foreach ($props[1] as $prop) {
            $q       = preg_quote($prop, '#');
            $content = self::sub(
                '#(<' . $q . '>)[^<]*(<\/' . $q . '>)#s',
                static fn ($m) => $m[1] . $xmlv . $m[2],
                $content,
                -1,
                $count
            );
            $changed += $count;
        }

        // Nothing declared: the vulnerability is transitive. <dependencyManagement>
        // pins the version for the whole graph without adding a direct
        // dependency, Maven's equivalent of an npm override. It needs a real
        // groupId, so a bare artifact name is left alone rather than guessed at.
        if ($changed === 0 && $g !== '') {
            $entry = "<dependency>\n        <groupId>" . htmlspecialchars($g, ENT_XML1) . "</groupId>\n"
                . '        <artifactId>' . htmlspecialchars($a, ENT_XML1) . "</artifactId>\n"
                . "        <version>{$xmlv}</version>\n      </dependency>";
            if (preg_match('#<dependencyManagement>\s*<dependencies>#s', $content) === 1) {
                $content = self::sub(
                    '#(<dependencyManagement>\s*<dependencies>)#s',
                    static fn ($m) => $m[1] . "\n      " . $entry,
                    $content,
                    1
                );
            } else {
                $content = self::sub(
                    '#(\s*<\/project>\s*)$#s',
                    static fn ($m) => "\n  <dependencyManagement>\n    <dependencies>\n      {$entry}\n    </dependencies>\n  </dependencyManagement>" . $m[1],
                    $content,
                    1
                );
            }
        }
        return $content;
    }

    private static function declaredMaven(string $content, string $pkg): string
    {
        if (preg_match('#' . self::mavenDependencyPattern($pkg) . '([^<]*?)\s*<#s', $content, $m) !== 1) {
            return '';
        }
        $v = $m[1];
        // follow a ${property} reference to its definition
        if (preg_match('/^\$\{([^}]+)\}$/', $v, $pm) === 1) {
            $q = preg_quote($pm[1], '/');
            if (preg_match('/<' . $q . '>\s*([^<]*?)\s*<\/' . $q . '>/', $content, $dm) === 1) {
                $v = $dm[1];
            }
        }
        return $v;
    }

    // ── nuget ────────────────────────────────────────────────────────────────

    /**
     * csproj/fsproj use <PackageReference Include=".." Version=".." />, a
     * .nuspec <dependency id=".." version=".." />, packages.config
     * <package id=".." version=".." />; either attribute order.
     */
    private static function applyNuget(string $content, string $pkg, string $version): string
    {
        $q = preg_quote($pkg, '/');
        foreach ([
            '/(<PackageReference\s+Include="' . $q . '"[^>]*?\sVersion=")[^"]*(")/is',
            '/(<PackageReference\s+Version=")[^"]*("[^>]*?\sInclude="' . $q . '")/is',
            '/(<dependency\s+id="' . $q . '"[^>]*?\sversion=")[^"]*(")/is',
            '/(<dependency\s+version=")[^"]*("[^>]*?\sid="' . $q . '")/is',
            '/(<package\s+id="' . $q . '"[^>]*?\sversion=")[^"]*(")/is',
        ] as $rx) {
            $content = self::sub($rx, static fn ($m) => $m[1] . $version . $m[2], $content);
        }
        return $content;
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /**
     * The editor for a manifest is decided by the file, not by the record's
     * ecosystem name: GitHub reports Cargo as "rust", Mix as "erlang" and
     * Gradle builds as "maven".
     */
    private static function ecosystem(string $ecosystem, string $path): string
    {
        $byFile = ManifestPaths::ecosystemFor($path);
        if ($byFile !== 'unknown') {
            return $byFile;
        }
        return match (strtolower($ecosystem)) {
            'rust'   => 'cargo',
            'erlang' => 'hex',
            'pypi'   => 'pip',
            default  => strtolower($ecosystem),
        };
    }

    /**
     * eachLine() over a go.mod, applying $fn only to require lines: a
     * `require x v1` line, or a line inside a `require (...)` block.
     */
    private static function eachGoRequire(string $content, callable $fn): string
    {
        $block = '';
        $out   = '';
        foreach (self::lines($content) as $line) {
            $trim = trim($line);
            if ($block !== '') {
                if ($trim === ')') {
                    $block = '';
                } elseif ($block === 'require') {
                    $line = $fn($line);
                }
            } elseif (preg_match('/^(\w+)\s*\($/', $trim, $m) === 1) {
                $block = $m[1];
            } elseif (str_starts_with($trim, 'require ')) {
                $line = $fn($line);
            }
            $out .= $line;
        }
        return $out;
    }

    /**
     * preg_replace_callback that throws instead of returning null on a PCRE
     * error (backtrack/JIT limits), so a failure can never blank a manifest.
     *
     * @param-out int $count
     */
    private static function sub(string $rx, callable $fn, string $subject, int $limit = -1, ?int &$count = null): string
    {
        $out = preg_replace_callback($rx, $fn, $subject, $limit, $count);
        if ($out === null) {
            throw new \RuntimeException('regex failed: ' . preg_last_error_msg());
        }
        return $out;
    }

    /**
     * @return array{0: string, 1: string} groupId ('' when absent), artifactId
     */
    private static function splitCoordinate(string $pkg): array
    {
        if (!str_contains($pkg, ':')) {
            return ['', $pkg];
        }
        $first = strpos($pkg, ':');
        $last  = strrpos($pkg, ':');
        return [substr($pkg, 0, (int)$first), substr($pkg, (int)$last + 1)];
    }

    /**
     * Apply a per-line transform, the way `perl -pe` did: each line keeps its
     * own trailing newline so `$` anchors before it.
     */
    private static function eachLine(string $content, callable $fn): string
    {
        $out = '';
        foreach (self::lines($content) as $line) {
            $out .= $fn($line);
        }
        return $out;
    }

    /**
     * @return list<string> lines including their "\n"
     */
    private static function lines(string $content): array
    {
        if ($content === '') {
            return [];
        }
        return preg_split('/(?<=\n)/', $content, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    private static function firstLineMatch(string $content, string $rx): string
    {
        foreach (self::lines($content) as $line) {
            if (preg_match($rx, $line, $m) === 1) {
                return $m[1];
            }
        }
        return '';
    }

    private static function decode(string $content): mixed
    {
        try {
            return JsonFile::decodeObject($content);
        } catch (JsonException $e) {
            return null;
        }
    }

    /**
     * jq `tostring`: strings verbatim, anything else as JSON.
     */
    private static function tostring(mixed $value): string
    {
        return is_string($value) ? $value : (string)json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * jq `(.obj // {}) + {key: value}`: replace in place, or append.
     */
    private static function withKey(mixed $obj, string $key, string $value): \stdClass
    {
        $obj = $obj instanceof \stdClass ? $obj : new \stdClass();
        $obj->{$key} = $value;
        return $obj;
    }

    /**
     * @return array{status: string, content: string}
     */
    private static function ok(string $content, ?string $original = null, mixed $doc = null): array
    {
        // A JSON rewrite that changes no value must not reformat the file
        if ($original !== null && $doc !== null && self::decode($original) == $doc) {
            return ['status' => self::OK, 'content' => $original];
        }
        return ['status' => self::OK, 'content' => $content];
    }
}
