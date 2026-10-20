<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * pnpm, yarn and npm workspaces: which directory defines one, which
 * directories it claims, and which tool governs their lockfiles.
 *
 * A workspace installs and audits once, from its root: the root's lockfile
 * pins every member, and `pnpm audit` / `yarn audit` / `npm audit` there
 * reports the whole graph. A member is not a standalone npm project — its
 * `workspace:*` and `catalog:` specifiers link sibling packages and the
 * root's catalog, protocols npm fails every install of
 * (EUNSUPPORTEDPROTOCOL) — so the Node auditor asks this class before it
 * dispatches, and the guard removes lockfiles a fallback run created in a
 * directory whose locks belong to the workspace tool.
 */
final class NodeWorkspace
{
    /** Dependency specifiers that link inside the repository, not to the registry. */
    public const PROTOCOL_RX = '/^(?:workspace|catalog):/';

    /** Corepack's "packageManager" field: the manager name in front of its "@version". */
    public const MANAGER_RX = '/^(pnpm|yarn|npm)@/';

    /** The lockfile(s) each package manager owns. */
    public const MANAGER_LOCKS = [
        'npm'  => ['package-lock.json', 'npm-shrinkwrap.json'],
        'yarn' => ['yarn.lock'],
        'pnpm' => ['pnpm-lock.yaml'],
    ];

    /**
     * The workspace containing $dir (absolute, inside the scanned tree): the
     * root's absolute and scan-root-relative paths, the manager the root
     * dictates, and whether $dir is a member the root's globs claim (never
     * the root itself). Null when $dir is in no workspace rooted inside the
     * scanned tree — one rooted above it is outside what this run can see.
     *
     * @return array{root: string, rel: string, manager: string, member: bool}|null
     */
    public static function containing(string $scanRoot, string $dir): ?array
    {
        $scan = realpath($scanRoot);
        $abs  = realpath($dir);
        if ($scan === false || $abs === false || ($abs !== $scan && !str_starts_with($abs, $scan . '/'))) {
            return null;
        }
        $relOf = static fn (string $at): string => $at === $scan ? '' : substr($at, strlen($scan) + 1);

        if (self::defines($abs)) {
            return ['root' => $abs, 'rel' => $relOf($abs), 'manager' => self::rootManager($abs), 'member' => false];
        }
        for ($up = dirname($abs); $up === $scan || str_starts_with($up, $scan . '/'); $up = dirname($up)) {
            if (!self::defines($up)) {
                if ($up === $scan) {
                    break;
                }
                continue;
            }
            return [
                'root'    => $up,
                'rel'     => $relOf($up),
                'manager' => self::rootManager($up),
                'member'  => self::claims(self::patterns($up), substr($abs, strlen($up) + 1)),
            ];
        }
        return null;
    }

    /**
     * Whether $dir is a workspace root: a package.json (without one there is
     * no target to audit at the root) plus a pnpm-workspace.yaml or a
     * non-empty "workspaces" field.
     */
    public static function defines(string $dir): bool
    {
        if (!self::packageJson($dir) instanceof \stdClass) {
            return false;
        }
        return is_file($dir . '/pnpm-workspace.yaml') || self::patterns($dir) !== [];
    }

    /**
     * The manager a workspace root dictates: pnpm-workspace.yaml means pnpm;
     * a root lockfile means its manager; corepack's "packageManager" field
     * breaks the tie where neither leaves one; npm otherwise — npm and yarn
     * 1 workspaces keep their single lockfile at the root too.
     */
    public static function rootManager(string $root): string
    {
        if (is_file($root . '/pnpm-workspace.yaml')) {
            return 'pnpm';
        }
        foreach (['yarn' => 'yarn.lock', 'pnpm' => 'pnpm-lock.yaml'] as $manager => $lock) {
            if (is_file($root . '/' . $lock)) {
                return $manager;
            }
        }
        return self::declaredManager($root) ?? 'npm';
    }

    /**
     * The manager a directory's corepack "packageManager" field names
     * ("pnpm" of "pnpm@9.12.3"), or null when the field is absent or names
     * no manager this tool knows.
     */
    public static function declaredManager(string $dir): ?string
    {
        return preg_match(self::MANAGER_RX, self::packageManager($dir), $m) === 1 ? $m[1] : null;
    }

    /**
     * The corepack "packageManager" field of a package.json, or '' when absent.
     */
    public static function packageManager(string $dir): string
    {
        $pm = self::packageJson($dir)->packageManager ?? null;
        return is_string($pm) ? $pm : '';
    }

    /**
     * Member globs of a root: the `packages:` list of pnpm-workspace.yaml
     * and the "workspaces" field of package.json (a list, or the "packages"
     * list of its object form). '!pattern' entries are kept as given.
     *
     * @return list<string>
     */
    public static function patterns(string $root): array
    {
        $patterns = is_file($root . '/pnpm-workspace.yaml')
            ? self::yamlPackages((string)file_get_contents($root . '/pnpm-workspace.yaml'))
            : [];
        $workspaces = self::packageJson($root)->workspaces ?? null;
        if ($workspaces instanceof \stdClass && isset($workspaces->packages)) {
            $workspaces = $workspaces->packages;
        }
        foreach (is_array($workspaces) ? $workspaces : [] as $entry) {
            if (is_string($entry) && trim($entry) !== '') {
                $patterns[] = trim($entry);
            }
        }
        return $patterns;
    }

    /**
     * Whether the globs claim a member directory, $rel relative to the root:
     * exact paths, '*' within one path segment, '**' across segments, and
     * '!pattern' entries that reject — an exclusion beats every positive
     * match, the way pnpm and micromatch treat them whatever their order.
     *
     * @param list<string> $patterns
     */
    public static function claims(array $patterns, string $rel): bool
    {
        $claimed = $excluded = false;
        foreach ($patterns as $pattern) {
            $negate = str_starts_with($pattern, '!');
            $glob   = trim($negate ? substr($pattern, 1) : $pattern, '/');
            if ($glob === '' || preg_match(self::toRegex($glob), $rel) !== 1) {
                continue;
            }
            if ($negate) {
                $excluded = true;
            } else {
                $claimed = true;
            }
        }
        return $claimed && !$excluded;
    }

    /**
     * The `packages:` list of a pnpm-workspace.yaml, block or flow style,
     * negations included. Not a YAML parser: `packages:` is a list of
     * strings under the file's schema, and nothing else in it is read here.
     *
     * @return list<string>
     */
    public static function yamlPackages(string $content): array
    {
        $out   = [];
        $inKey = false;
        foreach (preg_split('/\r?\n/', $content) ?: [] as $line) {
            if (preg_match('/^packages:[ \t]*+(.*)$/', $line, $m) === 1) {
                $inKey  = true;
                $inline = trim((string)preg_replace('/\s+#.*$/', '', $m[1]));
                if ($inline !== '' && !in_array($inline, ['|', '>'], true)) {
                    foreach (explode(',', trim($inline, '[]')) as $token) {
                        $token = trim($token, " \t\"'");
                        if ($token !== '') {
                            $out[] = $token;
                        }
                    }
                }
                continue;
            }
            if (!$inKey) {
                continue;
            }
            if (preg_match('/^\s*+-[ \t]++(.+?)\s*$/', $line, $m) === 1) {
                $item  = trim((string)preg_replace('/\s+#.*$/', '', $m[1]), " \t\"'");
                $out[] = $item;
                continue;
            }
            if (trim($line) === '' || str_starts_with(trim($line), '#')) {
                continue;
            }
            $inKey = false; // the next top-level key ends the list
        }
        return $out;
    }

    /**
     * The first dependency in $dir/package.json npm cannot resolve: a
     * `workspace:` or `catalog:` specifier, as "name=spec"; '' when none.
     */
    public static function protocolSpecifier(string $dir): string
    {
        $doc = self::packageJson($dir);
        if (!$doc instanceof \stdClass) {
            return '';
        }
        foreach (['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as $section) {
            $deps = $doc->{$section} ?? null;
            if (!$deps instanceof \stdClass) {
                continue;
            }
            foreach (get_object_vars($deps) as $name => $spec) {
                if (is_string($spec) && preg_match(self::PROTOCOL_RX, $spec) === 1) {
                    return $name . '=' . $spec;
                }
            }
        }
        return '';
    }

    /**
     * Every lockfile any supported node package manager owns.
     *
     * @return list<string>
     */
    public static function lockfiles(): array
    {
        return array_merge(...array_values(self::MANAGER_LOCKS));
    }

    private static function packageJson(string $dir): ?\stdClass
    {
        $file = $dir . '/package.json';
        if (!is_file($file)) {
            return null;
        }
        try {
            $doc = JsonFile::decodeObject((string)file_get_contents($file));
        } catch (\JsonException $e) {
            return null;
        }
        return $doc instanceof \stdClass ? $doc : null;
    }

    private static function toRegex(string $glob): string
    {
        $rx  = '';
        $len = strlen($glob);
        for ($i = 0; $i < $len; $i++) {
            $char = $glob[$i];
            if ($char === '?') {
                $rx .= '[^\/]';
                continue;
            }
            if ($char !== '*') {
                $rx .= preg_quote($char, '/');
                continue;
            }
            if ($i + 1 < $len && $glob[$i + 1] === '*') {
                $i++; // '**' spans directory separators...
                // ..."a/**/b" including the gap: it also matches "a/b", so the separator goes with it
                if ($i + 1 < $len && $glob[$i + 1] === '/') {
                    $i++;
                    $rx .= '(?:[^\/]+\/)*';
                } else {
                    $rx .= '.*';
                }
                continue;
            }
            $rx .= '[^\/]*'; // a single star stays inside one segment
        }
        return '/^' . $rx . '$/';
    }
}
