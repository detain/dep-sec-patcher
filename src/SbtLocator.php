<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Which build.sbt files declare a library, for Mend issues that name no
 * dependency file: its sbt scans report only Ivy cache paths, but the
 * dependency hierarchy names the root library ("http4s-ember-client_3-0.23.26.jar"),
 * which a build.sbt declares as "org.http4s" %% "http4s-ember-client" % Http4sVersion.
 *
 * A declaration matches on the artifact (with the Scala binary suffix %%
 * adds, from the file's scalaVersion when it sets one) and, when its version
 * is a literal or a val defined in the same file, on the version too.
 */
final class SbtLocator
{
    /**
     * @param list<string>             $files every manifest path under the root, relative
     * @param callable(string): ?string $read  relative path => contents, null when unreadable
     */
    public function __construct(private array $files, private $read)
    {
    }

    /**
     * @param list<array{0: string, 1: string}> $libraries [file name stem, version], as IssueParser passes them
     * @return list<string> the build.sbt files declaring one of them (the first library any file declares)
     */
    public function __invoke(array $libraries): array
    {
        $builds = array_values(array_filter($this->files, static fn (string $f): bool => basename($f) === 'build.sbt'));
        foreach ($libraries as [$stem, $version]) {
            $found = [];
            foreach ($builds as $build) {
                $content = ($this->read)($build);
                if (is_string($content) && self::declares($content, $stem, $version)) {
                    $found[] = $build;
                }
            }
            if ($found !== []) {
                sort($found, SORT_STRING);
                return $found;
            }
        }
        return [];
    }

    /**
     * Whether a build.sbt declares the library Mend calls "$stem-$version.jar".
     */
    public static function declares(string $content, string $stem, string $version): bool
    {
        $content = (string)preg_replace('#//[^\n]*#', '', $content);
        $vals    = [];
        preg_match_all('/\b(?:lazy\s+)?val\s+(\w+)\s*(?::\s*String\s*)?=\s*"([^"]+)"/', $content, $mm, PREG_SET_ORDER);
        foreach ($mm as $m) {
            $vals[$m[1]] = $m[2];
        }
        $binary = preg_match('/scalaVersion\s*:=\s*"(\d+)\.(\d+)/', $content, $m) === 1 ? ($m[1] === '3' ? '3' : $m[1] . '.' . $m[2]) : '';
        preg_match_all('/"[^"]+"\s*(?<op>%%%?|%)\s*"(?<a>[^"]+)"\s*%\s*(?:"(?<v>[^"]+)"|(?<n>[A-Za-z_]\w*))/', $content, $deps, PREG_SET_ORDER);
        foreach ($deps as $d) {
            $names = $d['op'] === '%' ? [$d['a']] : ($binary !== '' ? [$d['a'] . '_' . $binary] : []);
            $named = in_array($stem, $names, true)
                || ($names === [] && preg_match('/^' . preg_quote($d['a'], '/') . '_(?:2\.1\d|3)$/', $stem) === 1);
            if (!$named) {
                continue;
            }
            $declared = ($d['v'] ?? '') !== '' ? $d['v'] : ($vals[$d['n'] ?? ''] ?? '');
            if ($declared === '' || $declared === $version) {
                return true;
            }
        }
        return false;
    }
}
