<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Auditor;

use Detain\DepSecPatcher\Version;

/**
 * The version sites of a pom.xml, read and rewritten as text so an edit
 * leaves the rest of the file (formatting, comments) exactly as it was.
 *
 * A site is a <properties> entry or the <version> of a <dependency>,
 * <plugin>, <extension> or <parent> block; a version given as ${name}
 * makes that block a user of the property.
 *
 * Pure: content in, content out.
 */
final class MavenPom
{
    private const BLOCK_RX = '#<(dependency|plugin|parent|extension)>((?:(?!</\1>).)*)</\1>#s';

    /**
     * @return array{props: array<string, string>, lits: array<string, string>, refs: array<string, list<string>>}
     *         property => value, groupId:artifactId => literal version, property => the groupId:artifactIds using it
     */
    public static function sites(string $content): array
    {
        $props = [];
        if (preg_match_all('#<properties>(.*?)</properties>#s', $content, $blocks) > 0) {
            foreach ($blocks[1] as $block) {
                preg_match_all('#<([A-Za-z_][\w.-]*)>\s*([^<]*?)\s*</\1>#s', $block, $m, PREG_SET_ORDER);
                foreach ($m as $p) {
                    $props[$p[1]] ??= $p[2];
                }
            }
        }
        $lits = $refs = [];
        foreach (self::blocks($content) as [$ga, $version]) {
            if (preg_match('/^\$\{([^}]+)\}$/', $version, $m) === 1) {
                $refs[$m[1]][] = $ga;
            } elseif ($version !== '' && !str_contains($version, '${')) {
                $lits[$ga] ??= $version;
            }
        }
        foreach ($refs as $p => $users) {
            $refs[$p] = array_values(array_unique($users));
        }
        return ['props' => $props, 'lits' => $lits, 'refs' => $refs];
    }

    /**
     * Set property $name from $from to $to (only where it holds $from).
     */
    public static function setProperty(string $content, string $name, string $from, string $to): string
    {
        $q = preg_quote($name, '#');
        return (string)preg_replace_callback(
            '#(<' . $q . '>\s*)' . preg_quote($from, '#') . '(\s*</' . $q . '>)#',
            static fn (array $m): string => $m[1] . htmlspecialchars($to, ENT_XML1) . $m[2],
            $content
        );
    }

    /**
     * Set the literal <version> of the groupId:artifactId blocks holding $from to $to.
     */
    public static function setVersion(string $content, string $ga, string $from, string $to): string
    {
        return (string)preg_replace_callback(self::BLOCK_RX, static function (array $m) use ($ga, $from, $to): string {
            [$own, $version] = self::identify($m[1], $m[2]);
            if ($own !== $ga || $version !== $from) {
                return $m[0];
            }
            $count = 0;
            $body  = (string)preg_replace('#(<version>\s*)' . preg_quote($from, '#') . '(\s*</version>)#', '${1}' . htmlspecialchars($to, ENT_XML1) . '${2}', $m[2], 1, $count);
            return '<' . $m[1] . '>' . $body . '</' . $m[1] . '>';
        }, $content);
    }

    /**
     * The groupId:artifactId of the pom's own <project>, '' when unreadable.
     */
    public static function coordinate(string $content): string
    {
        // The project's own elements, with the blocks naming other artifacts taken out
        $own = (string)preg_replace(['#<(parent|dependencies|dependencyManagement|build|profiles|reporting|modules|properties|distributionManagement|repositories|pluginRepositories)>.*?</\1>#s'], '', $content);
        $parent = preg_match('#<parent>.*?<groupId>\s*([^<]+?)\s*</groupId>#s', $content, $pm) === 1 ? $pm[1] : '';
        $g = preg_match('#<groupId>\s*([^<]+?)\s*</groupId>#', $own, $gm) === 1 ? $gm[1] : $parent;
        $a = preg_match('#<artifactId>\s*([^<]+?)\s*</artifactId>#', $own, $am) === 1 ? $am[1] : '';
        return $g !== '' && $a !== '' ? $g . ':' . $a : '';
    }

    /**
     * The versions a maven-metadata.xml lists.
     *
     * @return list<string>
     */
    public static function metadataVersions(string $xml): array
    {
        preg_match_all('#<version>\s*([^<\s]+)\s*</version>#', (string)preg_replace('#^.*?<versions>|</versions>.*$#s', '', $xml), $m);
        return array_values(array_unique($m[1]));
    }

    /**
     * The newest release in $versions above $current, on $current's major
     * line unless $anyMajor, and at least every $floors bound ('>=' version)
     * and above every $above bound; '' when none qualifies. Ordered with
     * Maven's rules (Version::compareMaven), and preferring versions that
     * share $current's qualifier family: from guava 28.1-jre the -jre line,
     * never the lettered r09, which byte ordering ranked above everything.
     *
     * @param list<string> $versions
     * @param list<string> $floors
     * @param list<string> $above
     */
    public static function newestOnLine(array $versions, string $current, bool $anyMajor, array $floors = [], array $above = []): string
    {
        $line   = Version::majorLine($current);
        $family = Version::familySuffix($current);
        $ok     = array_values(array_filter($versions, static function (string $v) use ($current, $line, $anyMajor, $floors, $above): bool {
            if (Version::isPrerelease($v) || !Version::gteMaven($v, $current) || $v === $current) {
                return false;
            }
            if (!$anyMajor && Version::majorLine($v) !== $line) {
                return false;
            }
            foreach ($floors as $f) {
                if (!Version::gteMaven($v, $f)) {
                    return false;
                }
            }
            foreach ($above as $f) {
                if (Version::gteMaven($f, $v)) {
                    return false;
                }
            }
            return true;
        }));
        if ($family !== '') {
            $same   = array_values(array_filter($ok, static fn (string $v): bool => Version::familySuffix($v) === $family));
            $ok     = $same !== [] ? $same : $ok;
        }
        return Version::maxMaven($ok);
    }

    /**
     * groupId:artifactId => version of each block.
     *
     * @return list<array{string, string}>
     */
    private static function blocks(string $content): array
    {
        preg_match_all(self::BLOCK_RX, $content, $m, PREG_SET_ORDER);
        $out = [];
        foreach ($m as $b) {
            [$ga, $version] = self::identify($b[1], $b[2]);
            if ($ga !== '') {
                $out[] = [$ga, $version];
            }
        }
        // A plugin's own <dependencies> are blocks of their own
        foreach ($m as $b) {
            if ($b[1] === 'plugin' && preg_match('#<dependencies>(.*)</dependencies>#s', $b[2], $inner) === 1) {
                $out = array_merge($out, self::blocks($inner[1]));
            }
        }
        return $out;
    }

    /**
     * @return array{string, string} groupId:artifactId ('' when it names none), version
     */
    private static function identify(string $tag, string $body): array
    {
        // Only the block's own coordinates: not a plugin's dependencies or
        // configuration, nor a dependency's exclusions
        $head = (string)preg_replace('#<(configuration|dependencies|executions|exclusions)>.*$#s', '', $body);
        $g = preg_match('#<groupId>\s*([^<]+?)\s*</groupId>#', $head, $gm) === 1 ? $gm[1] : ($tag === 'plugin' ? 'org.apache.maven.plugins' : '');
        $a = preg_match('#<artifactId>\s*([^<]+?)\s*</artifactId>#', $head, $am) === 1 ? $am[1] : '';
        $v = preg_match('#<version>\s*([^<]*?)\s*</version>#', $head, $vm) === 1 ? $vm[1] : '';
        return [$g !== '' && $a !== '' ? $g . ':' . $a : '', $v];
    }
}
