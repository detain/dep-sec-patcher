<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Reads `export NAME=value` assignments out of shell rc files, for cron runs
 * that never source them.
 */
final class TokenHarvester
{
    /**
     * @return list<string> readable rc files, in lookup order
     */
    public static function rcFiles(): array
    {
        $home = getenv('HOME') ?: '';
        if ($home === '') {
            return [];
        }
        $files = [];
        foreach (['.bashrc', '.bash_profile', '.profile', '.zshrc'] as $rc) {
            if (is_readable($home . '/' . $rc)) {
                $files[] = $home . '/' . $rc;
            }
        }
        return $files;
    }

    /**
     * Last assignment to any of $names in an rc file's content, quotes and
     * whitespace stripped; null when there is none.
     *
     * @param list<string> $names
     */
    public static function fromContent(string $content, array $names): ?string
    {
        $alt = implode('|', array_map(static fn ($n) => preg_quote($n, '/'), $names));
        if (preg_match_all('/^[ \t]*(?:export[ \t]+)?(?:' . $alt . ')=(.*)$/m', $content, $m) === 0) {
            return null;
        }
        $value = (string)preg_replace('/["\'\s]/', '', (string)end($m[1]));
        return $value === '' ? null : $value;
    }

    /**
     * First non-empty value: environment, then rc files.
     */
    public static function find(string $name): ?string
    {
        $env = getenv($name);
        if (is_string($env) && $env !== '') {
            return $env;
        }
        foreach (self::rcFiles() as $rc) {
            $value = self::fromContent((string)@file_get_contents($rc), [$name]);
            if ($value !== null) {
                return $value;
            }
        }
        return null;
    }
}
