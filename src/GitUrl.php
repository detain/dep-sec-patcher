<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * Git remote URL knowledge: telling a URL from a local path, expanding the
 * GitHub OWNER/NAME shorthand, finding the GitHub repository a remote points
 * at, and keeping credentials out of anything printed or hashed.
 *
 * Pure: no I/O.
 */
final class GitUrl
{
    /** GitHub owner (user/org) and repository name character sets. */
    private const OWNER = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})';
    private const NAME  = '[A-Za-z0-9._-]+';

    /**
     * Whether a TARGET names a remote repository: scheme://... (https, ssh,
     * git, file, ...) or scp-like [user@]host:path. A local path is never a
     * URL; callers check the filesystem first.
     */
    public static function isUrl(string $target): bool
    {
        if (preg_match('#^[A-Za-z][A-Za-z0-9+.-]*://#', $target) === 1) {
            return true;
        }
        // scp-like syntax: no slash before the first colon, and more than a
        // drive letter in front of it
        return preg_match('#^(?:[^@/:\s]+@)?[^@/:\s]{2,}:[^\s]+$#', $target) === 1;
    }

    /**
     * Whether a TARGET is the GitHub OWNER/NAME shorthand.
     */
    public static function isGithubShorthand(string $target): bool
    {
        return preg_match('#^' . self::OWNER . '/' . self::NAME . '$#', $target) === 1
            && !str_ends_with($target, '/.') && !str_ends_with($target, '/..');
    }

    public static function fromShorthand(string $shorthand): string
    {
        return 'https://github.com/' . preg_replace('/\.git$/', '', $shorthand) . '.git';
    }

    /**
     * OWNER/NAME of the github.com repository a remote URL points at, or null
     * for anything else (another host, a local path, a malformed URL).
     *
     * Accepts https://[user@]github.com/o/n[.git], ssh://git@github.com[:22]/o/n,
     * git://github.com/o/n, git@github.com:o/n[.git] and github.com:o/n.
     */
    public static function githubRepo(string $url): ?string
    {
        $url  = trim($url);
        $tail = '(' . self::OWNER . ')/(' . self::NAME . ')/*$';
        $patterns = [
            '#^(?:https?|git|ssh|git\+ssh|ssh\+git)://(?:[^@/]+@)?(?:www\.)?github\.com(?::\d+)?/' . $tail . '#i',
            '#^(?:[^@/:\s]+@)?github\.com:/?' . $tail . '#i',
        ];
        foreach ($patterns as $rx) {
            if (preg_match($rx, $url, $m) === 1) {
                $name = (string)preg_replace('/\.git$/i', '', $m[2]);
                if ($name === '' || $name === '.' || $name === '..') {
                    return null;
                }
                return $m[1] . '/' . $name;
            }
        }
        return null;
    }

    /**
     * Hide credentials embedded in a URL. Any userinfo on http(s) is hidden
     * (a token is often passed as the user name); elsewhere only a password.
     */
    public static function redact(string $s): string
    {
        $s = (string)preg_replace('#^(https?://)[^/@\s]+@#i', '$1***@', $s);
        return (string)preg_replace('#^([A-Za-z][A-Za-z0-9+.-]*://[^/:@\s]+):[^/@\s]+@#', '$1:***@', $s);
    }

    /**
     * Stable identity for a remote, for hashing into a state slug: no
     * credentials, no trailing slash or ".git", lowercase host.
     */
    public static function normalize(string $url): string
    {
        $url = self::redact(trim($url));
        $url = (string)preg_replace('#^(https?://)\*\*\*@#i', '$1', $url);
        $url = rtrim($url, '/');
        $url = (string)preg_replace('/\.git$/i', '', $url);
        return (string)preg_replace_callback(
            '#^([A-Za-z][A-Za-z0-9+.-]*://(?:[^/@]+@)?)([^/:]+)#',
            static fn (array $m): string => strtolower($m[1]) . strtolower($m[2]),
            $url
        );
    }

    /**
     * Last path component of a remote, without ".git": the repository name.
     */
    public static function basename(string $url): string
    {
        $url  = rtrim(trim($url), '/');
        $url  = (string)preg_replace('/\.git$/i', '', $url);
        $base = (string)preg_replace('#^.*[/:]#', '', $url);
        return $base === '' ? 'repo' : $base;
    }
}
