<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * JSON encoding that preserves a file's existing indentation.
 *
 * The original shell script rewrote package.json/composer.json through jq, which
 * forces two-space indentation, so every fix to a four-space composer.json
 * re-indented the whole file. Here the original indent is detected and kept.
 *
 * Pure: no I/O.
 */
final class JsonFile
{
    private const FLAGS = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        | JSON_PRESERVE_ZERO_FRACTION | JSON_INVALID_UTF8_SUBSTITUTE;

    /**
     * The indent unit used by a JSON document: "\t", or a run of spaces.
     * Defaults to two spaces (npm's and jq's style) when nothing is indented.
     */
    public static function detectIndent(string $json): string
    {
        if (preg_match('/^[{\[][^\n]*\n([ \t]+)\S/', $json, $m) === 1) {
            return $m[1][0] === "\t" ? "\t" : str_repeat(' ', strlen($m[1]));
        }
        return '  ';
    }

    /**
     * Encode with the given indent unit and a trailing newline.
     */
    public static function encode(mixed $data, string $indent = '  '): string
    {
        $json = json_encode($data, self::FLAGS | JSON_THROW_ON_ERROR);
        if ($indent !== '    ') {
            // PHP always pretty-prints with four spaces; leading whitespace is
            // pure indentation because strings cannot contain raw newlines
            $json = (string)preg_replace_callback(
                '/^(?: {4})+/m',
                static fn (array $m): string => str_repeat($indent, intdiv(strlen($m[0]), 4)),
                $json
            );
        }
        return $json . "\n";
    }

    /**
     * Decode keeping JSON objects as stdClass, so "{}" and "[]" survive a
     * round trip.
     */
    public static function decodeObject(string $json): mixed
    {
        return json_decode($json, false, 512, JSON_THROW_ON_ERROR);
    }
}
