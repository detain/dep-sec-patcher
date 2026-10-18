<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

/**
 * The command line to suggest when a run found fixes it did not apply,
 * built from the one that was run: the same target and options, with the
 * mode and publishing flags swapped for the ones that act.
 *
 * Pure.
 */
final class NextSteps
{
    /** Flags a suggestion replaces when it chooses the mode and how to publish. */
    private const REPLACED = ['--check', '--update', '--push', '--pr', '--push-direct'];

    /**
     * @param list<string> $argv    the original command line, program first
     * @param list<string> $add     flags the suggestion adds
     * @param bool         $replace drop the original mode and publishing flags
     */
    public static function command(array $argv, array $add, bool $replace = true): string
    {
        $program = $argv[0] ?? 'dep-sec-patcher';
        $args    = array_slice($argv, 1);
        $kept    = [];
        $direct  = in_array('--push-direct', $add, true);
        $pr      = in_array('--pr', $add, true) || (!$replace && in_array('--pr', $args, true));
        for ($i = 0; $i < count($args); $i++) {
            $arg  = $args[$i];
            $name = explode('=', $arg, 2)[0];
            $own  = !str_contains($arg, '=');
            if ($replace && in_array($name, self::REPLACED, true)) {
                continue;
            }
            // Never echo the key; the run reads $NVD_API_KEY by itself.
            // --branch cannot go with --push-direct, nor --pr-merge without --pr
            if ($name === '--nvd-api-key' || ($name === '--branch' && $direct) || ($name === '--pr-merge' && !$pr)) {
                $i += $own ? 1 : 0;
                continue;
            }
            if (in_array($name, $add, true)) {
                continue;
            }
            $kept[] = $arg;
        }
        return implode(' ', array_map([self::class, 'quote'], array_merge([$program], $add, $kept)));
    }

    private static function quote(string $arg): string
    {
        return preg_match('#^[A-Za-z0-9_/.:=@,+%~-]+$#', $arg) === 1 ? $arg : escapeshellarg($arg);
    }
}
