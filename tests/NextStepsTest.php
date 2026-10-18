<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\NextSteps;
use PHPUnit\Framework\TestCase;

/**
 * The command suggested when a run found fixes it did not apply.
 */
class NextStepsTest extends TestCase
{
    public function testSwapsModeAndPublishingFlagsAndKeepsTheRest(): void
    {
        $argv = ['/opt/dsp/bin/dep-sec-patcher', '--check', '-t', '4', '--subdir', 'web app', 'owner/name'];
        $this->assertSame(
            "/opt/dsp/bin/dep-sec-patcher --update --pr -t 4 --subdir 'web app' owner/name",
            NextSteps::command($argv, ['--update', '--pr'])
        );
    }

    public function testDropsWhatTheNewFlagsCannotTakeAndNeverEchoesTheKey(): void
    {
        $argv = ['dsp', '--push', '--branch', 'sec/x', '--pr-merge=none', '--nvd-api-key', 'SECRET', '--allow-major', 'o/n'];
        $this->assertSame('dsp --update --push-direct --allow-major o/n', NextSteps::command($argv, ['--update', '--push-direct', '--allow-major']));
        $this->assertSame('dsp --update --pr --branch sec/x --pr-merge=none o/n', NextSteps::command(
            ['dsp', '--pr', '--branch', 'sec/x', '--pr-merge=none', 'o/n'],
            ['--update', '--pr']
        ));
    }

    public function testCanKeepThePublishingFlags(): void
    {
        $this->assertSame('dsp --allow-major --pr o/n', NextSteps::command(['dsp', '--pr', 'o/n'], ['--allow-major'], false));
    }
}
