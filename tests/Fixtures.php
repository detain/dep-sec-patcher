<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Console;
use Detain\DepSecPatcher\ProcessRunner;
use RuntimeException;

/**
 * Scratch directories and hermetic git repositories for tests. Nothing here
 * touches the network: a local bare repository stands in for a remote.
 */
trait Fixtures
{
    /** @var list<string> */
    private array $scratch = [];
    /** @var array<string, string|false> environment to restore */
    private array $savedEnv = [];

    protected function scratchDir(string $name = 'dsp'): string
    {
        $dir = sys_get_temp_dir() . '/dep-sec-patcher-test-' . $name . '-' . getmypid() . '-' . mt_rand();
        mkdir($dir, 0775, true);
        $real = (string)realpath($dir);
        $this->scratch[] = $real;
        return $real;
    }

    /**
     * Isolate git from the user's and system configuration (signing, hooks,
     * default branch names), and give it an identity.
     */
    protected function hermeticGit(): void
    {
        foreach ([
            'GIT_CONFIG_GLOBAL'   => '/dev/null',
            'GIT_CONFIG_NOSYSTEM' => '1',
            'GIT_AUTHOR_NAME'     => 'Test',
            'GIT_AUTHOR_EMAIL'    => 'test@example.com',
            'GIT_COMMITTER_NAME'  => 'Test',
            'GIT_COMMITTER_EMAIL' => 'test@example.com',
        ] as $k => $v) {
            $this->setEnv($k, $v);
        }
    }

    protected function setEnv(string $name, ?string $value): void
    {
        if (!array_key_exists($name, $this->savedEnv)) {
            $this->savedEnv[$name] = getenv($name);
        }
        putenv($value === null ? $name : "{$name}={$value}");
    }

    protected function cleanupFixtures(): void
    {
        foreach ($this->savedEnv as $k => $v) {
            putenv($v === false ? $k : "{$k}={$v}");
        }
        $this->savedEnv = [];
        foreach ($this->scratch as $dir) {
            exec('chmod -R u+w ' . escapeshellarg($dir) . ' 2>/dev/null; rm -rf ' . escapeshellarg($dir));
        }
        $this->scratch = [];
    }

    /**
     * Run git and return its stdout; throws on failure.
     *
     * @param list<string> $args
     */
    protected function git(string $cwd, array $args): string
    {
        $cmd = 'git ' . implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1';
        $out = [];
        $rc  = 0;
        exec('cd ' . escapeshellarg($cwd) . ' && ' . $cmd, $out, $rc);
        if ($rc !== 0) {
            throw new RuntimeException("git failed ({$rc}): {$cmd}\n" . implode("\n", $out));
        }
        return implode("\n", $out);
    }

    /**
     * A bare "remote" with one commit on main, and the work tree it was
     * pushed from (for adding later commits).
     *
     * @param array<string, string> $files path => content
     * @return array{bare: string, work: string, url: string}
     */
    protected function makeRemote(array $files = ['README.md' => "hello\n"]): array
    {
        $base = $this->scratchDir('remote');
        $bare = $base . '/remote.git';
        $work = $base . '/work';
        $this->git($base, ['init', '--quiet', '--bare', '--initial-branch=main', $bare]);
        $this->git($base, ['init', '--quiet', '--initial-branch=main', $work]);
        foreach ($files as $path => $content) {
            @mkdir(dirname($work . '/' . $path), 0775, true);
            file_put_contents($work . '/' . $path, $content);
        }
        $this->git($work, ['add', '--all']);
        $this->git($work, ['commit', '--quiet', '-m', 'initial']);
        $this->git($work, ['remote', 'add', 'origin', $bare]);
        $this->git($work, ['push', '--quiet', '-u', 'origin', 'main']);
        return ['bare' => $bare, 'work' => $work, 'url' => 'file://' . $bare];
    }

    /**
     * A console writing to memory, and a runner using it.
     *
     * @return array{0: Console, 1: ProcessRunner, 2: resource}
     */
    protected function quietRunner(int $timeout = 60): array
    {
        $out     = fopen('php://memory', 'w+');
        $this->assertIsResource($out);
        $console = new Console(false, '[test]', $out);
        return [$console, new ProcessRunner($console, $timeout), $out];
    }

    /**
     * @param resource $stream
     */
    protected static function readStream($stream): string
    {
        rewind($stream);
        return (string)stream_get_contents($stream);
    }
}
