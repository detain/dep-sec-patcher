<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher;

use InvalidArgumentException;
use JsonException;

/**
 * The optional config file: .dep-sec-patcher.json in the target root, or the
 * file named by --config. It supplies option defaults; the environment and
 * the command line override it.
 *
 *   {
 *     "ecosystems":     {"r": false, "swift": false},
 *     "scanners":       {"trivy": true, "grype": false},
 *     "only":           ["maven", "node", "netsec"],
 *     "threads":        4,
 *     "timeout":        1800,
 *     "nvd-timeout":    3600,
 *     "cvss-threshold": 7.0,
 *     "max-issues":     300,
 *     "close-label":    "security: verified fixed",
 *     "close-delay":    5,
 *     "close-limit":    400,
 *     "allow-http":     ["intranet.example.com/", "*.corp.example/"],
 *     "exclude-dirs":   ["docs", "test/fixtures"],
 *     "allow-major":    false,
 *     "retriage":       true
 *   }
 *
 * Keys starting with "$" or "_" are ignored (for "$schema" and comments).
 * Anything else that is unknown, or of the wrong type, is an error: a typo
 * must not silently fall back to a default.
 */
final class Config
{
    public const FILE = '.dep-sec-patcher.json';

    private const INT_KEYS = [
        'threads'     => 1,
        'timeout'     => 0,
        'nvd-timeout' => 0,
        'max-issues'  => 0,
        'close-delay' => 0,
        'close-limit' => 0,
    ];
    private const KEYS = [
        'ecosystems', 'scanners', 'only', 'threads', 'timeout', 'nvd-timeout', 'cvss-threshold', 'max-issues',
        'close-label', 'close-delay', 'close-limit', 'allow-http', 'exclude-dirs', 'allow-major', 'retriage',
    ];

    /** @var array<string, bool> */
    public array $ecosystems = [];
    /** @var array<string, bool> */
    public array $scanners = [];
    /** @var list<string>|null */
    public ?array $only = null;
    /** @var array<string, int> option key => value */
    public array $ints = [];
    public ?string $cvssThreshold = null;
    public ?string $closeLabel = null;
    /** @var list<string> */
    public array $allowHttp = [];
    /** @var list<string> */
    public array $excludeDirs = [];
    public ?bool $allowMajor = null;
    public ?bool $retriage = null;

    private function __construct(public readonly string $source)
    {
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidArgumentException("config file not readable: {$path}");
        }
        try {
            $data = json_decode((string)file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException("{$path}: invalid JSON: " . $e->getMessage());
        }
        if (!is_array($data) || ($data !== [] && array_is_list($data))) {
            throw new InvalidArgumentException("{$path}: the config must be a JSON object");
        }
        /** @var array<string, mixed> $data */
        return self::fromArray($data, $path);
    }

    /**
     * @param array<string, mixed> $data decoded config
     */
    public static function fromArray(array $data, string $source = 'config'): self
    {
        $c = new self($source);
        foreach ($data as $key => $value) {
            $key = (string)$key;
            if (str_starts_with($key, '$') || str_starts_with($key, '_')) {
                continue;
            }
            if (!in_array($key, self::KEYS, true)) {
                throw $c->error("unknown key \"{$key}\" (known: " . implode(', ', self::KEYS) . ')');
            }
            switch ($key) {
                case 'ecosystems':
                    $c->ecosystems = $c->switches($key, $value, Options::ECOSYSTEMS);
                    break;
                case 'scanners':
                    $c->scanners = $c->switches($key, $value, Options::SCANNER_SWITCHES);
                    break;
                case 'only':
                    $only = $c->strings($key, $value);
                    foreach ($only as $name) {
                        try {
                            Options::assertCheckName($name, '"only"');
                        } catch (InvalidArgumentException $e) {
                            throw $c->error($e->getMessage());
                        }
                    }
                    $c->only = $only;
                    break;
                case 'cvss-threshold':
                    if (!is_int($value) && !is_float($value) && !(is_string($value) && is_numeric($value))) {
                        throw $c->error('"cvss-threshold" must be a number from 0 to 10, got ' . self::show($value));
                    }
                    $c->cvssThreshold = $c->wrap(static fn () => Options::cvss((string)$value, '"cvss-threshold"'));
                    break;
                case 'close-label':
                    if (!is_string($value)) {
                        throw $c->error('"close-label" must be a string, got ' . self::show($value));
                    }
                    $c->closeLabel = $value;
                    break;
                case 'allow-http':
                    $c->allowHttp = array_map(
                        fn (string $p): string => $c->wrap(static fn () => Options::httpPattern($p, '"allow-http"')),
                        $c->strings($key, $value)
                    );
                    break;
                case 'allow-major':
                case 'retriage':
                    if (!is_bool($value)) {
                        throw $c->error("\"{$key}\" must be true or false, got " . self::show($value));
                    }
                    if ($key === 'allow-major') {
                        $c->allowMajor = $value;
                    } else {
                        $c->retriage = $value;
                    }
                    break;
                case 'exclude-dirs':
                    $c->excludeDirs = array_map(
                        fn (string $p): string => $c->wrap(static fn () => Options::relativePath($p, '"exclude-dirs"')),
                        $c->strings($key, $value)
                    );
                    break;
                default:
                    $min = self::INT_KEYS[$key];
                    if (!is_int($value) || $value < $min) {
                        throw $c->error(sprintf('"%s" must be %s integer, got %s', $key, $min > 0 ? 'a positive' : 'a non-negative', self::show($value)));
                    }
                    $c->ints[$key] = $value;
            }
        }
        return $c;
    }

    /**
     * Copy the configured values onto freshly defaulted options.
     */
    public function applyTo(Options $o): void
    {
        foreach ($this->ecosystems as $eco => $on) {
            $o->ecosystems[$eco] = $on;
        }
        foreach ($this->scanners as $scanner => $on) {
            $o->setScanner($scanner, $on ? 'yes' : 'no');
        }
        if ($this->only !== null) {
            $o->only = $this->only;
        }
        foreach ($this->ints as $key => $value) {
            match ($key) {
                'threads'     => $o->threads = $value,
                'timeout'     => $o->timeout = $value,
                'nvd-timeout' => $o->nvdTimeout = $value,
                'max-issues'  => $o->maxIssues = $value,
                'close-delay' => $o->closeDelay = $value,
                'close-limit' => $o->closeLimit = $value,
                default       => null,
            };
        }
        if ($this->cvssThreshold !== null) {
            $o->cvssThreshold = $this->cvssThreshold;
        }
        if ($this->closeLabel !== null) {
            $o->closeLabel = $this->closeLabel;
        }
        if ($this->allowMajor !== null) {
            $o->allowMajor = $this->allowMajor;
        }
        if ($this->retriage !== null) {
            $o->retriage = $this->retriage;
        }
        $o->allowHttp   = array_merge($this->allowHttp, $o->allowHttp);
        $o->excludeDirs = array_merge($this->excludeDirs, $o->excludeDirs);
    }

    /**
     * @param list<string> $known
     * @return array<string, bool>
     */
    private function switches(string $key, mixed $value, array $known): array
    {
        if (!is_array($value) || ($value !== [] && array_is_list($value))) {
            throw $this->error("\"{$key}\" must be an object of name: true|false, got " . self::show($value));
        }
        $out = [];
        foreach ($value as $name => $on) {
            $name = (string)$name;
            if (!in_array($name, $known, true)) {
                throw $this->error("\"{$key}\": unknown name \"{$name}\" (known: " . implode(', ', $known) . ')');
            }
            if (!is_bool($on)) {
                throw $this->error("\"{$key}\".\"{$name}\" must be true or false, got " . self::show($on));
            }
            $out[$name] = $on;
        }
        return $out;
    }

    /**
     * @return list<string>
     */
    private function strings(string $key, mixed $value): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw $this->error("\"{$key}\" must be a list of strings, got " . self::show($value));
        }
        $out = [];
        foreach ($value as $item) {
            if (!is_string($item) || trim($item) === '') {
                throw $this->error("\"{$key}\" must contain only non-empty strings, got " . self::show($item));
            }
            $out[] = $item;
        }
        return $out;
    }

    /**
     * Run an Options validator, re-labelling its error with the config source.
     *
     * @param callable(): string $fn
     */
    private function wrap(callable $fn): string
    {
        try {
            return $fn();
        } catch (InvalidArgumentException $e) {
            throw $this->error($e->getMessage());
        }
    }

    private function error(string $message): InvalidArgumentException
    {
        return new InvalidArgumentException("{$this->source}: {$message}");
    }

    private static function show(mixed $value): string
    {
        return (string)json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
