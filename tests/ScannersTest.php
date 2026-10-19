<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\ComposerAuditor;
use Detain\DepSecPatcher\Auditor\GradleAuditor;
use Detain\DepSecPatcher\Auditor\MavenAuditor;
use Detain\DepSecPatcher\Auditor\NodeAuditor;
use Detain\DepSecPatcher\Auditor\SbtAuditor;
use Detain\DepSecPatcher\Auditor\SimpleAuditor;
use Detain\DepSecPatcher\CommandResult;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\Scanner\Scanners;
use Detain\DepSecPatcher\TargetResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Trivy's Maven Central rate-limit handling, Elixir's check-mode steps,
 * Maven's, npm's and Dart's update steps, Composer without a lockfile and
 * how sbt is invoked, driven through stand-in tools on PATH.
 */
class ScannersTest extends TestCase
{
    use Fixtures;

    private const LIMITED = "2026-10-16T17:08:34-04:00\tFATAL\tError\tremote Maven repository returned 429 Too Many Requests"
        . " for https://repo.maven.apache.org/maven2/io/micronaut/micronaut-parent/4.4.0/micronaut-parent-4.4.0.pom. Retry-After: %s.\n"
        . "The repository blocks all subsequent requests from this IP until the block clears.\n";

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    /**
     * @return array<string, array{string, ?int}>
     */
    public static function rateLimitOutputs(): array
    {
        return [
            'trivy 429 with Retry-After' => [sprintf(self::LIMITED, '1600'), 1600],
            'short block'                => [sprintf(self::LIMITED, '45'), 45],
            'no usable Retry-After'      => ["remote Maven repository returned 429 Too Many Requests for https://x/y.pom\n", 60],
            'other failure'              => ["FATAL\tError\tunable to initialize scanner\n", null],
            'clean run'                  => ['', null],
        ];
    }

    #[DataProvider('rateLimitOutputs')]
    public function testRateLimitWait(string $output, ?int $expected): void
    {
        $this->assertSame($expected, Scanners::rateLimitWait($output));
    }

    public function testShortRateLimitIsWaitedOutAndRetried(): void
    {
        [$t, $calls] = $this->trivyWith(['1', 'ok']);
        $this->assertSame(TargetResult::FAIL, $t->status, 'the retried scan is reported');
        $this->assertCount(2, $calls);
        $this->assertStringNotContainsString('--offline-scan', implode("\n", $calls));
    }

    public function testLongRateLimitFallsBackToOfflineWithoutWaiting(): void
    {
        $start       = microtime(true);
        [$t, $calls] = $this->trivyWith(['1600']);
        $this->assertLessThan(5, microtime(true) - $start, 'a 1600s block is not waited out');
        $this->assertCount(2, $calls);
        $this->assertStringContainsString('--offline-scan', $calls[1]);
        $this->assertStringContainsString('offline scan', $t->detail);
        $this->assertSame(TargetResult::FAIL, $t->status, 'offline findings are still reported');
    }

    public function testRepeatedRateLimitFallsBackToOfflineAfterOneRetry(): void
    {
        [$t, $calls] = $this->trivyWith(['1', '1']);
        $this->assertCount(3, $calls);
        $this->assertStringNotContainsString('--offline-scan', $calls[1]);
        $this->assertStringContainsString('--offline-scan', $calls[2]);
        $this->assertStringContainsString('offline scan', $t->detail);
    }

    public function testElixirCheckModeFetchesDependenciesBeforeAuditing(): void
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/mix', "#!/bin/sh\necho \"\$*\" >> " . escapeshellarg($log) . "\n");
        chmod($bin . '/mix', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));

        $root = $this->scratchDir('elixir');
        file_put_contents($root . '/mix.exs', '');
        $t = SimpleAuditor::elixir()->audit($this->context($root, ['--check']), '');

        $this->assertSame(TargetResult::PASS, $t->status);
        $this->assertSame(['deps.get', 'hex.audit'], file($log, FILE_IGNORE_NEW_LINES));
    }

    /**
     * @return array<string, array{list<string>, bool}>
     */
    public static function mavenUpdates(): array
    {
        return [
            'without --allow-major' => [['--update'], true],
            'with --allow-major'    => [['--update', '--allow-major'], false],
        ];
    }

    /**
     * @param list<string> $args
     */
    #[DataProvider('mavenUpdates')]
    public function testMavenUpdateModeAlsoMovesVersionProperties(array $args, bool $capped): void
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/mvn', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            for a in "\$@"; do
              case "\$a" in -Dodc.outputDirectory=*) echo '{"dependencies": []}' > "\${a#*=}/dependency-check-report.json" ;; esac
            done
            SH);
        chmod($bin . '/mvn', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        $root = $this->scratchDir('java');
        file_put_contents($root . '/pom.xml', '<project/>');

        $t = (new MavenAuditor())->audit($this->context($root, $args), '');
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $goals = array_values(array_filter(file($log, FILE_IGNORE_NEW_LINES) ?: [], static fn (string $c): bool => str_contains($c, 'versions-maven-plugin:')));
        $this->assertCount(2, $goals);
        $this->assertStringContainsString(MavenAuditor::VERSIONS_PLUGIN . ':use-latest-releases', $goals[0], 'a plugin version that honours the ignore rule');
        $this->assertStringContainsString(MavenAuditor::VERSIONS_PLUGIN . ':update-properties', $goals[1], 'versions declared through ${...} properties');
        foreach ($goals as $goal) {
            $this->assertSame($capped, str_contains($goal, '-DallowMajorUpdates=false'));
            $this->assertStringContainsString('-Dmaven.version.ignore=' . MavenAuditor::PRERELEASES, $goal);
        }
    }

    public function testAnOldGradleWrapperRunsOnAJdkItSupports(): void
    {
        $bin = $this->scratchDir('bin');
        file_put_contents($bin . '/java', "#!/bin/sh\necho 'openjdk version \"21.0.12\" 2026-08-18' >&2\n");
        chmod($bin . '/java', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        $this->setEnv('JAVA_HOME', null);
        $jvm = $this->scratchDir('jvm');
        foreach (['jdk-8' => '1.8.0_392', 'jdk-11' => '11.0.2', 'jdk-17' => '17.0.1'] as $name => $version) {
            mkdir("{$jvm}/{$name}/bin", 0775, true);
            file_put_contents("{$jvm}/{$name}/bin/java", "#!/bin/sh\n");
            chmod("{$jvm}/{$name}/bin/java", 0755);
            file_put_contents("{$jvm}/{$name}/release", "IMPLEMENTOR=\"x\"\nJAVA_VERSION=\"{$version}\"\n");
        }
        $root = $this->scratchDir('gradle');
        $log  = $root . '/calls.log';
        file_put_contents($root . '/gradlew', "#!/bin/sh\necho \"JAVA_HOME=\$JAVA_HOME \$*\" >> '{$log}'\n");
        mkdir($root . '/gradle/wrapper', 0775, true);
        file_put_contents($root . '/gradle/wrapper/gradle-wrapper.properties', "distributionUrl=https\\://services.gradle.org/distributions/gradle-7.0-bin.zip\n");

        $t = (new GradleAuditor([$jvm]))->audit($this->context($root, ['--update']), '');
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $this->assertSame(["Gradle 7.0 does not run on Java 21; ran on {$jvm}/jdk-11"], $t->notes, 'the newest JDK it runs on');
        $this->assertSame(["JAVA_HOME={$jvm}/jdk-11 dependencies --no-daemon -q --console=plain"], file($log, FILE_IGNORE_NEW_LINES));

        $t = (new GradleAuditor([$this->scratchDir('nojvm')]))->audit($this->context($root, ['--update']), '');
        $this->assertSame(TargetResult::SKIP, $t->status);
        $this->assertStringContainsString('Gradle 7.0 runs on Java 16 at most, and this host has Java 21', $t->detail);
        $this->assertCount(1, file($log) ?: [], 'not run where it cannot start');
    }

    public function testAGradleFailureShowsWhatWentWrong(): void
    {
        $out = "FAILURE: Build failed with an exception.\n\n* Where:\nSettings file '/p/settings.gradle'\n\n* What went wrong:\n"
            . "Could not compile settings file '/p/settings.gradle'.\n> startup failed:\n  General error during conversion: Unsupported class file major version 65\n\n"
            . "* Try:\n> Run with --stacktrace option to get the stack trace.\n\nBUILD FAILED in 2s\n";
        $this->assertSame([
            '* Where:',
            "Settings file '/p/settings.gradle'",
            '* What went wrong:',
            "Could not compile settings file '/p/settings.gradle'.",
            '> startup failed:',
            '  General error during conversion: Unsupported class file major version 65',
        ], GradleAuditor::failure(new CommandResult('gradle', 1, false, '', $out, 2.0)));
        $this->assertSame(['boom'], GradleAuditor::failure(new CommandResult('gradle', 1, false, '', "boom\n", 1.0)), 'otherwise the last lines');
        $this->assertSame(16, GradleAuditor::maxJava('7.0.2'));
        $this->assertSame(0, GradleAuditor::maxJava('99.0'), 'newer than the table: not second-guessed');
    }

    public function testTheMavenUpdaterPassesOverPrereleasesOnly(): void
    {
        // The plugin takes the pattern as a Java regex and matches the whole
        // version; this one reads the same in PCRE
        $rx = '/' . str_replace('/', '\/', MavenAuditor::PRERELEASES) . '/';
        foreach (['7.1.0-M2', '5.0.0.Alpha2', '4.0.0.Beta8', '3.0-rc5', '1.0.0-alpha.1', '9.0.0-ea+13', '2.0.0.CR1', '1.0-SNAPSHOT', '5.0.0-preview.2'] as $v) {
            $this->assertSame(1, preg_match($rx, $v), "{$v} is a prerelease");
        }
        foreach (['4.1.42.Final', '28.2-android', '33.7.2-jre', '5.1.17.RELEASE', '2.9.10.4', '1.2.3', '1.0.0-GA', '2.12.7.1', '2.22'] as $v) {
            $this->assertSame(0, preg_match($rx, $v), "{$v} is a release");
        }
        // ...and agrees with the auto-fix's own prerelease test
        foreach (VersionTest::prereleaseProvider() as $name => [$v, $pre]) {
            $this->assertSame($pre, preg_match($rx, $v) === 1, "{$name}: {$v}");
        }
    }

    /**
     * A stand-in mvn: versions:update-properties sets ${jackson-version} to
     * 2.22, and dependency:resolve fails while the pom holds it (and, when
     * $broken, before it too), first with a failure Maven cached.
     */
    private function fakeMaven(bool $broken = false): string
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        $old = $broken ? 'true' : 'false';
        file_put_contents($bin . '/mvn', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            for a in "\$@"; do
              case "\$a" in -Dodc.outputDirectory=*) echo '{"dependencies": []}' > "\${a#*=}/dependency-check-report.json" ;; esac
            done
            case " \$* " in
              *":update-properties "*) sed -i 's#<jackson-version>2.9.5<#<jackson-version>2.22<#; s#<module-version>1<#<module-version>2<#' pom.xml mod/pom.xml 2>/dev/null; true ;;
              *" dependency:resolve "*)
                if {$old}; then echo '[ERROR] dependency: com.android.volley:volley:jar:1.2.1 (compile)'; fail=1; fi
                if grep -q '2.22<' pom.xml; then
                  echo '[ERROR] Failed to execute goal on project p: Could not resolve dependencies for project g:p:jar:1.0.0'
                  echo '[ERROR] dependency: com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider:jar:2.22 (compile)'
                  case " \$* " in
                    *" -U "*) echo '[ERROR]   Could not find artifact com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider:jar:2.22 in central (https://repo.maven.apache.org/maven2)' ;;
                    *) echo '[ERROR]   com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider:jar:2.22 was not found in https://repo.maven.apache.org/maven2 during a previous attempt. This failure was cached in the local repository' ;;
                  esac
                  fail=1
                fi
                exit \${fail:-0} ;;
            esac
            SH);
        chmod($bin . '/mvn', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        return $log;
    }

    private const JACKSON_POM = "<project>\n  <modules><module>mod</module></modules>\n  <properties>\n    <jackson-version>2.9.5</jackson-version>\n  </properties>\n</project>\n";

    public function testAMavenUpdateThatNoLongerResolvesIsRevertedWithAWarning(): void
    {
        $log  = $this->fakeMaven();
        $root = $this->scratchDir('java');
        file_put_contents($root . '/pom.xml', self::JACKSON_POM);
        mkdir($root . '/mod');
        file_put_contents($root . '/mod/pom.xml', '<project><properties><module-version>1</module-version></properties></project>');

        $t = (new MavenAuditor())->audit($this->context($root, ['--update']), '');
        $this->assertSame(self::JACKSON_POM, file_get_contents($root . '/pom.xml'), 'back to the pre-update content');
        $this->assertStringContainsString('<module-version>1<', (string)file_get_contents($root . '/mod/pom.xml'), 'module poms too');
        $this->assertSame(TargetResult::WARN, $t->status, $t->detail);
        $this->assertSame([
            'WARN: the version update left pom.xml unresolvable (com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider:jar:2.22);'
                . ' reverted 2 poms to the pre-update content, leaving the per-artifact fixes to auto-fix',
        ], $t->notes);
        $resolves = array_values(array_filter(file($log, FILE_IGNORE_NEW_LINES) ?: [], static fn (string $c): bool => str_contains($c, 'dependency:resolve')));
        $this->assertCount(3, $resolves, 'after the update, once more with -U for the cached failure, then the restored pom');
        $this->assertStringContainsString(' -U dependency:resolve', $resolves[1]);
        $this->assertStringNotContainsString(' -U ', $resolves[2], 'the restored pom resolved at once');
    }

    public function testAnUpdateToAPomThatAlreadyFailedToResolveIsKeptWhenItAddsNoFailure(): void
    {
        $this->fakeMaven(true);
        $root = $this->scratchDir('java');
        $pom = "<project>\n  <properties>\n    <module-version>1</module-version>\n  </properties>\n</project>\n";
        file_put_contents($root . '/pom.xml', $pom);
        $t = (new MavenAuditor())->audit($this->context($root, ['--update']), '');
        $this->assertSame(str_replace('>1<', '>2<', $pom), file_get_contents($root . '/pom.xml'), 'the volley failure was there before');
        $this->assertSame(['pom.xml did not resolve before the version update either (com.android.volley:volley:jar:1.2.1);'
            . ' kept the update, which adds no unresolved artifact'], $t->notes);
        $this->assertSame(TargetResult::PASS, $t->status);

        // An update that does break it on top of the volley failure is reverted
        file_put_contents($root . '/pom.xml', self::JACKSON_POM);
        $t = (new MavenAuditor())->audit($this->context($root, ['--update']), '');
        $this->assertSame(self::JACKSON_POM, file_get_contents($root . '/pom.xml'));
        $this->assertStringContainsString('unresolvable (com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider:jar:2.22)', $t->notes[0]);
    }

    public function testMissingArtifactsAreReadFromMavenOutput(): void
    {
        $out = "[ERROR] Failed to execute goal on project swagger-jaxrs-server: Could not resolve dependencies for project io.swagger:swagger-jaxrs-server:jar:1.0.0\n"
            . "[ERROR] dependency: com.fasterxml.jackson.datatype:jackson-datatype-joda:jar:2.22 (compile)\n"
            . "[ERROR] \tcom.fasterxml.jackson.datatype:jackson-datatype-joda:jar:2.22 was not found in https://repo.maven.apache.org/maven2 during a previous attempt.\n"
            . "[ERROR] Failed to execute goal org.apache.maven.plugins:maven-dependency-plugin:3.7.0:resolve (default-cli) on project x\n"
            . "[ERROR]     Non-resolvable parent POM for org.openapitools:openapi-micronaut-client:1.0.0: The following artifacts could not be resolved:"
            . " io.micronaut:micronaut-parent:pom:4.4.0 (absent): Could not find artifact io.micronaut:micronaut-parent:pom:4.4.0 in central\n"
            . "[INFO] Downloaded com.example:other:jar:1.0\n";
        $this->assertSame(
            ['com.fasterxml.jackson.datatype:jackson-datatype-joda:jar:2.22', 'io.micronaut:micronaut-parent:pom:4.4.0'],
            MavenAuditor::missingArtifacts($out)
        );
        $this->assertTrue(MavenAuditor::cachedFailure($out));
        $this->assertFalse(MavenAuditor::cachedFailure('[ERROR] Could not find artifact a:b:jar:1 in central'));
    }

    /**
     * @param list<string> $args
     */
    #[DataProvider('mavenUpdates')]
    public function testNpmPeerConflictsAreResolvedTheLegacyWayAndForceNeedsAllowMajor(array $args, bool $capped): void
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/npm', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            case " \$* " in
              *" --legacy-peer-deps "*) ;;
              *" install "*) echo 'npm error code ERESOLVE' >&2; echo 'npm error Conflicting peer dependency: @babel/core@8.0.7' >&2; exit 1 ;;
            esac
            case " \$* " in *" audit --json "*) echo '{"metadata": {"vulnerabilities": {"high": 0, "critical": 0}}}' ;; esac
            SH);
        chmod($bin . '/npm', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        $root = $this->scratchDir('js');
        file_put_contents($root . '/package.json', '{}');

        $t     = (new NodeAuditor())->audit($this->context($root, $args), '');
        $calls = file($log, FILE_IGNORE_NEW_LINES) ?: [];
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $this->assertContains('conflicting peer dependencies in package.json (npm ERESOLVE); resolved with --legacy-peer-deps', $t->notes);
        $this->assertStringNotContainsString('--legacy-peer-deps', $calls[0], 'tried the normal way first');
        foreach (array_slice($calls, 1, 3) as $call) {
            $this->assertStringContainsString('--legacy-peer-deps', $call, $call);
        }
        $fix = (string)current(array_filter($calls, static fn (string $c): bool => str_starts_with($c, 'audit fix')));
        $this->assertSame(!$capped, str_contains($fix, '--force'), 'npm audit fix --force makes major upgrades');
    }

    public function testNpmAuditFixSaysWhatItLeft(): void
    {
        $report = "# npm audit report\n\nminimist  <=0.2.3\nSeverity: critical\nfix available via `npm audit fix --force`\n"
            . "Will install minimist@1.2.8, which is a breaking change\n\nnode-fetch  <2.6.7\nfix available via `npm audit fix --force`\n\n"
            . "request  *\nNo fix available\n\n3 vulnerabilities (1 high, 2 critical)\n";
        $this->assertSame(
            'npm audit fix left 2 need a major upgrade (--allow-major), 1 has no fix available',
            NodeAuditor::auditFixNote(new CommandResult('npm audit fix', 1, false, $report, $report, 1.0))
        );
        $this->assertSame('npm audit fix exit 1', NodeAuditor::auditFixNote(new CommandResult('npm audit fix', 1, false, '', 'npm error code E403', 1.0)));

        // With --allow-major, --force was passed already; and "braces  *"
        // has no fix whatever older parent npm suggests
        $forced = "# npm audit report\n\nbraces  *\nSeverity: high\nfix available via `npm audit fix --force`\n"
            . "Will install flow-copy-source@2.0.9, which is a breaking change\nnode_modules/braces\n\n"
            . "form-data  4.0.0 - 4.0.5\nSeverity: high\nfix available via `npm audit fix --force`\nWill install zapier-platform-core@10.2.0, which is a breaking change\n"
            . "node_modules/zapier-platform-core/node_modules/form-data\n  zapier-platform-core  9.6.0 - 9.7.3 || >=11.0.0\n  Depends on vulnerable versions of form-data\n\n"
            . "diff  5.0.0 - 5.2.1\njsdiff has a Denial of Service vulnerability\nfix available via `npm audit fix`\nnode_modules/diff\n\n"
            . "3 vulnerabilities (3 high)\n";
        $this->assertSame(
            'npm audit fix left 1 not fixed even with --force, 1 it could not resolve, 1 has no fix available',
            NodeAuditor::auditFixNote(new CommandResult('npm audit fix', 1, false, $forced, $forced, 1.0), true)
        );
    }

    /**
     * An override naming a version npm never published (an unscoped
     * json-schema-ref-parser given @apidevtools' 15.3.6) is dropped so the
     * install runs, and what audit fix leaves is pinned with overrides.
     */
    public function testNpmDropsAnUnpublishedOverrideAndPinsWhatAuditFixLeft(): void
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/npm', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            case " \$* " in
              *" install "*)
                if grep -q '"json-schema-ref-parser"' package.json; then
                  echo 'npm error code ETARGET' >&2
                  echo 'npm error notarget No matching version found for json-schema-ref-parser@^15.3.6.' >&2
                  exit 1
                fi
                if grep -q '"form-data@4"' package.json; then
                  echo '{"packages": {"": {}, "node_modules/form-data": {"version": "4.0.6"}, "node_modules/zapier-platform-core/node_modules/form-data": {"version": "4.0.6"}}}' > package-lock.json
                fi ;;
              *" audit fix "*) exit 1 ;;
              *" audit --json "*)
                if grep -q '"form-data@4"' package.json; then echo '{"metadata": {"vulnerabilities": {"high": 0}}}'; exit 0; fi
                echo '{"vulnerabilities": {"form-data": {"via": [{"range": "4.0.0 - 4.0.5"}]}}, "metadata": {"vulnerabilities": {"high": 1}}}'
                exit 1 ;;
              *" view form-data versions "*) echo '["4.0.5", "4.0.6"]' ;;
            esac
            SH);
        chmod($bin . '/npm', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        $root = $this->scratchDir('js');
        file_put_contents($root . '/package.json', "{\n  \"dependencies\": {\n    \"form-data\": \"^4.0.6\"\n  },\n  \"overrides\": {\n"
            . "    \"@apidevtools/json-schema-ref-parser\": \"^15.3.6\",\n    \"json-schema-ref-parser\": \"^15.3.6\"\n  }\n}\n");
        file_put_contents($root . '/package-lock.json', '{"packages": {"": {}, "node_modules/form-data": {"version": "4.0.6"},'
            . ' "node_modules/zapier-platform-core/node_modules/form-data": {"version": "4.0.5"}}}');

        $t = (new NodeAuditor())->audit($this->context($root, ['--update', '--allow-major']), '');
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail . implode("\n", $t->notes));
        $this->assertContains('removed overrides.json-schema-ref-parser ^15.3.6 from package.json: npm has no matching version of json-schema-ref-parser', $t->notes);
        $this->assertContains('npm overrides for what npm audit fix left: form-data@4 ^4.0.6', $t->notes);
        $doc = json_decode((string)file_get_contents($root . '/package.json'), true);
        $this->assertSame(['@apidevtools/json-schema-ref-parser' => '^15.3.6', 'form-data@4' => '^4.0.6'], $doc['overrides'], 'the scoped package is a different one');
    }

    /**
     * @param list<string> $args
     */
    #[DataProvider('mavenUpdates')]
    public function testDartMajorVersionsNeedAllowMajor(array $args, bool $capped): void
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/dart', "#!/bin/sh\necho \"\$*\" >> " . escapeshellarg($log) . "\n");
        chmod($bin . '/dart', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        $root = $this->scratchDir('dart');
        file_put_contents($root . '/pubspec.yaml', '');

        SimpleAuditor::dart()->audit($this->context($root, $args), '');
        $this->assertSame([$capped ? 'pub upgrade' : 'pub upgrade --major-versions'], file($log, FILE_IGNORE_NEW_LINES));
    }

    public function testOldSbtIsAllowedItsSecurityManagerOnNewJava(): void
    {
        [$root, $home, $log] = $this->sbtProject('0.13.15');
        mkdir($home . '/.sbt/0.13/plugins', 0775, true);
        file_put_contents($home . '/.sbt/0.13/plugins/p.sbt', 'addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.6.4")');
        $bin = dirname($log);
        file_put_contents($bin . '/java', "#!/bin/sh\necho 'openjdk version \"21.0.12.1\" 2026-08-18' >&2\n");
        chmod($bin . '/java', 0755);
        (new SbtAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertStringContainsString(' -Djava.security.manager=allow -batch ', (string)file_get_contents($log));

        [$root, , $log] = $this->sbtProject('1.10.11');
        file_put_contents(dirname($log) . '/java', "#!/bin/sh\necho 'openjdk version \"21.0.12.1\"' >&2\n");
        chmod(dirname($log) . '/java', 0755);
        (new SbtAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertStringNotContainsString('java.security.manager', (string)file_get_contents($log), 'not needed from sbt 1.6');
    }

    public function testSbtUpdateModeOnlyReports(): void
    {
        [$root, , $log] = $this->sbtProject('1.10.11');
        (new SbtAuditor())->audit($this->context($root, ['--update']), '');
        $this->assertStringEndsWith(' -batch dependencyUpdates' . "\n", (string)file_get_contents($log), 'no settings sbt-updates does not have');
    }

    /**
     * @return array<string, array{list<string>}>
     */
    public static function modes(): array
    {
        return ['check' => [['--check']], 'update' => [['--update']]];
    }

    /**
     * @param list<string> $mode
     */
    #[DataProvider('modes')]
    public function testComposerWithoutALockfileAuditsAFreshResolutionAndDeletesIt(array $mode): void
    {
        $log  = $this->fakeComposer();
        $root = $this->scratchDir('lib');
        file_put_contents($root . '/composer.json', '{"require": {"psr/log": "^1.0"}}');
        $t = (new ComposerAuditor())->audit($this->context($root, $mode), '');

        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $calls = file($log, FILE_IGNORE_NEW_LINES) ?: [];
        $this->assertCount(2, $calls);
        $this->assertStringStartsWith('update -W --no-install', $calls[0]);
        $this->assertStringStartsWith('audit --locked', $calls[1]);
        $this->assertFileDoesNotExist($root . '/composer.lock', 'neither left behind nor committed');
        $this->assertContains('no composer.lock: audited a fresh resolution, then deleted it', $t->notes);
    }

    public function testComposerKeepsALockfileTheProjectHas(): void
    {
        $log  = $this->fakeComposer();
        $root = $this->scratchDir('app');
        file_put_contents($root . '/composer.json', '{}');
        file_put_contents($root . '/composer.lock', '{"old": true}');

        (new ComposerAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertSame(['audit --locked --no-interaction --format=json'], file($log, FILE_IGNORE_NEW_LINES), 'check mode only audits');
        $this->assertSame('{"old": true}', file_get_contents($root . '/composer.lock'));

        unlink($log);
        (new ComposerAuditor())->audit($this->context($root, ['--update']), '');
        $calls = file($log, FILE_IGNORE_NEW_LINES) ?: [];
        $this->assertStringStartsWith('update -W', $calls[0]);
        $this->assertSame("{}\n", file_get_contents($root . '/composer.lock'), 'update mode keeps the updated lockfile');
    }

    /**
     * @return array<string, array{string, string, bool, bool}>
     */
    public static function sbtProjects(): array
    {
        // build.properties version ('' = none: the runner's 2.0.10), where the plugin is, --server, injected
        return [
            'sbt 2, no plugin'                   => ['2.0.10', '', true, true],
            'sbt 2 ignores global plugins'       => ['2.0.10', '.sbt/1.0/plugins/p.sbt', true, true],
            'no build.properties: sbt 1, under the sbt 2 runner' => ['', '', true, true],
            'no build.properties: sbt 1 global plugins'          => ['', '.sbt/1.0/plugins/p.sbt', true, false],
            'sbt 1, no plugin'                   => ['1.10.11', '', false, true],
            'sbt 1, global plugin'               => ['1.10.11', '.sbt/1.0/plugins/p.sbt', false, false],
            'sbt 1, plugin in the project'       => ['1.13.0', 'project/plugins.sbt', false, false],
            'sbt 0.13, global plugin'            => ['0.13.15', '.sbt/0.13/plugins/p.sbt', false, false],
        ];
    }

    #[DataProvider('sbtProjects')]
    public function testSbtRunsInTheForegroundWithThePluginAddedWhenMissing(string $version, string $plugin, bool $server, bool $injected): void
    {
        [$root, $home, $log] = $this->sbtProject($version);
        if ($plugin !== '') {
            $file = (str_starts_with($plugin, 'project/') ? $root : $home) . '/' . $plugin;
            @mkdir(dirname($file), 0775, true);
            file_put_contents($file, 'addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.7.1")');
        }
        $ctx = $this->context($root, ['--check']);
        $t   = (new SbtAuditor())->audit($ctx, '');

        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $call = (string)file_get_contents($log);
        $this->assertStringStartsWith('SBT_NATIVE_CLIENT=false ', $call, 'never the native client');
        $this->assertSame($server, str_contains($call, ' --server '));
        $this->assertSame($injected, str_contains($call, '--addPluginSbtFile='));
        $this->assertSame($version === '', str_contains($call, ' -Dsbt.version=' . SbtAuditor::SBT1 . ' '), 'a build that names no version predates sbt 2');
        $this->assertStringContainsString(' -Dsbt.skip.version.write=true ', $call, 'no build.properties written into the tree');
        $this->assertStringEndsWith(" -batch dependencyUpdates\n", $call);
        if ($injected) {
            $file = $ctx->reportPath('sbt', '', 'sbt-updates.sbt');
            $this->assertStringContainsString("--addPluginSbtFile={$file} ", $call, 'kept outside the tree');
            $this->assertStringContainsString('"sbt-updates" % "0.7.1"', (string)file_get_contents($file));
            $this->assertSame(['build.sbt', 'project'], array_values(array_diff(scandir($root) ?: [], ['.', '..'])));
        }
    }

    public function testOldSbtWithoutThePluginIsSkippedWithTheLineToAdd(): void
    {
        [$root, $home, $log] = $this->sbtProject('0.13.15');
        $t = (new SbtAuditor())->audit($this->context($root, ['--check']), '');
        $this->assertSame(TargetResult::SKIP, $t->status);
        $this->assertStringContainsString('addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.6.4")', $t->detail);
        $this->assertStringContainsString("{$home}/.sbt/0.13/plugins/sbt-updates.sbt", $t->detail);
        $this->assertFileDoesNotExist($log, 'no JVM started for a guaranteed failure');
    }

    /**
     * A stand-in composer that logs its arguments: update writes a
     * lockfile, audit reports no advisories.
     */
    private function fakeComposer(): string
    {
        $bin = $this->scratchDir('bin');
        $log = $bin . '/calls.log';
        file_put_contents($bin . '/composer', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            case "\$1" in
              update) echo '{}' > composer.lock ;;
              audit) echo '{"advisories": {}, "abandoned": {}}' ;;
            esac
            SH);
        chmod($bin . '/composer', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        return $log;
    }

    /**
     * An sbt project (build.properties only when $version is given), a HOME
     * without global plugins, and a stand-in sbt whose runner is 2.0.10 and
     * which logs SBT_NATIVE_CLIENT and its arguments.
     *
     * @return array{string, string, string} root, home, log
     */
    private function sbtProject(string $version): array
    {
        $bin  = $this->scratchDir('bin');
        $log  = $bin . '/calls.log';
        $home = $this->scratchDir('home');
        file_put_contents($bin . '/sbt', <<<SH
            #!/bin/sh
            if [ "\$1" = --script-version ]; then echo 2.0.10; exit 0; fi
            echo "SBT_NATIVE_CLIENT=\$SBT_NATIVE_CLIENT \$*" >> '{$log}'
            SH);
        chmod($bin . '/sbt', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        $this->setEnv('HOME', $home);

        $root = $this->scratchDir('scala');
        file_put_contents($root . '/build.sbt', '');
        mkdir($root . '/project');
        if ($version !== '') {
            file_put_contents($root . '/project/build.properties', "sbt.version={$version}\n");
        }
        return [$root, $home, $log];
    }

    /**
     * Run Scanners::trivy against a stand-in trivy that answers each online
     * call with the next scripted response: a Retry-After value (a 429 and
     * exit 1) or "ok". An --offline-scan call always succeeds.
     *
     * @param list<string> $responses
     * @return array{TargetResult, list<string>}
     */
    private function trivyWith(array $responses): array
    {
        $bin   = $this->scratchDir('bin');
        $log   = $bin . '/calls.log';
        $queue = $bin . '/responses';
        file_put_contents($queue, implode("\n", $responses) . "\n");
        $report = json_encode(['Results' => [['Vulnerabilities' => [['Severity' => 'HIGH']]]]]);
        $limited = addcslashes(sprintf(self::LIMITED, '$next'), '"');
        file_put_contents($bin . '/trivy', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            out=''
            prev=''
            for a in "\$@"; do [ "\$prev" = --output ] && out="\$a"; prev="\$a"; done
            case " \$* " in *" --offline-scan "*) printf '%s' '{$report}' > "\$out"; exit 0;; esac
            next=\$(head -n 1 '{$queue}'); sed -i 1d '{$queue}'
            if [ "\$next" = ok ]; then printf '%s' '{$report}' > "\$out"; exit 0; fi
            printf "{$limited}" >&2
            exit 1
            SH);
        chmod($bin . '/trivy', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));

        $t = Scanners::trivy($this->context($this->scratchDir('tree'), ['--check']));
        return [$t, file($log, FILE_IGNORE_NEW_LINES) ?: []];
    }

    /**
     * @param list<string> $args
     */
    private function context(string $root, array $args): Context
    {
        [$console, $runner] = $this->quietRunner(30);
        return new Context(Options::parse($args, []), $console, $runner, $root, $this->scratchDir('reports'), ManifestIndex::fromList($root, []));
    }
}
