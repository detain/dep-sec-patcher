<?php

declare(strict_types=1);

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\Auditor\MavenAuditor;
use Detain\DepSecPatcher\Auditor\MavenPom;
use Detain\DepSecPatcher\Context;
use Detain\DepSecPatcher\ManifestIndex;
use Detain\DepSecPatcher\Options;
use Detain\DepSecPatcher\TargetResult;
use PHPUnit\Framework\TestCase;

/**
 * Maven update mode: undoing only the version changes that do not resolve,
 * and pinning the vulnerable transitive artifacts dependency-check finds,
 * driven through a stand-in mvn on PATH and a stand-in version listing.
 */
class MavenAuditorTest extends TestCase
{
    use Fixtures;

    private const VERSIONS = [
        'com.fasterxml.jackson.core:jackson-annotations'        => ['2.9.5', '2.19.4', '2.21', '2.22'],
        'com.fasterxml.jackson.datatype:jackson-datatype-joda'  => ['2.9.5', '2.19.4', '2.22.0', '2.22.4'],
        'com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider' => ['2.9.5', '2.19.4', '2.22', '2.22.4'],
        'org.yaml:snakeyaml'                                    => ['1.30', '1.31', '1.33', '2.0', '2.2', '2.3-rc1'],
        'org.springframework:spring-aop'                        => ['5.3.31', '5.3.39', '6.2.1'],
        'org.springframework:spring-context'                    => ['5.3.31', '5.3.39', '6.2.1'],
        'io.netty:netty-common'                                 => ['4.1.67.Final', '4.1.135.Final'],
    ];

    private const POM = <<<'XML'
        <project>
          <groupId>g</groupId>
          <artifactId>p</artifactId>
          <version>1.0.0</version>
          <dependencies>
            <dependency>
              <groupId>com.fasterxml.jackson.datatype</groupId>
              <artifactId>jackson-datatype-joda</artifactId>
              <version>${jackson-version}</version>
            </dependency>
            <dependency>
              <groupId>com.fasterxml.jackson.jaxrs</groupId>
              <artifactId>jackson-jaxrs-json-provider</artifactId>
              <version>${jackson-version}</version>
            </dependency>
            <dependency>
              <groupId>com.fasterxml.jackson.core</groupId>
              <artifactId>jackson-annotations</artifactId>
              <version>${jackson-version}</version>
            </dependency>
            <dependency>
              <groupId>org.example</groupId>
              <artifactId>lib</artifactId>
              <version>1.0</version>
              <exclusions><exclusion><groupId>x</groupId><artifactId>y</artifactId></exclusion></exclusions>
            </dependency>
          </dependencies>
          <properties>
            <jackson-version>2.9.5</jackson-version>
            <logback-version>1.0</logback-version>
          </properties>
        </project>

        XML;

    protected function tearDown(): void
    {
        $this->cleanupFixtures();
    }

    public function testPomSitesAndEdits(): void
    {
        $sites = MavenPom::sites(self::POM);
        $this->assertSame(['jackson-version' => '2.9.5', 'logback-version' => '1.0'], $sites['props']);
        $this->assertSame(['org.example:lib' => '1.0'], $sites['lits'], 'an exclusion is not a site');
        $this->assertSame([
            'com.fasterxml.jackson.datatype:jackson-datatype-joda',
            'com.fasterxml.jackson.jaxrs:jackson-jaxrs-json-provider',
            'com.fasterxml.jackson.core:jackson-annotations',
        ], $sites['refs']['jackson-version']);
        $this->assertSame('g:p', MavenPom::coordinate(self::POM));

        $edited = MavenPom::setProperty(self::POM, 'jackson-version', '2.9.5', '2.19.4');
        $this->assertSame(str_replace('>2.9.5<', '>2.19.4<', self::POM), $edited);
        $this->assertSame(self::POM, MavenPom::setProperty(self::POM, 'jackson-version', '2.22', '2.19.4'), 'only where it holds the value');
        $edited = MavenPom::setVersion(self::POM, 'org.example:lib', '1.0', '1.1');
        $this->assertSame(str_replace('<version>1.0</version>', '<version>1.1</version>', self::POM), $edited);
        $this->assertSame(self::POM, MavenPom::setVersion(self::POM, 'org.example:other', '1.0', '1.1'));

        $plugin = '<plugin><artifactId>maven-war-plugin</artifactId><version>3.1.0</version>'
            . '<dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>${b-version}</version></dependency></dependencies></plugin>';
        $sites  = MavenPom::sites($plugin);
        $this->assertSame(['org.apache.maven.plugins:maven-war-plugin' => '3.1.0'], $sites['lits']);
        $this->assertSame(['b-version' => ['a:b']], $sites['refs']);
    }

    public function testMetadataAndTheNewestReleaseOnALine(): void
    {
        $xml = '<metadata><versioning><latest>2.3-rc1</latest><release>2.2</release><versions><version>1.30</version>'
            . '<version>1.33</version><version>2.2</version><version>2.3-rc1</version></versions></versioning></metadata>';
        $this->assertSame(['1.30', '1.33', '2.2', '2.3-rc1'], MavenPom::metadataVersions($xml));

        $v = self::VERSIONS['org.yaml:snakeyaml'];
        $this->assertSame('1.33', MavenPom::newestOnLine($v, '1.30', false));
        $this->assertSame('2.2', MavenPom::newestOnLine($v, '1.30', true), 'never the release candidate');
        $this->assertSame('', MavenPom::newestOnLine($v, '1.30', false, ['2.0']), 'the fix is on the next major only');
        $this->assertSame('', MavenPom::newestOnLine($v, '1.30', false, [], ['1.33']));
        $this->assertSame('', MavenPom::newestOnLine($v, '2.2', false));
    }

    public function testAPropertyWithNoSuchVersionForSomeUserGoesToTheNewestTheyAllHave(): void
    {
        $log  = $this->fakeMaven(['update' => 's#<jackson-version>2.9.5<#<jackson-version>2.22<#; s#<logback-version>1.0<#<logback-version>1.1<#']);
        $root = $this->project(self::POM);

        $t = $this->auditor()->audit($this->context($root, ['--update']), '');

        $pom = (string)file_get_contents($root . '/pom.xml');
        $this->assertStringContainsString('<jackson-version>2.19.4</jackson-version>', $pom, 'annotations has no 2.22.4, so 2.22.x is not shared');
        $this->assertStringContainsString('<logback-version>1.1</logback-version>', $pom, 'the rest of the update stays');
        $this->assertSame(TargetResult::PASS, $t->status, $t->detail);
        $this->assertSame([
            'the version update left pom.xml unresolvable (com.fasterxml.jackson.datatype:jackson-datatype-joda:jar:2.22); set ${jackson-version}'
                . ' to 2.19.4 (com.fasterxml.jackson.datatype:jackson-datatype-joda has no 2.22; 2.19.4 is the newest release all 3 artifacts using it have)'
                . ' and kept the rest of it',
        ], $t->notes);
        $this->assertCount(2, $this->calls($log, 'dependency:resolve'));
    }

    public function testAPropertyWithNoCommonNewerReleaseGoesBack(): void
    {
        $this->fakeMaven(['update' => 's#<jackson-version>2.9.5<#<jackson-version>2.22<#; s#<logback-version>1.0<#<logback-version>1.1<#']);
        $root = $this->project(self::POM);

        $t = $this->auditor(['com.fasterxml.jackson.core:jackson-annotations' => ['2.9.5', '2.22']])->audit($this->context($root, ['--update']), '');

        $this->assertSame(str_replace('>1.0</logback', '>1.1</logback', self::POM), file_get_contents($root . '/pom.xml'));
        $this->assertStringContainsString('set ${jackson-version} to 2.9.5 (com.fasterxml.jackson.datatype:jackson-datatype-joda has no 2.22)', $t->notes[0]);
    }

    public function testAChangedVersionThatDoesNotResolveIsPutBackAlone(): void
    {
        $this->fakeMaven([
            'update'  => 's#<version>1.0</version>#<version>9.9</version>#; s#<logback-version>1.0<#<logback-version>1.1<#',
            'missing' => ['<version>9.9<' => 'org.example:lib:jar:9.9'],
        ]);
        $root = $this->project(self::POM);

        $t = $this->auditor()->audit($this->context($root, ['--update']), '');

        $this->assertSame(str_replace('>1.0</logback', '>1.1</logback', self::POM), file_get_contents($root . '/pom.xml'));
        $this->assertStringContainsString('set org.example:lib to 1.0 (org.example:lib has no 9.9) and kept the rest of it', $t->notes[0]);
    }

    public function testWhatTheNarrowingCannotFixIsRevertedWhole(): void
    {
        // The failure names an artifact no changed site leads to
        $this->fakeMaven([
            'update'  => 's#<logback-version>1.0<#<logback-version>1.1<#',
            'missing' => ['<logback-version>1.1<' => 'ch.qos.logback:logback-core:jar:1.1'],
        ]);
        $root = $this->project(self::POM);

        $t = $this->auditor()->audit($this->context($root, ['--update']), '');

        $this->assertSame(self::POM, file_get_contents($root . '/pom.xml'));
        $this->assertSame(TargetResult::WARN, $t->status);
        $this->assertStringContainsString('reverted 1 pom to the pre-update content', $t->notes[0]);
    }

    public function testVulnerableArtifactsAreReadFromTheReport(): void
    {
        $found = MavenAuditor::vulnerableArtifacts(self::report());
        $this->assertSame([
            'io.netty:netty-common'               => ['versions' => ['4.1.67.Final'], 'floors' => [], 'above' => ['4.1.70.Final']],
            'org.springframework:spring-aop'      => ['versions' => ['5.3.31'], 'floors' => ['5.3.33'], 'above' => []],
            'org.springframework:spring-context'  => ['versions' => ['5.3.31'], 'floors' => ['5.3.33'], 'above' => []],
            'org.yaml:snakeyaml'                  => ['versions' => ['1.30'], 'floors' => ['1.31', '2.0'], 'above' => []],
        ], $found, 'the folded spring-context counts, the shaded copy and the JavaScript do not');
        $this->assertSame([], MavenAuditor::vulnerableArtifacts('nope'));
    }

    public function testVulnerableTransitiveArtifactsArePinnedOnTheLineInUse(): void
    {
        $log  = $this->fakeMaven(['report' => self::report()]);
        $pom  = str_replace('</dependencies>', "  <dependency><groupId>io.netty</groupId><artifactId>netty-common</artifactId><version>4.1.67.Final</version></dependency>\n  </dependencies>", self::POM);
        $root = $this->project($pom);

        $t = $this->auditor()->audit($this->context($root, ['--update']), '');

        $after = (string)file_get_contents($root . '/pom.xml');
        $this->assertSame(1, substr_count($after, '<dependencyManagement>'));
        foreach (['snakeyaml</artifactId>\s*<version>1.33<', 'spring-aop</artifactId>\s*<version>5.3.39<', 'spring-context</artifactId>\s*<version>5.3.39<'] as $rx) {
            $this->assertMatchesRegularExpression('#<dependencyManagement>.*' . $rx . '#s', $after);
        }
        $this->assertStringContainsString('<version>4.1.67.Final</version>', $after, 'a declared artifact is left to the versions plugin and auto-fix');
        $this->assertStringContainsString('pinned 3 vulnerable transitive dependencies in <dependencyManagement>: org.springframework:spring-aop 5.3.31 -> 5.3.39;'
            . ' org.springframework:spring-context 5.3.31 -> 5.3.39; org.yaml:snakeyaml 1.30 -> 1.33 (a full fix needs 2.0, --allow-major)', implode("\n", $t->notes));
        $this->assertStringContainsString('dependency-check before the pins: dependency-check: 6 vulnerabilities in 4 dependencies', implode("\n", $t->notes));
        $this->assertCount(2, $this->calls($log, ':check'), 'checked again after pinning');

        // --allow-major takes the newest release
        $root = $this->project(self::POM);
        $this->auditor()->audit($this->context($root, ['--update', '--allow-major']), '');
        $this->assertMatchesRegularExpression('#snakeyaml</artifactId>\s*<version>2.2<#', (string)file_get_contents($root . '/pom.xml'));
        $this->assertMatchesRegularExpression('#spring-aop</artifactId>\s*<version>6.2.1<#', (string)file_get_contents($root . '/pom.xml'));
    }

    public function testAPinThatDoesNotResolveIsDropped(): void
    {
        $this->fakeMaven(['report' => self::report(), 'missing' => ['<version>1.33<' => 'org.yaml:snakeyaml:jar:1.33']]);
        $root = $this->project(self::POM);

        $t = $this->auditor()->audit($this->context($root, ['--update']), '');

        $after = (string)file_get_contents($root . '/pom.xml');
        $this->assertStringNotContainsString('snakeyaml', $after);
        $this->assertStringContainsString('spring-aop', $after);
        $this->assertStringContainsString('not pinned, the pinned version does not resolve: org.yaml:snakeyaml 1.33', implode("\n", $t->notes));
    }

    public function testPinsThatBreakResolutionAreAllLeftOut(): void
    {
        $this->fakeMaven(['report' => self::report(), 'missing' => ['<dependencyManagement>' => 'com.example:bom:pom:1']]);
        $root = $this->project(self::POM);

        $t = $this->auditor()->audit($this->context($root, ['--update']), '');

        $this->assertSame(self::POM, file_get_contents($root . '/pom.xml'));
        $this->assertStringContainsString('WARN: pinning 4 transitive dependencies left pom.xml unresolvable (com.example:bom:pom:1); left them unpinned', implode("\n", $t->notes));
    }

    public function testCheckModePinsNothing(): void
    {
        $log  = $this->fakeMaven(['report' => self::report()]);
        $root = $this->project(self::POM);
        $this->auditor()->audit($this->context($root, ['--check']), '');
        $this->assertSame(self::POM, file_get_contents($root . '/pom.xml'));
        $this->assertCount(1, $this->calls($log, ':check'));
    }

    private static function report(): string
    {
        $vuln = static fn (string $cve, array $sw): array => ['name' => $cve, 'cvssv3' => ['baseScore' => 7.5], 'vulnerableSoftware' => [['software' => $sw]]];
        return (string)json_encode(['dependencies' => [
            ['fileName' => 'snakeyaml-1.30.jar', 'packages' => [['id' => 'pkg:maven/org.yaml/snakeyaml@1.30']], 'vulnerabilities' => [
                $vuln('CVE-2022-1471', ['id' => 'cpe:x', 'vulnerabilityIdMatched' => 'true', 'versionEndExcluding' => '2.0']),
                $vuln('CVE-2022-25857', ['id' => 'cpe:x', 'vulnerabilityIdMatched' => 'true', 'versionEndExcluding' => '1.31']),
                $vuln('CVE-unmatched', ['id' => 'cpe:x', 'versionEndExcluding' => '9.0']),
            ]],
            ['fileName' => 'spring-aop-5.3.31.jar', 'packages' => [['id' => 'pkg:maven/org.springframework/spring-aop@5.3.31']],
                'relatedDependencies' => [['fileName' => 'spring-context-5.3.31.jar', 'packageIds' => [['id' => 'pkg:maven/org.springframework/spring-context@5.3.31']]]],
                'vulnerabilities' => [$vuln('CVE-2024-22259', ['id' => 'cpe:y', 'vulnerabilityIdMatched' => 'true', 'versionEndExcluding' => '5.3.33'])]],
            ['fileName' => 'netty-common-4.1.67.Final.jar', 'packages' => [
                ['id' => 'pkg:maven/io.netty/netty-common@4.1.67.Final'], ['id' => 'pkg:maven/com.shaded/inner@1.0'],
            ], 'vulnerabilities' => [$vuln('CVE-n', ['id' => 'cpe:z', 'vulnerabilityIdMatched' => 'true', 'versionEndIncluding' => '4.1.70.Final'])]],
            ['fileName' => 'swagger-ui.jar: bundle.js', 'packages' => [['id' => 'pkg:javascript/DOMPurify@3.0.9']], 'vulnerabilities' => [$vuln('CVE-js', [])]],
            ['fileName' => 'clean-1.0.jar', 'packages' => [['id' => 'pkg:maven/a/clean@1.0']], 'vulnerabilities' => []],
        ]]);
    }

    /**
     * A stand-in mvn. $spec: update => sed script update-properties applies;
     * missing => pom.xml substring => the coordinate dependency:resolve
     * reports missing while the pom holds it (by default the jackson 2.22
     * failure of jackson-datatype-joda); report => the dependency-check report.
     *
     * @param array{update?: string, missing?: array<string, string>, report?: string} $spec
     */
    private function fakeMaven(array $spec): string
    {
        $bin    = $this->scratchDir('bin');
        $log    = $bin . '/calls.log';
        $report = $bin . '/report.json';
        file_put_contents($report, $spec['report'] ?? '{"dependencies": []}');
        $sed     = escapeshellarg($spec['update'] ?? 's#x#x#');
        $checks  = '';
        foreach ($spec['missing'] ?? ['<jackson-version>2.22<' => 'com.fasterxml.jackson.datatype:jackson-datatype-joda:jar:2.22'] as $needle => $coord) {
            $checks .= 'if grep -q ' . escapeshellarg($needle) . " pom.xml; then echo '[ERROR] Failed to execute goal on project p: Could not resolve dependencies for project g:p:jar:1.0.0';"
                . " echo '[ERROR] dependency: {$coord} (compile)'; echo '[ERROR]   Could not find artifact {$coord} in central'; fail=1; fi\n";
        }
        file_put_contents($bin . '/mvn', <<<SH
            #!/bin/sh
            echo "\$*" >> '{$log}'
            for a in "\$@"; do
              case "\$a" in -Dodc.outputDirectory=*) cp '{$report}' "\${a#*=}/dependency-check-report.json" ;; esac
            done
            case " \$* " in
              *":update-properties "*) sed -i {$sed} pom.xml ;;
              *" dependency:resolve "*)
                {$checks}
                exit \${fail:-0} ;;
            esac
            SH);
        chmod($bin . '/mvn', 0755);
        $this->setEnv('PATH', $bin . ':' . getenv('PATH'));
        return $log;
    }

    /**
     * @return list<string>
     */
    private function calls(string $log, string $goal): array
    {
        return array_values(array_filter(file($log, FILE_IGNORE_NEW_LINES) ?: [], static fn (string $c): bool => str_contains($c, $goal)));
    }

    private function project(string $pom): string
    {
        $root = $this->scratchDir('java');
        file_put_contents($root . '/pom.xml', $pom);
        return $root;
    }

    /**
     * @param array<string, list<string>> $override
     */
    private function auditor(array $override = []): MavenAuditor
    {
        $versions = $override + self::VERSIONS;
        return new MavenAuditor(static fn (string $g, string $a): array => $versions["{$g}:{$a}"] ?? []);
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
