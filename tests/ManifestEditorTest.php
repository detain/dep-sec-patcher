<?php

namespace Detain\DepSecPatcher\Tests;

use Detain\DepSecPatcher\ManifestEditor;
use PHPUnit\Framework\TestCase;

/**
 * Manifest rewrites (ported from the original shell script's perl/jq) and their
 * inverse, declared(). On a public repository's 620 pending fixes the port made
 * the same edits as the original shell script, apart from the bugs fixed here.
 */
class ManifestEditorTest extends TestCase
{
    /**
     * @return array{status: string, content: string}
     */
    private static function apply(string $eco, string $path, string $content, string $pkg, string $ver, string $max = '', bool $yarn = false): array
    {
        return ManifestEditor::apply($eco, $path, $content, $pkg, $ver, $max, $yarn);
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    public function testNpmBumpKeepsRangePrefixAndIndent(): void
    {
        $json = "{\n    \"name\": \"x\",\n    \"dependencies\": {\n        \"qs\": \"^6.11.0\"\n    }\n}\n";
        $res  = self::apply('npm', 'package.json', $json, 'qs', '6.15.2');
        $this->assertSame(ManifestEditor::OK, $res['status']);
        $this->assertSame("{\n    \"name\": \"x\",\n    \"dependencies\": {\n        \"qs\": \"^6.15.2\"\n    }\n}\n", $res['content']);
        $this->assertSame('^6.15.2', ManifestEditor::declared('npm', 'package.json', $res['content'], 'qs'));
    }

    public function testNpmRefusesDowngrade(): void
    {
        $json = "{\n  \"dependencies\": {\n    \"express\": \"^4.16.0\"\n  }\n}\n";
        $res  = self::apply('npm', 'package.json', $json, 'express', '4.0.0');
        $this->assertSame(ManifestEditor::REFUSED, $res['status']);
        $this->assertSame($json, $res['content']);
    }

    public function testNpmTransitiveBecomesOverrideAtPackageMaximum(): void
    {
        $json = "{\n  \"name\": \"x\",\n  \"dependencies\": {}\n}\n";
        $res  = self::apply('npm', 'package.json', $json, 'minimatch', '3.1.2', '3.1.4', true);
        $doc  = json_decode($res['content'], true);
        $this->assertSame(['minimatch' => '3.1.4'], $doc['overrides']);
        $this->assertSame(['minimatch' => '3.1.4'], $doc['resolutions'], 'yarn honours resolutions');
        $this->assertSame([], $doc['dependencies'], 'empty object survives');
        $this->assertStringContainsString('"dependencies": {}', $res['content']);
    }

    public function testNpmNoValueChangeLeavesFormattingAlone(): void
    {
        $json = "{\"overrides\":{\"a\":\"1.0.0\"}}";
        $res  = self::apply('npm', 'package.json', $json, 'a', '1.0.0', '1.0.0');
        $this->assertSame($json, $res['content']);
    }

    // ── composer ─────────────────────────────────────────────────────────────

    public function testComposerBumpsRequireDev(): void
    {
        // The original shell script looked up `.[".require-dev"]`, so this never changed
        $json = "{\n    \"require-dev\": {\n        \"guzzlehttp/guzzle\": \"^7.0\"\n    }\n}\n";
        $res  = self::apply('composer', 'composer.json', $json, 'guzzlehttp/guzzle', '7.15.2');
        $this->assertSame("{\n    \"require-dev\": {\n        \"guzzlehttp/guzzle\": \"^7.15.2\"\n    }\n}\n", $res['content']);
    }

    public function testComposerUndeclaredPackageIsUnchanged(): void
    {
        $json = "{\n    \"require\": {\n        \"php\": \">=8.1\"\n    }\n}\n";
        $this->assertSame($json, self::apply('composer', 'composer.json', $json, 'a/b', '1.0')['content']);
    }

    // ── pip ──────────────────────────────────────────────────────────────────

    public function testRequirementsLineIsPinned(): void
    {
        $txt = "certifi>=2023.1.1\nurllib3 >= 1.25.3, < 3.0.0\npython_dateutil[extra] >= 2.8.2\nrequests-toolbelt==1.0\n";
        $res = self::apply('pip', 'requirements.txt', $txt, 'urllib3', '2.6.3');
        $res = self::apply('pip', 'requirements.txt', $res['content'], 'python-dateutil', '2.9.0');
        $this->assertSame("certifi>=2023.1.1\nurllib3==2.6.3\npython-dateutil[extra]==2.9.0\nrequests-toolbelt==1.0\n", $res['content']);
    }

    public function testPyprojectTableAndArrayForms(): void
    {
        $toml = "[tool.poetry.dependencies]\npytest = \">= 8.4.2\"\n[project]\ndependencies = [\n  \"urllib3>=1.25\",\n]\n";
        $res  = self::apply('pip', 'pyproject.toml', $toml, 'pytest', '9.0.3');
        $res  = self::apply('pip', 'pyproject.toml', $res['content'], 'urllib3', '2.6.3');
        $this->assertSame("[tool.poetry.dependencies]\npytest = \">= 9.0.3\"\n[project]\ndependencies = [\n  \"urllib3>=2.6.3\",\n]\n", $res['content']);
        // The original shell script could not read the TOML table form back
        $this->assertSame('9.0.3', ManifestEditor::declared('pip', 'pyproject.toml', $res['content'], 'pytest'));
        $this->assertSame('2.6.3', ManifestEditor::declared('pip', 'pyproject.toml', $res['content'], 'urllib3'));
    }

    public function testPipNameMatchingIsNormalised(): void
    {
        $this->assertSame('2.8.2', ManifestEditor::declared('pip', 'requirements.txt', "Python_DateUtil>=2.8.2\n", 'python-dateutil'));
        $this->assertSame('', ManifestEditor::declared('pip', 'requirements.txt', "pytest-cov==4.0\n", 'pytest'));
    }

    // ── maven ────────────────────────────────────────────────────────────────

    private const POM = <<<'XML'
<project>
  <properties>
    <jackson.version>2.15.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.code.gson</groupId>
      <artifactId>gson</artifactId>
      <version>2.8.1</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
  </dependencies>
</project>

XML;

    public function testMavenLiteralVersion(): void
    {
        $res = self::apply('maven', 'pom.xml', self::POM, 'com.google.code.gson:gson', '2.13.1');
        $this->assertStringContainsString("<artifactId>gson</artifactId>\n      <version>2.13.1</version>", $res['content']);
        $this->assertSame('2.13.1', ManifestEditor::declared('maven', 'pom.xml', $res['content'], 'com.google.code.gson:gson'));
    }

    public function testMavenPropertyIndirection(): void
    {
        $this->assertSame('2.15.0', ManifestEditor::declared('maven', 'pom.xml', self::POM, 'com.fasterxml.jackson.core:jackson-databind'));
        $res = self::apply('maven', 'pom.xml', self::POM, 'com.fasterxml.jackson.core:jackson-databind', '2.18.8');
        $this->assertStringContainsString('<jackson.version>2.18.8</jackson.version>', $res['content']);
        $this->assertStringContainsString('<version>${jackson.version}</version>', $res['content'], 'reference untouched');
    }

    public function testMavenBareArtifactName(): void
    {
        $this->assertSame('2.8.1', ManifestEditor::declared('maven', 'pom.xml', self::POM, 'gson'));
    }

    public function testMavenTransitiveGetsDependencyManagement(): void
    {
        $res = self::apply('maven', 'pom.xml', self::POM, 'io.netty:netty-handler', '4.1.118.Final');
        $this->assertMatchesRegularExpression(
            '#<dependencyManagement>\s*<dependencies>\s*<dependency>\s*<groupId>io\.netty</groupId>\s*<artifactId>netty-handler</artifactId>\s*<version>4\.1\.118\.Final</version>\s*</dependency>\s*</dependencies>\s*</dependencyManagement>\s*</project>#',
            $res['content']
        );
        // A second transitive pin joins the existing block
        $res = self::apply('maven', 'pom.xml', $res['content'], 'io.netty:netty-codec', '4.1.118.Final');
        $this->assertSame(1, substr_count($res['content'], '<dependencyManagement>'));
        $this->assertStringContainsString('<artifactId>netty-codec</artifactId>', $res['content']);
    }

    public function testMavenBareTransitiveArtifactIsNotGuessed(): void
    {
        $this->assertSame(self::POM, self::apply('maven', 'pom.xml', self::POM, 'netty-handler', '4.1.118.Final')['content']);
    }

    public function testMavenHugePomDoesNotBlankTheFile(): void
    {
        // A regex failure must leave the manifest as it was, never empty
        $big = self::POM . str_repeat("<!-- " . str_repeat('x', 200) . " -->\n", 50000);
        $res = self::apply('maven', 'pom.xml', $big, 'com.google.code.gson:gson', '2.13.1');
        $this->assertNotSame('', $res['content']);
    }

    // ── the rest ─────────────────────────────────────────────────────────────

    public function testGradle(): void
    {
        $g   = "dependencies {\n  implementation 'com.squareup.okio:okio:1.6.0'\n  implementation \"com.google.code.gson:gson:2.8.1\"\n}\n";
        $res = self::apply('gradle', 'build.gradle', $g, 'com.squareup.okio:okio', '3.6.0');
        $this->assertStringContainsString("'com.squareup.okio:okio:3.6.0'", $res['content']);
        $this->assertSame('2.8.1', ManifestEditor::declared('gradle', 'build.gradle', $g, 'com.google.code.gson:gson'));
        $this->assertSame(ManifestEditor::UNSUPPORTED, self::apply('gradle', 'build.gradle', $g, 'okio', '3.6.0')['status']);
    }

    public function testGoExactModulePathOnly(): void
    {
        $mod = "module x\n\nrequire (\n\tgolang.org/x/net v0.47.0 // indirect\n\tgithub.com/a/net v1.0.0\n)\n\nrequire golang.org/x/text v0.3.0\n";
        $res = self::apply('go', 'go.mod', $mod, 'golang.org/x/net', '0.55.0');
        $this->assertStringContainsString("\tgolang.org/x/net v0.55.0 // indirect\n", $res['content']);
        $this->assertStringContainsString("github.com/a/net v1.0.0", $res['content']);
        $this->assertSame($mod, self::apply('go', 'go.mod', $mod, 'net', '0.55.0')['content'], 'short names never match');
        $this->assertSame('0.3.0', ManifestEditor::declared('go', 'go.mod', $mod, 'golang.org/x/text'), 'single-line require');
        $this->assertStringContainsString('require golang.org/x/text v0.3.8', self::apply('go', 'go.mod', $mod, 'golang.org/x/text', 'v0.3.8')['content']);
    }

    public function testNugetBothAttributeOrders(): void
    {
        $xml = "<ItemGroup>\n  <PackageReference Include=\"RestSharp\" Version=\"111.4.1\" />\n  <PackageReference Version=\"8.0.4\" Include=\"System.Text.Json\" />\n</ItemGroup>\n";
        $res = self::apply('nuget', 'x.csproj', $xml, 'RestSharp', '112.0.0');
        $res = self::apply('nuget', 'x.csproj', $res['content'], 'System.Text.Json', '8.0.5');
        $this->assertStringContainsString('Include="RestSharp" Version="112.0.0"', $res['content']);
        $this->assertStringContainsString('Version="8.0.5" Include="System.Text.Json"', $res['content']);
        $this->assertSame('112.0.0', ManifestEditor::declared('nuget', 'x.csproj', $res['content'], 'RestSharp'));
    }

    public function testPubRubygemsCargoHex(): void
    {
        $pub = "dependencies:\n  http: ^0.13.0\n";
        $this->assertSame("dependencies:\n  http: ^1.2.2\n", self::apply('pub', 'pubspec.yaml', $pub, 'http', '1.2.2')['content']);
        $this->assertSame('0.13.0', ManifestEditor::declared('pub', 'pubspec.yaml', $pub, 'http'));

        $gem = "gem 'faraday', '~> 1.0'\n";
        $this->assertSame("gem 'faraday', '~> 2.12.3'\n", self::apply('rubygems', 'Gemfile', $gem, 'faraday', '2.12.3')['content']);
        $this->assertSame('1.0', ManifestEditor::declared('rubygems', 'Gemfile', $gem, 'faraday'));

        $cargo = "[dependencies]\nreqwest = { version = \"0.11\", features = [\"json\"] }\nurl = \"2.2\"\n";
        $res   = self::apply('cargo', 'Cargo.toml', $cargo, 'reqwest', '0.12.5');
        $res   = self::apply('cargo', 'Cargo.toml', $res['content'], 'url', '2.5.4');
        $this->assertSame("[dependencies]\nreqwest = { version = \"0.12.5\", features = [\"json\"] }\nurl = \"2.5.4\"\n", $res['content']);

        $hex = "{:tesla, \"~> 1.4\"},\n";
        $this->assertSame("{:tesla, \"~> 1.7.0\"},\n", self::apply('hex', 'mix.exs', $hex, 'tesla', '1.7.0')['content']);
        $this->assertSame('1.4', ManifestEditor::declared('hex', 'mix.exs', $hex, 'tesla'));
    }

    public function testUnknownEcosystem(): void
    {
        $this->assertSame(ManifestEditor::UNSUPPORTED, self::apply('swift', 'Package.swift', 'x', 'a', '1')['status']);
        $this->assertSame('', ManifestEditor::declared('swift', 'Package.swift', 'x', 'a'));
    }
}
