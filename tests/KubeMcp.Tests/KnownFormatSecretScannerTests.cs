using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Security;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace KubeMcp.Tests;

public sealed class KnownFormatSecretScannerTests
{
    private static readonly SecretScannerCorpus Corpus = SecretScannerCorpus.Instance;

    public static TheoryData<int, string> PositiveCases()
    {
        var data = new TheoryData<int, string>();
        for (var i = 0; i < Corpus.Positives.Count; i++)
        {
            data.Add(i, $"{Corpus.Positives[i].Rule} in {Corpus.Positives[i].Placement}");
        }

        return data;
    }

    public static TheoryData<string> NegativeCaseNames()
    {
        var data = new TheoryData<string>();
        foreach (var negative in Corpus.Negatives)
        {
            data.Add(negative.Name);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(PositiveCases))]
    public void PlantedCredentialIsDetectedAtItsPathAndNowhereElse(int index, string description)
    {
        var positive = Corpus.Positives[index];
        Assert.Equal(description, $"{positive.Rule} in {positive.Placement}");
        var root = positive.Root.DeepClone();

        var matches = KnownFormatSecretScanner.Scan(root, CancellationToken.None);

        Assert.Contains(matches, match => match.Path == positive.Path && match.RuleId == positive.Rule);
        Assert.All(matches, match => Assert.Equal(positive.Path, match.Path));
        KnownFormatSecretScanner.Redact(matches);
        var remaining = DecodedStrings(root).ToList();
        Assert.All(positive.Secrets, secret => Assert.DoesNotContain(remaining, value => value.Contains(secret, StringComparison.Ordinal)));
    }

    // Every string value, plus the strings of any JSON document embedded in one.
    private static IEnumerable<string> DecodedStrings(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject jsonObject:
                return jsonObject.SelectMany(property => DecodedStrings(property.Value));
            case JsonArray jsonArray:
                return jsonArray.SelectMany(DecodedStrings);
            case JsonValue value when value.GetValueKind() == JsonValueKind.String:
                var text = value.GetValue<string>();
                try
                {
                    return text.TrimStart().StartsWith('{') ? DecodedStrings(JsonNode.Parse(text)).Append(text) : [text];
                }
                catch (JsonException)
                {
                    return [text];
                }

            default:
                return [];
        }
    }

    [Theory]
    [MemberData(nameof(NegativeCaseNames))]
    public void RealisticObjectDoesNotTrigger(string name)
    {
        var negative = Corpus.Negatives.Single(candidate => candidate.Name == name);

        var matches = KnownFormatSecretScanner.Scan(negative.Root, CancellationToken.None);

        Assert.Empty(matches.Select(match => $"{match.RuleId} {match.Path}"));
    }

    [Fact]
    public void KubeMcpGeneratedValuesNeverTriggerEvenUnderSecretKeys()
    {
        var root = new JsonObject
        {
            ["password"] = "hmac-sha256:" + new string('a', 16) + "0123456789abcdef",
            ["token"] = KnownFormatSecretScanner.RedactionMarker("github-token"),
            ["env"] = new JsonArray(new JsonObject
            {
                ["name"] = "API_TOKEN",
                ["value"] = "hmac-sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f0"
            })
        };

        Assert.Empty(KnownFormatSecretScanner.Scan(root, CancellationToken.None));
        // Without the exclusion the fingerprint would pass the generic value filter.
        Assert.True(KnownFormatSecretScanner.IsNonTrivialGenericValue(
            "hmac-sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            KnownFormatSecretScanner.DefaultGenericMinEntropy));
    }

    [Fact]
    public void ReportsJsonPathOfEachMatchingStringValue()
    {
        var root = JsonNode.Parse("""
            {"data":{"tls.key":"plain","app.env":"DB_PASSWORD=Q7v!x9Lr#2mZp4Tk"},
             "spec":{"containers":[{"env":[{"name":"API_TOKEN","value":"V9b2Qx7LmN4pR8sT1wYz3cKd"}]}]}}
            """);

        var paths = KnownFormatSecretScanner.Scan(root, CancellationToken.None)
            .Select(match => $"{match.RuleId} {match.Path}")
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "generic-assignment $.data['app.env']",
                "generic-keyed-field $.spec.containers[0].env[0].value"
            ],
            paths);
    }

    public static TheoryData<string, string> RedactionCases()
    {
        var token = "gh" + "p_" + "Q7v9xLr2mZp4TkV9b2Qx7LmN4pR8sT1wYz3c";
        var password = "Xk2mQ9vL7pR4tW8z";
        var pemBody = string.Concat(Enumerable.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", 3));
        var pem = "-----BEGIN " + "PRIVATE KEY-----\n" + pemBody + "\n" + pemBody + "\n-----END " + "PRIVATE KEY-----";
        return new TheoryData<string, string>
        {
            { "LOG=info\nGITHUB_TOKEN=" + token + "\nX=1", "LOG=info\nGITHUB_TOKEN=[redacted:github-token]\nX=1" },
            { "a " + token + " b " + token, "a [redacted:github-token] b [redacted:github-token]" },
            { "postgres://app:" + password + "@db:5432/app", "postgres://app:[redacted:url-credentials]@db:5432/app" },
            { "tls:\n  key: |\n" + pem + "\n  cert: ok", "tls:\n  key: |\n[redacted:private-key]\n  cert: ok" },
            { "server: db\npassword: " + password + "\n", "[redacted:generic-assignment]" },
            // A covered generic candidate must not hide a later uncovered one.
            { "GITHUB_TOKEN=" + token + "\nDB_PASSWORD=" + password, "[redacted:generic-assignment]" },
            // Incomplete or over-long candidates redact the whole value.
            { "key: |\n-----BEGIN " + "PRIVATE KEY-----\n" + pemBody + "\nmode=fast", "[redacted:private-key]" },
            { "id=" + Jwt("e30", new string('s', 5000)), "[redacted:jwt]" },
            { "id=" + Jwt("e30", "c2lnbmF0dXJl") + " ok", "id=[redacted:jwt] ok" },
        };
    }

    [Theory]
    [MemberData(nameof(RedactionCases))]
    public void ExactFormatsRedactOnlyTheMatchedTextAndGenericRulesTheWholeValue(string value, string expected)
    {
        var root = new JsonObject { ["data"] = new JsonObject { ["config"] = value } };

        KnownFormatSecretScanner.Redact(KnownFormatSecretScanner.Scan(root, CancellationToken.None));

        Assert.Equal(expected, root["data"]!["config"]!.GetValue<string>());
    }

    private static string Jwt(string payload, string signature) =>
        Convert.ToBase64String("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"u8).TrimEnd('=') + "." + payload + "." + signature;

    [Fact]
    public void EmbeddedJsonBeyondTheDepthBudgetFailsClosed()
    {
        var root = new JsonObject { ["blob"] = new string('[', 100) + new string(']', 100) };

        var exception = Assert.Throws<KubernetesReadException>(() => KnownFormatSecretScanner.Scan(root, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.CredentialScanFailed, exception.Category);
    }

    [Fact]
    public void EmbeddedJsonWithDuplicateKeysIsScannedAsText()
    {
        var token = "gh" + "p_" + "Q7v9xLr2mZp4TkV9b2Qx7LmN4pR8sT1wYz3c";
        var root = new JsonObject { ["blob"] = "{\"x\":0,\"x\":\"" + token + "\"}" };

        var matches = KnownFormatSecretScanner.Scan(root, CancellationToken.None);
        KnownFormatSecretScanner.Redact(matches);

        Assert.Equal("{\"x\":0,\"x\":\"[redacted:github-token]\"}", root["blob"]!.GetValue<string>());
    }

    [Fact]
    public void LogPathWildcardsCredentialLikeMapKeys()
    {
        var token = "gh" + "p_" + "Q7v9xLr2mZp4TkV9b2Qx7LmN4pR8sT1wYz3c";
        var fingerprint = "hmac-sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        var root = JsonNode.Parse("{\"spec\":{\"tokens\":{}},\"metadata\":{\"annotations\":{}}}")!;
        root["spec"]!["tokens"]![token] = "API_TOKEN=" + token;
        root["spec"]!["tokens"]![fingerprint] = token;
        root["metadata"]!["annotations"]!["example.com/api-token"] = token;

        var paths = KnownFormatSecretScanner.Scan(root, CancellationToken.None)
            .Select(KnownFormatSecretScanner.LogPath)
            .Distinct()
            .ToArray();

        Assert.Equal(["$.spec.tokens[*]", "$.metadata.annotations['example.com/api-token']"], paths);
    }

    [Fact]
    public void EmbeddedJsonIsRedactedAsATreeAndReserialized()
    {
        var token = "gh" + "p_" + "Q7v9xLr2mZp4TkV9b2Qx7LmN4pR8sT1wYz3c";
        var applied = new JsonObject
        {
            ["kind"] = "ConfigMap",
            ["data"] = new JsonObject
            {
                ["API_TOKEN"] = "V9b2Qx7LmN4pR8sT1wYz3cKd",
                ["script"] = "curl -H 'X-Token: none' && echo " + token,
                ["LOG_LEVEL"] = "info"
            }
        };
        var root = new JsonObject
        {
            ["metadata"] = new JsonObject
            {
                ["annotations"] = new JsonObject { ["kubectl.kubernetes.io/last-applied-configuration"] = applied.ToJsonString() }
            }
        };

        var matches = KnownFormatSecretScanner.Scan(root, CancellationToken.None);
        Assert.All(matches, match => Assert.Equal("$.metadata.annotations['kubectl.kubernetes.io/last-applied-configuration']", match.Path));
        KnownFormatSecretScanner.Redact(matches);

        var redacted = JsonNode.Parse(root["metadata"]!["annotations"]!["kubectl.kubernetes.io/last-applied-configuration"]!.GetValue<string>())!;
        Assert.Equal("[redacted:generic-keyed-field]", redacted["data"]!["API_TOKEN"]!.GetValue<string>());
        Assert.Equal("curl -H 'X-Token: none' && echo [redacted:github-token]", redacted["data"]!["script"]!.GetValue<string>());
        Assert.Equal("info", redacted["data"]!["LOG_LEVEL"]!.GetValue<string>());
    }

    [Fact]
    public void RegexTimeoutFailsClosed()
    {
        var catastrophic = new KnownFormatSecretScanner.ValueRule(
            "test-catastrophic",
            new Regex("^(a+)+$", RegexOptions.None, TimeSpan.FromMilliseconds(10)),
            static (_, _) => true);
        var root = new JsonObject { ["value"] = new string('a', 64) + "!" };

        var exception = Assert.Throws<KubernetesReadException>(() =>
            KnownFormatSecretScanner.Scan(root, CancellationToken.None, rules: [catastrophic]));

        Assert.Equal(KubernetesErrorCategory.CredentialScanFailed, exception.Category);
    }

    public static TheoryData<string> PathologicalInputNames()
    {
        var data = new TheoryData<string>();
        foreach (var (name, _) in SecretScannerEvaluation.PathologicalInputs())
        {
            data.Add(name);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(PathologicalInputNames))]
    public void PathologicalOneMebibyteInputsStayBounded(string name)
    {
        var input = SecretScannerEvaluation.PathologicalInputs().Single(candidate => candidate.Name == name).Value;
        var root = new JsonObject { ["data"] = new JsonObject { ["blob"] = input } };

        var stopwatch = Stopwatch.StartNew();
        try
        {
            KnownFormatSecretScanner.Scan(root, CancellationToken.None);
        }
        catch (KubernetesReadException exception)
        {
            // A per-match timeout is an acceptable fail-closed outcome.
            Assert.Equal(KubernetesErrorCategory.CredentialScanFailed, exception.Category);
        }

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"{name} took {stopwatch.Elapsed}.");
    }
}

public sealed class CredentialScannerReaderTests
{
    private static readonly string GitHubToken = "gh" + "p_" + "Q7v9xLr2mZp4TkV9b2Qx7LmN4pR8sT1wYz3c";

    private static ReaderHost Host(
        string configMapValue,
        CredentialScannerOptions? scanner = null,
        ILogger<KubernetesReader>? logger = null)
    {
        var host = new ReaderHost(
            ReaderTestOptions.Options(
                resources: new()
                {
                    ["configmaps"] = ReaderTestOptions.R("", "v1", "configmaps", "ConfigMap"),
                    ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
                },
                credentialScanner: scanner),
            logger: logger);
        host.Api.GetHandler = (descriptor, _, name, _, _) => Task.FromResult(descriptor.IsSecret
            ? KubernetesJson.SecretGetBody(name, configMapValue)
            : KubernetesJson.ConfigMapGetBody(name, configMapValue));
        return host;
    }

    [Fact]
    public async Task EnabledByDefaultAndRedactsOnlyTheMatchingFieldValue()
    {
        var logger = new ListLogger();
        using var host = Host(GitHubToken, logger: logger);

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(GitHubToken, result.Json);
        using var json = JsonDocument.Parse(result.Json);
        Assert.Equal("[redacted:github-token]", json.RootElement.GetProperty("data").GetProperty("key").GetString());
        Assert.Equal("app", json.RootElement.GetProperty("metadata").GetProperty("name").GetString());
        Assert.Equal(1, result.ObjectCount);
        var message = Assert.Single(logger.Messages);
        Assert.Contains("github-token $.data.key", message);
        Assert.DoesNotContain(GitHubToken, message);
    }

    [Fact]
    public async Task DisabledScannerReturnsOutputUnchanged()
    {
        using var host = Host(GitHubToken, new CredentialScannerOptions { Enabled = false });

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None);

        Assert.Contains(GitHubToken, result.Json);
    }

    [Fact]
    public async Task DisabledRuleIsSkipped()
    {
        using var host = Host(GitHubToken, new CredentialScannerOptions { DisabledRules = ["github-token"] });

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None);

        Assert.Contains(GitHubToken, result.Json);
    }

    [Fact]
    public async Task LoggedPathsAreBoundedAndSanitized()
    {
        var logger = new ListLogger();
        using var host = Host(GitHubToken, logger: logger);
        var key = "line\nbreak" + new string('k', 400);
        host.Api.GetHandler = (_, _, name, _, _) => Task.FromResult(new JsonObject
        {
            ["apiVersion"] = "v1",
            ["kind"] = "ConfigMap",
            ["metadata"] = new JsonObject { ["name"] = name, ["namespace"] = "prod" },
            ["data"] = new JsonObject { [key] = GitHubToken }
        }.ToJsonString());

        await host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None);

        var message = Assert.Single(logger.Messages);
        Assert.Contains("github-token $.data[*]", message);
        Assert.DoesNotContain("\n", message);
        Assert.DoesNotContain("kkkk", message);
    }

    [Fact]
    public async Task ListSummariesAreNotScanned()
    {
        var logger = new ListLogger();
        using var host = Host(GitHubToken, logger: logger);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(KubernetesJson.ListBody(
            [new JsonObject
            {
                ["apiVersion"] = "v1",
                ["kind"] = "Secret",
                ["metadata"] = new JsonObject { ["name"] = "tokens", ["namespace"] = "prod" },
                ["data"] = new JsonObject { [GitHubToken] = "AA==" }
            }.ToJsonString()],
            null,
            "v1",
            "SecretList"));

        var result = await host.Reader.ReadAsync("secrets", "prod", null, CancellationToken.None);

        Assert.Contains(GitHubToken, result.Json);
        Assert.Empty(logger.Messages);
    }

    [Fact]
    public async Task SanitizedSecretGetWithKnownFormatValuesIsUnchanged()
    {
        using var host = Host(GitHubToken);

        var result = await host.Reader.ReadAsync("secrets", "prod", "database", CancellationToken.None);

        Assert.DoesNotContain(GitHubToken, result.Json);
        Assert.DoesNotContain("[redacted:", result.Json);
        Assert.Contains("hmac-sha256:", result.Json);
    }

    [Fact]
    public void ValidatorRejectsUnknownDisabledRule()
    {
        var options = ReaderTestOptions.Options(
            credentialScanner: new CredentialScannerOptions { DisabledRules = ["no-such-rule"] });

        var result = new KubeMcpOptionsValidator(new TestHostEnvironment("Production")).Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("DisabledRules", result.FailureMessage);
    }

    private sealed class ListLogger : ILogger<KubernetesReader>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}

/// <summary>
/// Produces the evaluation tables for the POC write-up when
/// <c>KUBE_MCP_SCANNER_REPORT=/path/report.md</c> is set.
/// </summary>
public sealed class SecretScannerEvaluationReport(ITestOutputHelper output)
{
    [Fact]
    public void WriteEvaluationReport()
    {
        // Opt-in: the report measures latency and has no assertions.
        if (Environment.GetEnvironmentVariable("KUBE_MCP_SCANNER_REPORT") is not { Length: > 0 } path)
        {
            return;
        }

        var report = SecretScannerEvaluation.BuildReport();
        output.WriteLine(report);
        File.WriteAllText(path, report);
    }
}

/// <summary>
/// Held-out evaluation on real kube-mcp output. Set <c>KUBE_MCP_SCANNER_CORPUS_DIR</c>
/// to a local directory of saved tool outputs (*.json, searched recursively); the
/// report is written to <c>scan-report.md</c> in that directory. Values are shown
/// only as masked shapes. Keep such directories out of the repository.
/// </summary>
public sealed class SecretScannerHeldOutEvaluation
{
    [Fact]
    public void ScanSavedOutputs()
    {
        if (Environment.GetEnvironmentVariable("KUBE_MCP_SCANNER_CORPUS_DIR") is not { Length: > 0 } directory)
        {
            return;
        }

        var builder = new StringBuilder();
        var timings = new List<(double Milliseconds, int Bytes)>();
        var findings = new List<string>();
        var perRule = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var files = Directory.GetFiles(directory, "*.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
        var strings = 0;
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            var root = JsonNode.Parse(text)!;
            strings += SecretScannerEvaluation.CountStrings(root);
            KnownFormatSecretScanner.Scan(root, CancellationToken.None);
            var stopwatch = Stopwatch.StartNew();
            var matches = KnownFormatSecretScanner.Scan(root, CancellationToken.None);
            timings.Add((stopwatch.Elapsed.TotalMilliseconds, Encoding.UTF8.GetByteCount(text)));
            foreach (var match in matches)
            {
                perRule[match.RuleId] = perRule.GetValueOrDefault(match.RuleId) + 1;
                findings.Add($"| {Path.GetFileNameWithoutExtension(file)} | `{match.RuleId}` | `{match.Path}` | {Describe(match)} |");
            }
        }

        timings.Sort();
        builder.AppendLine($"Files: {files.Length}; string values: {strings}; matches: {findings.Count}");
        builder.AppendLine($"Scan ms p50 {timings[timings.Count / 2].Milliseconds:0.00}, p95 {timings[timings.Count * 95 / 100].Milliseconds:0.00}, max {timings[^1].Milliseconds:0.00} (largest output {timings.Max(timing => timing.Bytes) / 1024.0:0.#} KiB)");
        builder.AppendLine();
        builder.AppendLine("| Rule | Matches |");
        builder.AppendLine("| --- | ---: |");
        foreach (var (rule, count) in perRule)
        {
            builder.AppendLine($"| `{rule}` | {count} |");
        }

        builder.AppendLine();
        builder.AppendLine("| Object | Rule | Path | Value shape |");
        builder.AppendLine("| --- | --- | --- | --- |");
        findings.ForEach(finding => builder.AppendLine(finding));
        File.WriteAllText(Path.Combine(directory, "scan-report.md"), builder.ToString());
    }

    // Shape only: letters become a/A, digits 9. For a match inside an embedded
    // JSON document, the inner path names the leaf.
    private static string Describe(KnownFormatSecretScanner.ScanMatch match) =>
        (match.Embedding is null ? "" : $"embedded `{match.Node.GetPath()}` ") + Mask(match.Node.GetValue<string>());

    private static string Mask(string value)
    {
        var masked = string.Concat(value.Take(48).Select(c =>
            char.IsAsciiLetterLower(c) ? 'a' : char.IsAsciiLetterUpper(c) ? 'A' : char.IsAsciiDigit(c) ? '9' :
            char.IsWhiteSpace(c) ? '␣' : c == '|' ? '¦' : c));
        return $"`{masked}{(value.Length > 48 ? "…" : "")}` len {value.Length}, H {KnownFormatSecretScanner.ShannonEntropy(value):0.0}";
    }
}

internal static class SecretScannerEvaluation
{
    private static readonly string[] GenericRules = ["bearer-token", "generic-assignment", "generic-keyed-field"];

    public static IEnumerable<(string Name, string Value)> PathologicalInputs()
    {
        const int size = 1024 * 1024;

        static string Repeat(string unit) =>
            new StringBuilder(size + unit.Length).Insert(0, unit, size / unit.Length).ToString();

        yield return ("1 MiB of 'a'", new string('a', size));
        yield return ("repeated 'password=' (keyword, no value)", Repeat("password="));
        yield return ("repeated 'password=aaaaaaaa ' (rejected values)", Repeat("password=aaaaaaaa "));
        yield return ("repeated '-----BEGIN ' (no PRIVATE KEY)", Repeat("-----BEGIN "));
        yield return ("repeated PEM header without body", Repeat("-----BEGIN RSA PRIVATE KEY-----\n"));
        yield return ("repeated 'a://b:' (URL without '@')", Repeat("a://b:"));
        yield return ("repeated 'eyAAAAAAAAAAAAAAAAA.' (JWT-like)", Repeat("eyAAAAAAAAAAAAAAAAA."));
        yield return ("'LS0tLS1CRUdJTi' + 1 MiB base64", "LS0tLS1CRUdJTi" + new string('A', size));
        yield return ("repeated 'aws_secret' (AWS keyword chain)", Repeat("aws_secret"));
        yield return ("repeated 'Bearer ' (no token)", Repeat("Bearer "));
        yield return ("repeated 'xoxb-1234567890-' (Slack prefix)", Repeat("xoxb-1234567890-"));
    }

    public static string BuildReport()
    {
        var corpus = SecretScannerCorpus.Instance;
        var builder = new StringBuilder();
        AppendRuleTable(builder, corpus);
        AppendPlacementTable(builder, corpus);
        AppendEntropyTable(builder, corpus);
        AppendRedactionCostTable(builder, corpus);
        AppendEvasionTable(builder, corpus);
        AppendLatencyTable(builder, corpus);
        AppendRedosTable(builder);
        return builder.ToString();
    }

    private static List<KnownFormatSecretScanner.ScanMatch> Scan(JsonNode root, double entropy = KnownFormatSecretScanner.DefaultGenericMinEntropy) =>
        KnownFormatSecretScanner.Scan(root, CancellationToken.None, entropy);

    public static int CountStrings(JsonNode? node) => node switch
    {
        JsonObject jsonObject => jsonObject.Sum(property => CountStrings(property.Value)),
        JsonArray jsonArray => jsonArray.Sum(CountStrings),
        JsonValue value when value.GetValueKind() == JsonValueKind.String => 1,
        _ => 0
    };

    private static string Percent(int part, int whole) =>
        whole == 0 ? "n/a" : (100.0 * part / whole).ToString("0.#", CultureInfo.InvariantCulture) + "%";

    private static void AppendRuleTable(StringBuilder builder, SecretScannerCorpus corpus)
    {
        var negativeMatches = corpus.Negatives.SelectMany(negative => Scan(negative.Root)).ToList();
        var negativeStrings = corpus.Negatives.Sum(negative => CountStrings(negative.Root));
        var spurious = 0;

        builder.AppendLine($"### Per-rule results ({corpus.Positives.Count} positive placements; {corpus.Negatives.Count} negative objects, {negativeStrings} string values)");
        builder.AppendLine();
        builder.AppendLine("| Rule | Positives | Expected-rule recall | Any-rule recall | False positives (negative strings) |");
        builder.AppendLine("| --- | ---: | ---: | ---: | ---: |");
        foreach (var rule in KnownFormatSecretScanner.RuleIds)
        {
            var positives = corpus.Positives.Where(positive => positive.Rule == rule).ToList();
            var expected = 0;
            var any = 0;
            foreach (var positive in positives)
            {
                var matches = Scan(positive.Root);
                expected += matches.Any(match => match.Path == positive.Path && match.RuleId == rule) ? 1 : 0;
                any += matches.Any(match => match.Path == positive.Path) ? 1 : 0;
                spurious += matches.Count(match => match.Path != positive.Path);
            }

            builder.AppendLine($"| `{rule}` | {positives.Count} | {expected}/{positives.Count} ({Percent(expected, positives.Count)}) | {any}/{positives.Count} ({Percent(any, positives.Count)}) | {negativeMatches.Count(match => match.RuleId == rule)} |");
        }

        var totalAny = corpus.Positives.Count(positive => Scan(positive.Root).Any(match => match.Path == positive.Path));
        builder.AppendLine($"| **All** | {corpus.Positives.Count} | | {totalAny}/{corpus.Positives.Count} ({Percent(totalAny, corpus.Positives.Count)}) | {negativeMatches.Count} |");
        builder.AppendLine();
        builder.AppendLine($"Spurious matches elsewhere in the positive host objects: {spurious}.");
        builder.AppendLine();
    }

    private static void AppendPlacementTable(StringBuilder builder, SecretScannerCorpus corpus)
    {
        builder.AppendLine("### Recall by placement (any rule)");
        builder.AppendLine();
        builder.AppendLine("| Placement | Cases | Detected | Missed (rule) |");
        builder.AppendLine("| --- | ---: | ---: | --- |");
        foreach (var group in corpus.Positives.GroupBy(positive => positive.Placement))
        {
            var missed = group.Where(positive => !Scan(positive.Root).Any(match => match.Path == positive.Path))
                .Select(positive => positive.Rule)
                .ToList();
            var detected = group.Count() - missed.Count;
            builder.AppendLine($"| {group.Key} | {group.Count()} | {detected} ({Percent(detected, group.Count())}) | {(missed.Count == 0 ? "-" : string.Join(", ", missed.Distinct()))} |");
        }

        builder.AppendLine();
    }

    private static void AppendEntropyTable(StringBuilder builder, SecretScannerCorpus corpus)
    {
        var genericPositives = corpus.Positives.Where(positive => GenericRules.Contains(positive.Rule)).ToList();
        // Strings under secret-like keys (or after a secret keyword) that are not credentials.
        var hardNegatives = new JsonObject
        {
            ["recyclarr"] = "api_key: !env_var SONARR_API_KEY",
            ["token"] = "ServiceAccount",
            ["secret"] = "prod_v2_tls",
            ["apiKey"] = "X-Api-Key",
            ["accessKey"] = "minio_root_user",
            ["vault"] = new JsonObject { ["secret"] = "kv/data/apps/grafana" },
            ["auth_token"] = "per-request",
            ["clientSecret"] = "oidc-client.v1"
        };
        var hardCount = hardNegatives.Count;

        builder.AppendLine($"### Shannon-entropy threshold for generic rules ({genericPositives.Count} generic positives; {hardCount} extra hard negatives)");
        builder.AppendLine();
        builder.AppendLine("| Min entropy (bits/char) | Generic expected-rule recall | Generic FPs (corpus negatives) | Hard-negative FPs |");
        builder.AppendLine("| ---: | ---: | ---: | ---: |");
        foreach (var threshold in new[] { 0.0, 2.5, 3.0, 3.5, 4.0 })
        {
            var recall = genericPositives.Count(positive => Scan(positive.Root, threshold)
                .Any(match => match.Path == positive.Path && match.RuleId == positive.Rule));
            var falsePositives = corpus.Negatives.Sum(negative => Scan(negative.Root, threshold)
                .Count(match => GenericRules.Contains(match.RuleId)));
            var hard = Scan(hardNegatives, threshold).Select(match => match.Path).Distinct().Count();
            builder.AppendLine($"| {threshold.ToString("0.0", CultureInfo.InvariantCulture)} | {recall}/{genericPositives.Count} ({Percent(recall, genericPositives.Count)}) | {falsePositives} | {hard}/{hardCount} |");
        }

        builder.AppendLine();
        var hits = Scan(hardNegatives).Select(match => $"`{match.Path}` ({match.RuleId})").Distinct();
        builder.AppendLine($"Hard negatives still flagged at the default {KnownFormatSecretScanner.DefaultGenericMinEntropy:0.0}: {string.Join(", ", hits)}.");
        builder.AppendLine();
    }

    private static void AppendRedactionCostTable(StringBuilder builder, SecretScannerCorpus corpus)
    {
        builder.AppendLine("### Redaction: response bytes kept on a true positive (withholding would keep 0%)");
        builder.AppendLine();
        builder.AppendLine("| Placement | Cases | Median bytes kept | Min bytes kept |");
        builder.AppendLine("| --- | ---: | ---: | ---: |");
        foreach (var group in corpus.Positives.GroupBy(positive => positive.Placement))
        {
            var kept = group.Select(positive =>
            {
                var clone = positive.Root.DeepClone();
                var original = Encoding.UTF8.GetByteCount(clone.ToJsonString());
                KnownFormatSecretScanner.Redact(Scan(clone));

                return (double)Encoding.UTF8.GetByteCount(clone.ToJsonString()) / original;
            }).Order().ToList();
            builder.AppendLine($"| {group.Key} | {kept.Count} | {kept[kept.Count / 2]:P0} | {kept[0]:P0} |");
        }

        builder.AppendLine();
    }

    private static void AppendEvasionTable(StringBuilder builder, SecretScannerCorpus corpus)
    {
        builder.AppendLine("### Known gaps (evasion corpus)");
        builder.AppendLine();
        builder.AppendLine("| Technique | Caught by this layer | Value is an env/ConfigMap data value (layer 1 scope) |");
        builder.AppendLine("| --- | --- | --- |");
        foreach (var evasion in corpus.Evasions)
        {
            var rules = Scan(evasion.Root).Select(match => match.RuleId).Distinct().ToList();
            builder.AppendLine($"| {evasion.Technique} | {(rules.Count == 0 ? "no" : "yes (" + string.Join(", ", rules) + ")")} | {(evasion.Layer1Placement ? "yes" : "no")} |");
        }

        builder.AppendLine();
    }

    private static void AppendLatencyTable(StringBuilder builder, SecretScannerCorpus corpus)
    {
        builder.AppendLine($"### Latency (median of 9 runs after warm-up; {Environment.ProcessorCount} logical CPUs, {System.Runtime.InteropServices.RuntimeInformation.OSArchitecture})");
        builder.AppendLine();
        builder.AppendLine("| Output | Size | Strings | Serialize (baseline) | Scan | Scan throughput |");
        builder.AppendLine("| --- | ---: | ---: | ---: | ---: | ---: |");
        foreach (var (name, root) in LatencyObjects(corpus))
        {
            var json = root.ToJsonString();
            var bytes = Encoding.UTF8.GetByteCount(json);
            var serialize = MedianMilliseconds(() => root.ToJsonString());
            var scan = MedianMilliseconds(() => Scan(root));
            builder.AppendLine(
                $"| {name} | {bytes / 1024.0:0.#} KiB | {CountStrings(root)} | {serialize:0.00} ms | {scan:0.00} ms | {bytes / 1024.0 / 1024.0 / (scan / 1000.0):0} MiB/s |");
        }

        builder.AppendLine();
    }

    private static void AppendRedosTable(StringBuilder builder)
    {
        builder.AppendLine("### Pathological 1 MiB inputs (single string value; per-match timeout 250 ms)");
        builder.AppendLine();
        builder.AppendLine("| Input | Time | Outcome |");
        builder.AppendLine("| --- | ---: | --- |");
        foreach (var (name, value) in PathologicalInputs())
        {
            var root = new JsonObject { ["blob"] = value };
            var stopwatch = Stopwatch.StartNew();
            string outcome;
            try
            {
                var matches = Scan(root);
                outcome = matches.Count == 0
                    ? "no match"
                    : $"{matches.Count} matches: " + string.Join(", ", matches.Select(match => match.RuleId).Distinct());
            }
            catch (KubernetesReadException)
            {
                outcome = "timeout, failed closed";
            }

            builder.AppendLine($"| {name} | {stopwatch.Elapsed.TotalMilliseconds:0} ms | {outcome} |");
        }

        builder.AppendLine();
    }

    private static double MedianMilliseconds(Action action)
    {
        action();
        action();
        var samples = new double[9];
        for (var i = 0; i < samples.Length; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            action();
            samples[i] = stopwatch.Elapsed.TotalMilliseconds;
        }

        Array.Sort(samples);
        return samples[samples.Length / 2];
    }

    private const string ReleaseTemplate = """
                {"name":"app-@I@","image":"ghcr.io/home-operations/app:@I@.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 "env":[{"name":"TZ","value":"Europe/Amsterdam"},{"name":"API_TOKEN","valueFrom":{"secretKeyRef":{"name":"app-@I@","key":"token"}}},{"name":"LOG_LEVEL","value":"info"}],
                 "resources":{"requests":{"cpu":"10m","memory":"64Mi"}},"existingSecret":"app-@I@-secret"}
                """;

    private static IEnumerable<(string Name, JsonNode Root)> LatencyObjects(SecretScannerCorpus corpus)
    {
        const int target = 1000 * 1024;
        yield return ("Typical Deployment GET", corpus.Negatives[0].Root);
        yield return ("CNPG Cluster GET", corpus.Negatives.Single(negative => negative.Name.StartsWith("cluster/", StringComparison.Ordinal)).Root);

        var text = new StringBuilder();
        for (var i = 0; text.Length < target; i++)
        {
            text.Append(CultureInfo.InvariantCulture, $"- name: service-{i}\n  url: http://service-{i}.apps.svc.cluster.local:8080/api\n  timeout: 30s\n  tokenTTL: 1h\n  secretName: service-{i}-tls\n  password: ${{SERVICE_{i}_PASSWORD}}\n  labels: {{team: platform, tier: backend}}\n");
        }

        yield return ("ConfigMap, one ~1 MiB config text", new JsonObject { ["kind"] = "ConfigMap", ["data"] = new JsonObject { ["services.yaml"] = text.ToString() } });

        var data = new JsonObject();
        for (var i = 0; i < 5000; i++)
        {
            data[$"feature.flag.{i}"] = $"enabled=true;rollout=25;owner=team-{i % 17};updated=2026-11-01T02:00:13Z;note=flag {i} controls the checkout experiment";
        }

        yield return ("ConfigMap, 5,000 small keys", new JsonObject { ["kind"] = "ConfigMap", ["data"] = data });

        var releases = new JsonArray();
        for (var (i, length) = (0, 0); length < target; i++)
        {
            var release = JsonNode.Parse(ReleaseTemplate.Replace("@I@", i.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal))!;
            length += release.ToJsonString().Length + 1;
            releases.Add(release);
        }

        yield return ("HelmRelease, ~1 MiB nested values", new JsonObject { ["kind"] = "HelmRelease", ["spec"] = new JsonObject { ["values"] = new JsonObject { ["apps"] = releases } } });
    }
}
