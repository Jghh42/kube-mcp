using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Security;
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

        var matches = KnownFormatSecretScanner.Scan(positive.Root, CancellationToken.None);

        Assert.Contains(matches, match => match.Path == positive.Path);
        Assert.All(matches, match => Assert.Equal(positive.Path, match.Path));
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

    private static ReaderHost Host(CredentialScannerMode mode, string configMapValue)
    {
        var host = new ReaderHost(ReaderTestOptions.Options(
            resources: new()
            {
                ["configmaps"] = ReaderTestOptions.R("", "v1", "configmaps", "ConfigMap"),
                ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
            },
            credentialScannerMode: mode));
        host.Api.GetHandler = (descriptor, _, name, _, _) => Task.FromResult(descriptor.IsSecret
            ? KubernetesJson.SecretGetBody(name, configMapValue)
            : KubernetesJson.ConfigMapGetBody(name, configMapValue));
        return host;
    }

    [Fact]
    public async Task OffModeReturnsOutputUnchanged()
    {
        using var host = Host(CredentialScannerMode.Off, GitHubToken);

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None);

        Assert.Contains(GitHubToken, result.Json);
    }

    [Fact]
    public async Task RedactModeReplacesOnlyTheMatchingFieldValue()
    {
        using var host = Host(CredentialScannerMode.Redact, GitHubToken);

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(GitHubToken, result.Json);
        using var json = JsonDocument.Parse(result.Json);
        Assert.Equal("[redacted:github-token]", json.RootElement.GetProperty("data").GetProperty("key").GetString());
        Assert.Equal("app", json.RootElement.GetProperty("metadata").GetProperty("name").GetString());
        Assert.Equal(1, result.ObjectCount);
    }

    [Fact]
    public async Task WithholdModeFailsWithFixedCategory()
    {
        using var host = Host(CredentialScannerMode.Withhold, GitHubToken);

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("configmaps", "prod", "app", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.CredentialDetected, exception.Category);
        Assert.DoesNotContain(GitHubToken, exception.Message);
    }

    [Fact]
    public async Task SanitizedSecretGetWithKnownFormatValuesPassesWithhold()
    {
        using var host = Host(CredentialScannerMode.Withhold, GitHubToken);

        var result = await host.Reader.ReadAsync("secrets", "prod", "database", CancellationToken.None);

        Assert.DoesNotContain(GitHubToken, result.Json);
        Assert.Contains("hmac-sha256:", result.Json);
    }

    [Fact]
    public void ValidatorRejectsUndefinedMode()
    {
        var options = ReaderTestOptions.Options(credentialScannerMode: (CredentialScannerMode)42);

        var result = new KubeMcpOptionsValidator(new TestHostEnvironment("Production")).Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("CredentialScannerMode", result.FailureMessage);
    }
}

/// <summary>
/// Produces the evaluation tables for the POC write-up. Run with
/// <c>KUBE_MCP_SCANNER_REPORT=/path/report.md</c> to write the markdown to a file.
/// </summary>
public sealed class SecretScannerEvaluationReport(ITestOutputHelper output)
{
    [Fact]
    public void WriteEvaluationReport()
    {
        var report = SecretScannerEvaluation.BuildReport();
        output.WriteLine(report);
        if (Environment.GetEnvironmentVariable("KUBE_MCP_SCANNER_REPORT") is { Length: > 0 } path)
        {
            File.WriteAllText(path, report);
        }
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

    private static int CountStrings(JsonNode? node) => node switch
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
        builder.AppendLine("### Redact vs withhold: response bytes kept on a true positive");
        builder.AppendLine();
        builder.AppendLine("| Placement | Cases | Redact: median bytes kept | Redact: min bytes kept | Withhold |");
        builder.AppendLine("| --- | ---: | ---: | ---: | ---: |");
        foreach (var group in corpus.Positives.GroupBy(positive => positive.Placement))
        {
            var kept = group.Select(positive =>
            {
                var clone = positive.Root.DeepClone();
                var original = Encoding.UTF8.GetByteCount(clone.ToJsonString());
                foreach (var match in Scan(clone).DistinctBy(match => match.Node))
                {
                    match.Node.ReplaceWith(KnownFormatSecretScanner.RedactionMarker(match.RuleId));
                }

                return (double)Encoding.UTF8.GetByteCount(clone.ToJsonString()) / original;
            }).Order().ToList();
            builder.AppendLine($"| {group.Key} | {kept.Count} | {kept[kept.Count / 2]:P0} | {kept[0]:P0} | 0% |");
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
                outcome = matches.Count == 0 ? "no match" : "match: " + string.Join(", ", matches.Select(match => match.RuleId));
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

        var list = new JsonArray();
        for (var i = 0; i < 100; i++)
        {
            list.Add(new JsonObject { ["name"] = $"app-{i}-7d9f8b6c5d-x2v7q", ["namespace"] = "media", ["kind"] = "Pod", ["age"] = "12d" });
        }

        yield return ("LIST summary, 100 items", new JsonObject { ["operation"] = "LIST", ["items"] = list, ["count"] = 100, ["limited"] = false });

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
