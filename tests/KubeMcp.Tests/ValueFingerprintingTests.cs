using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Security;
using Microsoft.Extensions.Configuration;

namespace KubeMcp.Tests;

public sealed class ValueFingerprintingTests
{
    private const string RawEnvValue = "env-value-must-not-leak";
    private const string RawConfigValue = "config-value-must-not-leak";
    private const string AllowedEnvValue = "debug";
    private static readonly string[] ContainerLists = ["containers", "initContainers", "ephemeralContainers"];

    public static TheoryData<string, string, string, string> WorkloadKinds => new()
    {
        { "pods", "", "Pod", "spec" },
        { "replicationcontrollers", "", "ReplicationController", "spec.template.spec" },
        { "deployments", "apps", "Deployment", "spec.template.spec" },
        { "statefulsets", "apps", "StatefulSet", "spec.template.spec" },
        { "daemonsets", "apps", "DaemonSet", "spec.template.spec" },
        { "replicasets", "apps", "ReplicaSet", "spec.template.spec" },
        { "jobs", "batch", "Job", "spec.template.spec" },
        { "cronjobs", "batch", "CronJob", "spec.jobTemplate.spec.template.spec" }
    };

    [Theory]
    [MemberData(nameof(WorkloadKinds))]
    public async Task GetFingerprintsEnvValuesInEveryContainerListOfEveryWorkloadKind(
        string resource,
        string group,
        string kind,
        string podSpecPath)
    {
        using var host = Host(resource, group, kind, plaintextEnvVars: ["LOG_LEVEL"]);
        var body = WorkloadBody(group, kind, podSpecPath, PodSpec());
        body["metadata"]!["annotations"] = new JsonObject
        {
            [KubernetesJson.LastAppliedAnnotation] = body.ToJsonString(),
            ["example.com/kept"] = "visible"
        };
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync(resource, "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(RawEnvValue, result.Json);
        Assert.DoesNotContain("last-applied", result.Json);
        var root = JsonNode.Parse(result.Json)!;
        Assert.Equal("visible", root["metadata"]!["annotations"]!["example.com/kept"]!.GetValue<string>());

        var podSpec = podSpecPath.Split('.').Aggregate(root, (node, segment) => node[segment]!);
        foreach (var list in ContainerLists)
        {
            var env = podSpec[list]![0]!["env"]!.AsArray();
            Assert.Equal(Fingerprint(RawEnvValue), env[0]!["value"]!.GetValue<string>());
            Assert.Equal(AllowedEnvValue, env[1]!["value"]!.GetValue<string>());
            Assert.Equal(Fingerprint(RawEnvValue), env[2]!["value"]!.GetValue<string>());
            Assert.False(env[3]!.AsObject().ContainsKey("value"));
            Assert.Equal("db", env[3]!["valueFrom"]!["secretKeyRef"]!["name"]!.GetValue<string>());
        }
    }

    [Fact]
    public async Task GetFingerprintsEnvValuesInMappedCustomResources()
    {
        using var host = Host("clusters.postgresql.cnpg.io", "postgresql.cnpg.io", "Cluster", resource: "clusters", version: "v1");
        var body = WorkloadBody("postgresql.cnpg.io", "Cluster", "spec", new JsonObject
        {
            ["env"] = new JsonArray(new JsonObject { ["name"] = "TOKEN", ["value"] = RawEnvValue })
        });
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("clusters.postgresql.cnpg.io", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(RawEnvValue, result.Json);
        Assert.Contains(Fingerprint(RawEnvValue), result.Json);
    }

    [Fact]
    public async Task GetRemovesLastAppliedFromNestedTemplateMetadata()
    {
        using var host = Host("deployments", "apps", "Deployment");
        var body = WorkloadBody("apps", "Deployment", "spec.template.spec", new JsonObject());
        body["spec"]!["template"]!["metadata"] = new JsonObject
        {
            ["annotations"] = new JsonObject
            {
                [KubernetesJson.LastAppliedAnnotation] = $$"""{"env":"{{RawEnvValue}}"}""",
                ["example.com/kept"] = "visible"
            }
        };
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("deployments", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(RawEnvValue, result.Json);
        Assert.DoesNotContain("last-applied", result.Json);
        Assert.Equal(
            "visible",
            JsonNode.Parse(result.Json)!["spec"]!["template"]!["metadata"]!["annotations"]!["example.com/kept"]!.GetValue<string>());
    }

    [Fact]
    public async Task GetFingerprintsEnvArraysNestedInsideEnvEntries()
    {
        using var host = Host("clusters.postgresql.cnpg.io", "postgresql.cnpg.io", "Cluster", resource: "clusters", version: "v1");
        var body = WorkloadBody("postgresql.cnpg.io", "Cluster", "spec", new JsonObject
        {
            ["env"] = new JsonArray(new JsonObject
            {
                ["name"] = "OUTER",
                ["env"] = new JsonArray(new JsonObject { ["name"] = "TOKEN", ["value"] = RawEnvValue })
            })
        });
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("clusters.postgresql.cnpg.io", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(RawEnvValue, result.Json);
        Assert.Contains(Fingerprint(RawEnvValue), result.Json);
    }

    [Fact]
    public async Task GetFingerprintsNonStringEnvValues()
    {
        using var host = Host("pods", "", "Pod");
        var body = WorkloadBody("", "Pod", "spec", new JsonObject
        {
            ["containers"] = new JsonArray(new JsonObject
            {
                ["name"] = "app",
                ["env"] = new JsonArray(new JsonObject
                {
                    ["name"] = "NESTED",
                    ["value"] = new JsonObject { ["inner"] = RawEnvValue }
                })
            })
        });
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("pods", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(RawEnvValue, result.Json);
        Assert.Contains("hmac-sha256:", result.Json);
    }

    [Fact]
    public async Task GetFingerprintsConfigMapDataAndBinaryDataButKeepsKeys()
    {
        using var host = Host("configmaps", "", "ConfigMap");
        var binary = new byte[] { 0, 255, 128, 42 };
        var body = ConfigMapBody(
            new JsonObject { ["settings.json"] = RawConfigValue, ["empty"] = "" },
            new JsonObject { ["blob"] = Convert.ToBase64String(binary) });
        body["metadata"]!["annotations"] = new JsonObject
        {
            [KubernetesJson.LastAppliedAnnotation] = body.ToJsonString()
        };
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app-config", CancellationToken.None);

        Assert.DoesNotContain(RawConfigValue, result.Json);
        Assert.DoesNotContain(Convert.ToBase64String(binary), result.Json);
        Assert.DoesNotContain("last-applied", result.Json);
        var root = JsonNode.Parse(result.Json)!;
        Assert.Equal(Fingerprint(RawConfigValue), root["data"]!["settings.json"]!.GetValue<string>());
        Assert.Equal(Fingerprint(""), root["data"]!["empty"]!.GetValue<string>());
        Assert.Equal(new SecretFingerprinterFixture().Fingerprinter.Fingerprint(binary), root["binaryData"]!["blob"]!.GetValue<string>());
        Assert.Equal("app-config", root["metadata"]!["name"]!.GetValue<string>());
    }

    [Fact]
    public async Task GetReturnsAllowlistedConfigMapInPlaintextWithoutLastApplied()
    {
        using var host = Host("configmaps", "", "ConfigMap", plaintextConfigMaps: ["prod/app-config"]);
        var body = ConfigMapBody(
            new JsonObject { ["settings.json"] = RawConfigValue },
            new JsonObject { ["blob"] = "AP+A" });
        body["metadata"]!["annotations"] = new JsonObject
        {
            [KubernetesJson.LastAppliedAnnotation] = "{}"
        };
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app-config", CancellationToken.None);

        var root = JsonNode.Parse(result.Json)!;
        Assert.Equal(RawConfigValue, root["data"]!["settings.json"]!.GetValue<string>());
        Assert.Equal("AP+A", root["binaryData"]!["blob"]!.GetValue<string>());
        Assert.DoesNotContain("last-applied", result.Json);
    }

    [Theory]
    [InlineData("other/app-config")]
    [InlineData("prod/app-config-2")]
    [InlineData("prod/App-Config")]
    public async Task GetFingerprintsConfigMapsThatMissTheAllowlist(string allowlistEntry)
    {
        using var host = Host("configmaps", "", "ConfigMap", plaintextConfigMaps: [allowlistEntry]);
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(
            ConfigMapBody(new JsonObject { ["key"] = RawConfigValue }, null).ToJsonString());

        var result = await host.Reader.ReadAsync("configmaps", "prod", "app-config", CancellationToken.None);

        Assert.DoesNotContain(RawConfigValue, result.Json);
        Assert.Contains(Fingerprint(RawConfigValue), result.Json);
    }

    [Theory]
    [InlineData("log_level")]
    [InlineData("LOG_LEVEL_X")]
    [InlineData("LOG")]
    public async Task EnvAllowlistMatchesExactCaseSensitiveNamesOnly(string variableName)
    {
        using var host = Host("pods", "", "Pod", plaintextEnvVars: ["LOG_LEVEL"]);
        var body = WorkloadBody("", "Pod", "spec", new JsonObject
        {
            ["containers"] = new JsonArray(new JsonObject
            {
                ["name"] = "app",
                ["env"] = new JsonArray(new JsonObject { ["name"] = variableName, ["value"] = RawEnvValue })
            })
        });
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("pods", "prod", "app", CancellationToken.None);

        Assert.DoesNotContain(RawEnvValue, result.Json);
        Assert.Contains(Fingerprint(RawEnvValue), result.Json);
    }

    [Fact]
    public async Task FingerprintsMatchSecretFingerprintsForEqualValues()
    {
        using var host = Host("pods", "", "Pod");
        var body = WorkloadBody("", "Pod", "spec", new JsonObject
        {
            ["containers"] = new JsonArray(new JsonObject
            {
                ["name"] = "app",
                ["env"] = new JsonArray(new JsonObject { ["name"] = "PASSWORD", ["value"] = RawEnvValue })
            })
        });
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var result = await host.Reader.ReadAsync("pods", "prod", "app", CancellationToken.None);
        var secret = new SecretFingerprinterFixture().Sanitizer.SanitizeSecretGet(
            JsonDocument.Parse(KubernetesJson.SecretGetBody("db", RawEnvValue)).RootElement);

        Assert.Contains(secret["data"]!["password"]!.GetValue<string>(), result.Json);
    }

    [Theory]
    [InlineData("""{"data":{"key":42}}""")]
    [InlineData("""{"data":["value"]}""")]
    [InlineData("""{"binaryData":{"blob":"not base64!"}}""")]
    [InlineData("""{"binaryData":{"blob":null}}""")]
    public async Task MalformedConfigMapValuesMapToMalformedCategory(string fields)
    {
        await AssertMalformedConfigMapAsync(fields, plaintextConfigMaps: null);
    }

    [Theory]
    [InlineData("""{"data":{"key":42}}""")]
    [InlineData("""{"binaryData":{"blob":"not base64!"}}""")]
    public async Task MalformedAllowlistedConfigMapValuesMapToMalformedCategory(string fields)
    {
        await AssertMalformedConfigMapAsync(fields, plaintextConfigMaps: ["prod/app-config"]);
    }

    private static async Task AssertMalformedConfigMapAsync(string fields, string[]? plaintextConfigMaps)
    {
        using var host = Host("configmaps", "", "ConfigMap", plaintextConfigMaps: plaintextConfigMaps);
        var body = ConfigMapBody(null, null);
        foreach (var (name, value) in JsonNode.Parse(fields)!.AsObject())
        {
            body[name] = value?.DeepClone();
        }

        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body.ToJsonString());

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("configmaps", "prod", "app-config", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.DoesNotContain("not base64", exception.ToString());
    }

    [Fact]
    public async Task ListSummariesNeverIncludeSpecsOrConfigMapData()
    {
        using var host = Host("configmaps", "", "ConfigMap");
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(KubernetesJson.ListBody(
            [ConfigMapBody(new JsonObject { ["key"] = RawConfigValue }, null).ToJsonString()],
            null,
            kind: "ConfigMapList"));

        var result = await host.Reader.ReadAsync("configmaps", "prod", null, CancellationToken.None);

        Assert.Contains("app-config", result.Json);
        Assert.DoesNotContain(RawConfigValue, result.Json);
        Assert.DoesNotContain("hmac-sha256:", result.Json);
    }

    [Theory]
    [InlineData(new[] { "LOG_LEVEL", "my.var-1", "Weird$Name" }, new string[0])]
    [InlineData(new string[0], new[] { "kube-system/kube-root-ca.crt", "team-a/app-settings" })]
    public void ValidatorAcceptsWellFormedAllowlists(string[] envVars, string[] configMaps)
    {
        var result = Validate(envVars, configMaps);

        Assert.True(result.Succeeded, result.FailureMessage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("HAS SPACE")]
    [InlineData("API_KEY=leaked-value")]
    [InlineData("TAB\tNAME")]
    [InlineData("NON_ASCII_É")]
    [InlineData("LOG_LEVEL\n")]
    [InlineData(null)]
    public void ValidatorRejectsMalformedEnvVarNamesWithoutEchoingThem(string? entry)
    {
        var result = Validate(["LOG_LEVEL", entry!], []);

        Assert.True(result.Failed);
        Assert.Contains("PlaintextEnvVars:1", result.FailureMessage);
        Assert.DoesNotContain("leaked-value", result.FailureMessage);
    }

    [Theory]
    [InlineData("")]
    [InlineData("app-settings")]
    [InlineData("team-a/")]
    [InlineData("/app-settings")]
    [InlineData("team-a/app/settings")]
    [InlineData("*/kube-root-ca.crt")]
    [InlineData("team-a/*")]
    [InlineData("Team-A/app-settings")]
    [InlineData("team-a/App-Settings")]
    [InlineData("team-a/app_settings")]
    [InlineData("team-a/app..settings")]
    [InlineData(" team-a/app-settings")]
    [InlineData("team-a/app-settings\n")]
    [InlineData("team-a\n/app-settings")]
    [InlineData(null)]
    public void ValidatorRejectsMalformedConfigMapReferences(string? entry)
    {
        var result = Validate([], ["team-a/app-settings", entry!]);

        Assert.True(result.Failed);
        Assert.Contains("PlaintextConfigMaps:1", result.FailureMessage);
    }

    [Fact]
    public void ValidatorRejectsOverlongConfigMapNames()
    {
        var result = Validate([], [$"team-a/{string.Join('.', Enumerable.Repeat(new string('a', 63), 4))}"]);

        Assert.True(result.Failed);
        Assert.Contains("PlaintextConfigMaps:0", result.FailureMessage);
    }

    [Fact]
    public void AllowlistsDefaultToEmpty()
    {
        var options = new KubeMcpOptions();

        Assert.Empty(options.PlaintextEnvVars);
        Assert.Empty(options.PlaintextConfigMaps);
    }

    [Fact]
    public void EnvironmentVariableEntriesMergeWithFileEntriesByIndex()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["KubeMcp:PlaintextEnvVars:0"] = "LOG_LEVEL",
                ["KubeMcp:PlaintextEnvVars:1"] = "TZ"
            })
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["KubeMcp:PlaintextEnvVars:0"] = "PORT"
            })
            .Build();
        var options = new KubeMcpOptions();

        configuration.GetSection(KubeMcpOptions.SectionName).Bind(options);

        Assert.Equal(["PORT", "TZ"], options.PlaintextEnvVars);
    }

    private static Microsoft.Extensions.Options.ValidateOptionsResult Validate(
        string[] envVars,
        string[] configMaps) =>
        new KubeMcpOptionsValidator(new TestHostEnvironment("Production")).Validate(
            null,
            new KubeMcpOptions
            {
                SecretHmacKey = ReaderTestOptions.HmacKey,
                AllowedResources = new() { ["pods"] = ReaderTestOptions.R("", "v1", "pods", "Pod") },
                Authentication = new() { ApiKey = new string('k', 32) },
                PlaintextEnvVars = envVars,
                PlaintextConfigMaps = configMaps
            });

    private static ReaderHost Host(
        string name,
        string group,
        string kind,
        string[]? plaintextEnvVars = null,
        string[]? plaintextConfigMaps = null,
        string? resource = null,
        string version = "v1") =>
        new(ReaderTestOptions.Options(
            resources: new() { [name] = ReaderTestOptions.R(group, version, resource ?? name, kind) },
            plaintextEnvVars: plaintextEnvVars,
            plaintextConfigMaps: plaintextConfigMaps));

    private static string Fingerprint(string value) =>
        new SecretFingerprinterFixture().Fingerprinter.Fingerprint(Encoding.UTF8.GetBytes(value));

    private static JsonObject PodSpec()
    {
        var spec = new JsonObject();
        foreach (var list in ContainerLists)
        {
            spec[list] = new JsonArray(new JsonObject
            {
                ["name"] = list,
                ["image"] = "example.com/app:1",
                ["env"] = new JsonArray(
                    new JsonObject { ["name"] = "API_TOKEN", ["value"] = RawEnvValue },
                    new JsonObject { ["name"] = "LOG_LEVEL", ["value"] = AllowedEnvValue },
                    new JsonObject { ["name"] = "API_TOKEN", ["value"] = RawEnvValue },
                    new JsonObject
                    {
                        ["name"] = "FROM_SECRET",
                        ["valueFrom"] = new JsonObject
                        {
                            ["secretKeyRef"] = new JsonObject { ["name"] = "db", ["key"] = "password" }
                        }
                    })
            });
        }

        return spec;
    }

    private static JsonObject WorkloadBody(string group, string kind, string podSpecPath, JsonObject podSpec)
    {
        var root = new JsonObject
        {
            ["apiVersion"] = group.Length == 0 ? "v1" : $"{group}/v1",
            ["kind"] = kind,
            ["metadata"] = new JsonObject { ["name"] = "app", ["namespace"] = "prod" }
        };

        var segments = podSpecPath.Split('.');
        var parent = root;
        foreach (var segment in segments[..^1])
        {
            var child = new JsonObject();
            parent[segment] = child;
            parent = child;
        }

        parent[segments[^1]] = podSpec;
        return root;
    }

    private static JsonObject ConfigMapBody(JsonObject? data, JsonObject? binaryData)
    {
        var root = new JsonObject
        {
            ["apiVersion"] = "v1",
            ["kind"] = "ConfigMap",
            ["metadata"] = new JsonObject
            {
                ["name"] = "app-config",
                ["namespace"] = "prod",
                ["creationTimestamp"] = "2024-01-01T00:00:00Z"
            }
        };
        if (data is not null)
        {
            root["data"] = data;
        }

        if (binaryData is not null)
        {
            root["binaryData"] = binaryData;
        }

        return root;
    }

    private sealed class SecretFingerprinterFixture
    {
        public SecretFingerprinter Fingerprinter { get; } = new(Convert.FromBase64String(ReaderTestOptions.HmacKey));

        public ResponseSanitizer Sanitizer => new(
            Fingerprinter,
            Microsoft.Extensions.Options.Options.Create(new KubeMcpOptions()));
    }
}
