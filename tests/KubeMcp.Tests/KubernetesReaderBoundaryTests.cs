using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace KubeMcp.Tests;

// ---------------------------------------------------------------------------
// Test infrastructure: a recording fake adapter, a controllable time provider,
// and a host that wires KubernetesReader with its real collaborators.
// ---------------------------------------------------------------------------

internal sealed class FakeKubernetesApi : IKubernetesApi
{
    private readonly object callsLock = new();

    public List<string> Calls { get; } = [];

    public List<int> ListPageSizes { get; } = [];

    public int LastListPageSize { get; private set; }
    public string? LastListContinueToken { get; private set; }
    public byte[]? LastGetBodyBytes { get; private set; }
    public byte[]? LastListBodyBytes { get; private set; }

    public Func<KubernetesResourceDescriptor, string, string, int, CancellationToken, Task<string>>? GetHandler { get; set; }
    public Func<KubernetesResourceDescriptor, string, int, string?, int, CancellationToken, Task<string>>? ListHandler { get; set; }
    public Func<string, string, CancellationToken, Task<bool>>? NamespaceLabelHandler { get; set; }

    public async Task<ReadOnlyMemory<byte>> GetNamespacedAsync(
        KubernetesResourceDescriptor descriptor, string @namespace, string name, int maxBodyBytes, CancellationToken cancellationToken)
    {
        Record($"GET {descriptor.QualifiedName} {@namespace}/{name} maxBody={maxBodyBytes}");
        var body = GetHandler is null
            ? "{}"
            : await GetHandler(descriptor, @namespace, name, maxBodyBytes, cancellationToken).ConfigureAwait(false);
        LastGetBodyBytes = Encoding.UTF8.GetBytes(body);
        return LastGetBodyBytes;
    }

    public async Task<ReadOnlyMemory<byte>> ListNamespacedAsync(
        KubernetesResourceDescriptor descriptor, string @namespace, int pageSize, string? continueToken, int maxBodyBytes, CancellationToken cancellationToken)
    {
        LastListPageSize = pageSize;
        LastListContinueToken = continueToken;
        ListPageSizes.Add(pageSize);
        Record($"LIST {descriptor.QualifiedName} {@namespace} pageSize={pageSize} continue={continueToken ?? "<null>"} maxBody={maxBodyBytes}");
        var body = ListHandler is null
            ? KubernetesJson.ListBody(
                [],
                null,
                descriptor.ApiVersion,
                descriptor.Kind + "List")
            : await ListHandler(descriptor, @namespace, pageSize, continueToken, maxBodyBytes, cancellationToken).ConfigureAwait(false);
        LastListBodyBytes = Encoding.UTF8.GetBytes(body);
        return LastListBodyBytes;
    }

    public async Task<bool> NamespaceMatchesLabelSelectorAsync(
        string @namespace,
        string labelSelector,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        Record($"NSCHECK {@namespace} selector={labelSelector} maxBody={maxBodyBytes}");
        return NamespaceLabelHandler is null
            ? true
            : await NamespaceLabelHandler(@namespace, labelSelector, cancellationToken).ConfigureAwait(false);
    }

    private void Record(string call)
    {
        lock (callsLock)
        {
            Calls.Add(call);
        }
    }

    public void Dispose()
    {
    }
}

internal sealed class FakeTimeProvider : TimeProvider
{
    private DateTimeOffset now;
    private long timestamp;

    public FakeTimeProvider(DateTimeOffset initial) => now = initial;

    public void Advance(TimeSpan duration)
    {
        now += duration;
        timestamp += duration.Ticks;
    }

    public override DateTimeOffset GetUtcNow() => now;

    public override long GetTimestamp() => timestamp;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
}

internal sealed class ReaderHost : IDisposable
{
    public KubeMcpOptions Options { get; }
    public FakeKubernetesApi Api { get; }
    public FakeTimeProvider Time { get; }
    public KubernetesReader Reader { get; }

    public ReaderHost(KubeMcpOptions options, FakeKubernetesApi? api = null, FakeTimeProvider? time = null)
    {
        Options = options;
        Time = time ?? new FakeTimeProvider(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Api = api ?? new FakeKubernetesApi();

        var fingerprinter = new SecretFingerprinter(Microsoft.Extensions.Options.Options.Create(options));
        var sanitizer = new SecretSanitizer(fingerprinter);
        var summarizer = new KubernetesListSummarizer(sanitizer, Time);
        var allowlist = new ResourceAllowlist(Microsoft.Extensions.Options.Options.Create(options));
        var namespacePolicy = new NamespaceAccessPolicy(Microsoft.Extensions.Options.Options.Create(options));

        Reader = new KubernetesReader(
            sanitizer,
            summarizer,
            allowlist,
            namespacePolicy,
            Microsoft.Extensions.Options.Options.Create(options),
            new SimpleFactory(Api),
            NullLogger<KubernetesReader>.Instance);
    }

    public void Dispose() => Reader.Dispose();
}

internal sealed class SimpleFactory(FakeKubernetesApi api) : IKubernetesClientFactory
{
    public IKubernetesApi Create() => api;
}

internal static class ReaderTestOptions
{
    public const string HmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    public static KubernetesResourceOptions R(string group, string version, string resource, string kind) => new()
    {
        Group = group,
        Version = version,
        Resource = resource,
        Kind = kind
    };

    public static KubeMcpOptions Options(
        Dictionary<string, KubernetesResourceOptions>? resources = null,
        NamespacePolicyOptions? namespacePolicy = null,
        int maxListItems = 100,
        int maxResponseBytes = 1024 * 1024,
        int listPageSize = 50,
        int maxListPages = 20,
        int secretListPageSize = 10,
        int kubernetesRequestTimeoutSeconds = 15) => new()
        {
            SecretHmacKey = HmacKey,
            AllowedResources = resources ?? new() { ["pods"] = R("", "v1", "pods", "Pod") },
            NamespacePolicy = namespacePolicy ?? new NamespacePolicyOptions(),
            MaxListItems = maxListItems,
            MaxResponseBytes = maxResponseBytes,
            MaxUpstreamBodyBytes = Math.Max(4 * 1024 * 1024, maxResponseBytes),
            ListPageSize = listPageSize,
            MaxListPages = maxListPages,
            SecretListPageSize = secretListPageSize,
            KubernetesRequestTimeoutSeconds = kubernetesRequestTimeoutSeconds
        };
}

internal static class KubernetesJson
{
    public static string PodItem(
        string name,
        string node = "node-1",
        string @namespace = "production") => JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Pod",
            metadata = new { name, @namespace, creationTimestamp = "2024-01-01T00:00:00Z" },
            spec = new { nodeName = node },
            status = new { phase = "Running", podIP = "10.0.0.1" }
        });

    public static string SecretGetBody(string name, string plaintext)
    {
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        return JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Secret",
            metadata = new
            {
                name,
                @namespace = "prod",
                uid = "uid-1",
                resourceVersion = "1",
                creationTimestamp = "2024-01-01T00:00:00Z",
                annotations = new { dangerous = "annotation-must-not-leak" }
            },
            type = "Opaque",
            data = new { password = base64, username = Convert.ToBase64String("user"u8) }
        });
    }

    public static string SecretListItem(string name, string plaintext)
    {
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        return JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Secret",
            metadata = new { name, @namespace = "prod", creationTimestamp = "2024-01-01T00:00:00Z" },
            type = "Opaque",
            data = new { password = base64 }
        });
    }

    public static string ConfigMapGetBody(string name, string value)
    {
        return JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "ConfigMap",
            metadata = new { name, @namespace = "prod", creationTimestamp = "2024-01-01T00:00:00Z" },
            data = new { key = value }
        });
    }

    public static string ListBody(
        IEnumerable<string> itemJsons,
        string? nextContinue,
        string apiVersion = "v1",
        string kind = "PodList")
    {
        var root = new JsonObject
        {
            ["apiVersion"] = apiVersion,
            ["kind"] = kind
        };
        var metadata = new JsonObject();
        if (nextContinue is not null)
        {
            metadata["continue"] = nextContinue;
        }

        root["metadata"] = metadata;
        var items = new JsonArray();
        foreach (var item in itemJsons)
        {
            items.Add(JsonNode.Parse(item));
        }

        root["items"] = items;
        return root.ToJsonString();
    }


}

// ---------------------------------------------------------------------------
// Boundary option relationships
// ---------------------------------------------------------------------------

public sealed class KubernetesBoundaryOptionsTests
{
    [Fact]
    public void SecretPagesCannotExceedRegularListPages()
    {
        var options = ReaderTestOptions.Options(listPageSize: 10, secretListPageSize: 11);

        var result = new KubeMcpOptionsValidator(new TestHostEnvironment("Development"))
            .Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("SecretListPageSize", result.FailureMessage);
    }

    [Fact]
    public void OverallMcpTimeoutMustBeValidatedAndExceedKubernetesTimeout()
    {
        var baseline = ReaderTestOptions.Options();
        var options = new KubeMcpOptions
        {
            SecretHmacKey = baseline.SecretHmacKey,
            AllowedResources = baseline.AllowedResources,
            NamespacePolicy = baseline.NamespacePolicy,
            KubernetesRequestTimeoutSeconds = 15,
            OverallMcpRequestTimeoutSeconds = 15
        };

        var result = new KubeMcpOptionsValidator(new TestHostEnvironment("Development"))
            .Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("must be greater than KubernetesRequestTimeoutSeconds", result.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3601)]
    public void OverallMcpTimeoutRejectsOutOfRangeValues(int timeoutSeconds)
    {
        var baseline = ReaderTestOptions.Options();
        var options = new KubeMcpOptions
        {
            SecretHmacKey = baseline.SecretHmacKey,
            AllowedResources = baseline.AllowedResources,
            NamespacePolicy = baseline.NamespacePolicy,
            KubernetesRequestTimeoutSeconds = 15,
            OverallMcpRequestTimeoutSeconds = timeoutSeconds
        };

        var result = new KubeMcpOptionsValidator(new TestHostEnvironment("Development"))
            .Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("between 1 and 3600", result.FailureMessage);
    }

    [Fact]
    public void UpstreamBodyBudgetCannotBeSmallerThanSafeOutputBudget()
    {
        var valid = ReaderTestOptions.Options(maxResponseBytes: 128 * 1024);
        var options = new KubeMcpOptions
        {
            SecretHmacKey = valid.SecretHmacKey,
            AllowedResources = valid.AllowedResources,
            NamespacePolicy = valid.NamespacePolicy,
            MaxResponseBytes = valid.MaxResponseBytes,
            MaxUpstreamBodyBytes = 64 * 1024
        };

        var result = new KubeMcpOptionsValidator(new TestHostEnvironment("Development"))
            .Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("MaxUpstreamBodyBytes", result.FailureMessage);
    }
}

// ---------------------------------------------------------------------------
// Policy and ordering (P2-07 regression list)
// ---------------------------------------------------------------------------

public sealed class KubernetesReaderPolicyAndOrderTests
{
    [Fact]
    public async Task OversizedResourceIsRejectedBeforePolicyOrKubernetesCalls()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        var oversized = new string('r', KubernetesNameValidator.MaximumQualifiedNameLength + 1);

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync(oversized, "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.InvalidRequest, exception.Category);
        Assert.Empty(host.Api.Calls);
        Assert.DoesNotContain(oversized, exception.Message);
    }

    [Fact]
    public async Task UnknownResourceIsDeniedBeforeAnyKubernetesCall()
    {
        var options = ReaderTestOptions.Options(namespacePolicy: new NamespacePolicyOptions
        {
            Mode = NamespacePolicyMode.LabelSelector,
            LabelSelector = "env=prod"
        });
        using var host = new ReaderHost(options);
        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("jobs", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.ResourceNotAllowed, exception.Category);
        Assert.Empty(host.Api.Calls);
    }

    [Fact]
    public async Task StaticNamespaceDenialMakesNoKubernetesCall()
    {
        var options = ReaderTestOptions.Options(namespacePolicy: new NamespacePolicyOptions
        {
            Mode = NamespacePolicyMode.Blacklist,
            DeniedNamespaces = ["kube-system"]
        });

        using var host = new ReaderHost(options);
        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "kube-system", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.NamespaceNotAllowed, exception.Category);
        Assert.Empty(host.Api.Calls);
    }

    [Fact]
    public async Task LabelCheckIsTheOnlyCallBeforeListAndBlocksRead()
    {
        var options = ReaderTestOptions.Options(namespacePolicy: new NamespacePolicyOptions
        {
            Mode = NamespacePolicyMode.LabelSelector,
            LabelSelector = "env=prod"
        });

        using var host = new ReaderHost(options);
        host.Api.NamespaceLabelHandler = (_, _, _) => Task.FromResult(false);

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "unlabelled", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.NamespaceNotAllowed, exception.Category);
        var call = Assert.Single(host.Api.Calls);
        Assert.StartsWith("NSCHECK", call);
        Assert.DoesNotContain("LIST", host.Api.Calls[0]);
    }

    [Fact]
    public async Task LabelCheckRunsBeforeListInAllowlistMode()
    {
        var options = ReaderTestOptions.Options(namespacePolicy: new NamespacePolicyOptions
        {
            Mode = NamespacePolicyMode.LabelSelector,
            LabelSelector = "env=prod"
        });

        using var host = new ReaderHost(options);
        host.Api.NamespaceLabelHandler = (_, _, _) => Task.FromResult(true);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p1")], null));

        await host.Reader.ReadAsync("pods", "production", null, CancellationToken.None);

        Assert.StartsWith("NSCHECK", host.Api.Calls[0]);
        Assert.StartsWith("LIST", host.Api.Calls[1]);
    }


}

// ---------------------------------------------------------------------------
// GET vs LIST and verb selection
// ---------------------------------------------------------------------------

public sealed class KubernetesReaderGetListTests
{
    [Fact]
    public async Task NameSuppliedIssuesGetNotList()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(KubernetesJson.PodItem("web-1"));

        await host.Reader.ReadAsync("pods", "production", "web-1", CancellationToken.None);

        Assert.Contains(host.Api.Calls, c => c.StartsWith("GET pods"));
        Assert.DoesNotContain(host.Api.Calls, c => c.StartsWith("LIST"));
    }

    [Fact]
    public async Task NameOmittedIssuesListNotGet()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p1")], null));

        await host.Reader.ReadAsync("pods", "production", null, CancellationToken.None);

        Assert.Contains(host.Api.Calls, c => c.StartsWith("LIST pods"));
        Assert.DoesNotContain(host.Api.Calls, c => c.StartsWith("GET"));
    }


}

// ---------------------------------------------------------------------------
// Timeout and cancellation
// ---------------------------------------------------------------------------

public sealed class KubernetesReaderTimeoutTests
{
    [Fact]
    public async Task ConfiguredTimeoutTranslatesToTimeoutCategory()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options(kubernetesRequestTimeoutSeconds: 1));
        host.Api.ListHandler = async (_, _, _, _, _, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return KubernetesJson.ListBody([], null);
        };

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.Timeout, exception.Category);
    }

    [Fact]
    public async Task UnrelatedOperationCanceledDoesNotMasqueradeAsTimeout()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.ListHandler = (_, _, _, _, _, _) => throw new OperationCanceledException();

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.Internal, exception.Category);
    }

    [Fact]
    public async Task CallerCancellationPropagatesAsOperationCanceled()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.ListHandler = (_, _, _, _, _, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(KubernetesJson.ListBody([], null));
        };

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            host.Reader.ReadAsync("pods", "production", null, cts.Token));
    }
}

// ---------------------------------------------------------------------------
// Secret routing and sanitization
// ---------------------------------------------------------------------------

public sealed class KubernetesReaderSecretTests
{
    [Fact]
    public async Task SecretGetAppliesSanitizerAndOmitsRawData()
    {
        var options = ReaderTestOptions.Options(resources: new() { ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret") });
        using var host = new ReaderHost(options);
        const string plaintext = "s3cr3t-value";
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(KubernetesJson.SecretGetBody("db", plaintext));

        var result = await host.Reader.ReadAsync("secrets", "prod", "db", CancellationToken.None);

        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        Assert.DoesNotContain(plaintext, result.Json);
        Assert.DoesNotContain(base64, result.Json);
        Assert.DoesNotContain("annotation-must-not-leak", result.Json);
        Assert.DoesNotContain("annotations", result.Json);

        using var document = JsonDocument.Parse(result.Json);
        var data = document.RootElement.GetProperty("data");
        var password = data.GetProperty("password").GetString();
        Assert.StartsWith("hmac-sha256:", password);
        Assert.NotEqual(password, data.GetProperty("username").GetString());
        Assert.All(host.Api.LastGetBodyBytes!, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task SecretListAppliesListItemSanitizerAndOmitsRawData()
    {
        var options = ReaderTestOptions.Options(resources: new() { ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret") });
        using var host = new ReaderHost(options);
        const string plaintext = "s3cr3t-value";
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody(
                [KubernetesJson.SecretListItem("db", plaintext)],
                null,
                "v1",
                "SecretList"));

        var result = await host.Reader.ReadAsync("secrets", "prod", null, CancellationToken.None);

        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        Assert.DoesNotContain(plaintext, result.Json);
        Assert.DoesNotContain(base64, result.Json);
        Assert.DoesNotContain("hmac-sha256:", result.Json);

        using var document = JsonDocument.Parse(result.Json);
        var item = Assert.Single(document.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("db", item.GetProperty("name").GetString());
        Assert.Equal("Opaque", item.GetProperty("type").GetString());
        Assert.Equal("password", Assert.Single(item.GetProperty("keys").EnumerateArray()).GetString());
        Assert.False(item.TryGetProperty("data", out _));
        Assert.All(host.Api.LastListBodyBytes!, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task InvalidSecretDataMapsToMalformedResponse()
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
        });
        using var host = new ReaderHost(options);
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(
            "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"bad\",\"namespace\":\"prod\"},\"data\":{\"password\":\"not base64!\"}}");

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("secrets", "prod", "bad", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.Equal(KubernetesApi.SafeMessage(KubernetesErrorCategory.MalformedResponse), exception.Message);
        Assert.All(host.Api.LastGetBodyBytes!, value => Assert.Equal(0, value));
    }

    [Theory]
    [InlineData("\"data\":[]")]
    [InlineData("\"stringData\":false")]
    [InlineData("\"type\":{}")]
    [InlineData("\"immutable\":\"true\"")]
    public async Task MalformedSecretFieldsAreRejectedAndRawBodyIsCleared(
        string malformedField)
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
        });
        using var host = new ReaderHost(options);
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(
            "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"bad\",\"namespace\":\"prod\"}," +
            malformedField + "}");

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("secrets", "prod", "bad", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.All(host.Api.LastGetBodyBytes!, value => Assert.Equal(0, value));
    }

    [Theory]
    [InlineData("\"data\":[]")]
    [InlineData("\"data\":{\"password\":false}")]
    [InlineData("\"stringData\":false")]
    [InlineData("\"stringData\":{\"password\":[]}")]
    [InlineData("\"type\":{}")]
    [InlineData("\"immutable\":\"true\"")]
    public async Task MalformedSecretListFieldsAreRejectedAndRawPageIsCleared(
        string malformedField)
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
        });
        using var host = new ReaderHost(options);
        var item =
            "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"bad\",\"namespace\":\"prod\"}," +
            malformedField + "}";
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([item], null, "v1", "SecretList"));

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("secrets", "prod", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.All(host.Api.LastListBodyBytes!, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task SecretListValidatesMalformedItemsOmittedByItemCap()
    {
        var options = ReaderTestOptions.Options(
            resources: new()
            {
                ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
            },
            maxListItems: 1);
        using var host = new ReaderHost(options);
        const string malformedItem =
            "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"bad\",\"namespace\":\"prod\"},\"data\":{\"password\":false}}";
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody(
                [KubernetesJson.SecretListItem("good", "safe"), malformedItem],
                null,
                "v1",
                "SecretList"));

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("secrets", "prod", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.All(host.Api.LastListBodyBytes!, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task ContinueTokenScanDoesNotTreatSecretDataAsListMetadata()
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
        });
        using var host = new ReaderHost(options);
        var item = JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Secret",
            metadata = new { name = "db", @namespace = "prod" },
            data = new Dictionary<string, string>
            {
                ["continue"] = new string('x', KubernetesApi.MaximumContinueTokenBytes + 1)
            }
        });
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([item], null, "v1", "SecretList"));

        var result = await host.Reader.ReadAsync(
            "secrets",
            "prod",
            null,
            CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.Equal(1, document.RootElement.GetProperty("count").GetInt32());
        Assert.Equal("continue", Assert.Single(document.RootElement
            .GetProperty("items")[0]
            .GetProperty("keys")
            .EnumerateArray()).GetString());
        Assert.All(host.Api.LastListBodyBytes!, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task MalformedSecretListStillClearsRawPage()
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
        });
        using var host = new ReaderHost(options);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult("{}");

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("secrets", "prod", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.All(host.Api.LastListBodyBytes!, value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task NonSecretGetReturnsFullObjectWithoutSanitization()
    {
        var options = ReaderTestOptions.Options(resources: new() { ["configmaps"] = ReaderTestOptions.R("", "v1", "configmaps", "ConfigMap") });
        using var host = new ReaderHost(options);
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(KubernetesJson.ConfigMapGetBody("cm", "the-value"));

        var result = await host.Reader.ReadAsync("configmaps", "prod", "cm", CancellationToken.None);

        Assert.Contains("the-value", result.Json);
        using var document = JsonDocument.Parse(result.Json);
        Assert.Equal("the-value", document.RootElement.GetProperty("data").GetProperty("key").GetString());
    }
}

// ---------------------------------------------------------------------------
// Safe error translation (P2-02 Kubernetes boundary part)
// ---------------------------------------------------------------------------

public sealed class KubernetesReaderErrorTests
{
    [Theory]
    [InlineData(KubernetesErrorCategory.NotFound, 404)]
    [InlineData(KubernetesErrorCategory.AccessDenied, 403)]
    [InlineData(KubernetesErrorCategory.RateLimited, 429)]
    [InlineData(KubernetesErrorCategory.ServerError, 503)]
    [InlineData(KubernetesErrorCategory.MalformedResponse, null)]
    [InlineData(KubernetesErrorCategory.NetworkError, null)]
    [InlineData(KubernetesErrorCategory.ResponseTooLarge, null)]
    [InlineData(KubernetesErrorCategory.InvalidRequest, 400)]
    public async Task TranslatesAdapterExceptionsToSafeBoundaryException(
        KubernetesErrorCategory category,
        int? statusCode)
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        var upstreamSecret = "UPSTREAM-RESPONSE-BODY-MUST-NOT-LEAK";
        host.Api.GetHandler = (_, _, _, _, _) => throw new KubernetesApiException(
            category,
            upstreamSecret,
            statusCode);

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", "web-1", CancellationToken.None));

        Assert.Equal(category, exception.Category);
        Assert.Equal(KubernetesApi.SafeMessage(category), exception.Message);
        Assert.DoesNotContain(upstreamSecret, exception.ToString());
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task MalformedGetResponseMapsToMalformedCategory()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult("not-json");

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", "web-1", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.Equal(KubernetesApi.SafeMessage(KubernetesErrorCategory.MalformedResponse), exception.Message);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"other\",\"namespace\":\"production\"}}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"web-1\",\"namespace\":\"production\"}}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"web-1\"}}")]
    [InlineData("{\"APIVERSION\":\"v1\",\"KIND\":\"Pod\",\"metadata\":{\"name\":\"web-1\",\"namespace\":\"production\"}}")]
    [InlineData("{\"apiVersion\":\"v1\",\"ApiVersion\":\"evil/v9\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"web-1\",\"namespace\":\"production\"}}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"web-1\",\"namespace\":\"production\"},\"Metadata\":{\"name\":\"other\",\"namespace\":\"other\"}}")]
    public async Task GetRequiresExpectedKubernetesObjectIdentity(string body)
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(body);

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", "web-1", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"items\":null}")]
    [InlineData("{\"items\":[null]}")]
    [InlineData("{\"metadata\":{\"continue\":42},\"items\":[]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"ServiceList\",\"metadata\":{},\"items\":[]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[{}]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p1\",\"namespace\":\"other\"}}]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[{\"APIVERSION\":\"v1\",\"KIND\":\"Pod\",\"metadata\":{\"name\":\"p1\",\"namespace\":\"production\"}}]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[{\"apiVersion\":\"v1\",\"ApiVersion\":\"evil/v9\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p1\",\"namespace\":\"production\"}}]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"name\":\"p1\",\"namespace\":\"production\"},\"Metadata\":{\"name\":\"other\",\"namespace\":\"other\"}}]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[],\"Items\":[]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"continue\":\"c1\",\"Continue\":\"c2\"},\"items\":[]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"continue\":\"c1\",\"continue\":\"c2\"},\"items\":[]}")]
    [InlineData("{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"continue\":\"\\uD800\"},\"items\":[]}")]
    public async Task MalformedListShapeMapsToMalformedCategory(string body)
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(body);

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
    }

    [Fact]
    public async Task ListAcceptsKubernetesItemsWithoutRepeatedTypeMeta()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            "{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{},\"items\":[" +
            "{\"metadata\":{\"name\":\"p1\",\"namespace\":\"production\",\"creationTimestamp\":\"2024-01-01T00:00:00Z\"},\"spec\":{\"containers\":[]},\"status\":{}}]}");

        var result = await host.Reader.ReadAsync(
            "pods", "production", null, CancellationToken.None);

        using var json = JsonDocument.Parse(result.Json);
        var item = Assert.Single(json.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("p1", item.GetProperty("name").GetString());
    }

    [Fact]
    public async Task ListValidatesMalformedItemsOmittedByItemCap()
    {
        var options = ReaderTestOptions.Options(maxListItems: 1);
        using var host = new ReaderHost(options);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody(
                [
                    KubernetesJson.PodItem("p1"),
                    KubernetesJson.PodItem("p2", @namespace: "other")
                ],
                null));

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
    }

    [Fact]
    public async Task GetResponseExceedingSafeOutputBudgetThrowsResponseTooLarge()
    {
        var options = ReaderTestOptions.Options(
            resources: new() { ["configmaps"] = ReaderTestOptions.R("", "v1", "configmaps", "ConfigMap") },
            maxResponseBytes: 1024);
        using var host = new ReaderHost(options);
        host.Api.GetHandler = (_, _, _, _, _) => Task.FromResult(
            KubernetesJson.ConfigMapGetBody("big", new string('x', 2048)));

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("configmaps", "prod", "big", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.ResponseTooLarge, exception.Category);
    }

    [Fact]
    public async Task UnexpectedBoundaryFailureMapsToInternalCategory()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options());
        host.Api.GetHandler = (_, _, _, _, _) => throw new InvalidOperationException("unexpected-detail");

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", "web-1", CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.Internal, exception.Category);
        Assert.Equal("The Kubernetes API request failed.", exception.Message);
        Assert.DoesNotContain("unexpected-detail", exception.Message);
    }
}

// ---------------------------------------------------------------------------
// Pagination and limits (P1-02)
// ---------------------------------------------------------------------------

public sealed class KubernetesReaderPaginationTests
{
    [Fact]
    public async Task PaginatesAcrossContinueTokensAndReportsNotLimited()
    {
        var options = ReaderTestOptions.Options(maxListItems: 100, listPageSize: 2);
        using var host = new ReaderHost(options);
        host.Api.ListHandler = (_, _, _, cont, _, _) => cont switch
        {
            null => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p1"), KubernetesJson.PodItem("p2")], "c1")),
            "c1" => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p3"), KubernetesJson.PodItem("p4")], "c2")),
            "c2" => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p5")], null)),
            _ => throw new InvalidOperationException("unexpected continue token")
        };

        var result = await host.Reader.ReadAsync("pods", "production", null, CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.Equal(5, document.RootElement.GetProperty("count").GetInt32());
        Assert.False(document.RootElement.GetProperty("limited").GetBoolean());
        Assert.Equal(3, host.Api.Calls.Count(c => c.StartsWith("LIST")));
    }

    [Fact]
    public async Task PageCapStopsUniqueEmptyContinuationChainAndMarksLimited()
    {
        var options = ReaderTestOptions.Options(
            maxListItems: 100,
            listPageSize: 2,
            maxListPages: 2);
        using var host = new ReaderHost(options);
        var page = 0;
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([], $"token-{Interlocked.Increment(ref page)}"));

        var result = await host.Reader.ReadAsync(
            "pods",
            "production",
            null,
            CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.True(document.RootElement.GetProperty("limited").GetBoolean());
        Assert.Equal(0, document.RootElement.GetProperty("count").GetInt32());
        Assert.Equal(2, host.Api.Calls.Count(c => c.StartsWith("LIST")));
    }

    [Fact]
    public async Task RepeatedContinueTokenIsRejectedInsteadOfLooping()
    {
        var options = ReaderTestOptions.Options(maxListItems: 10, listPageSize: 2);
        using var host = new ReaderHost(options);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([], "same-token"));

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.Equal(2, host.Api.Calls.Count(c => c.StartsWith("LIST")));
    }

    [Fact]
    public async Task OversizedContinueTokenIsRejectedBeforeReplay()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options(maxListPages: 100));
        var oversizedToken = new string('t', KubernetesApi.MaximumContinueTokenBytes + 1);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([], oversizedToken));

        var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
            host.Reader.ReadAsync("pods", "production", null, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        Assert.Equal(1, host.Api.Calls.Count(call => call.StartsWith("LIST")));
    }

    [Fact]
    public async Task EscapedContinueTokenIsMeasuredAfterBoundedDecoding()
    {
        using var host = new ReaderHost(ReaderTestOptions.Options(maxListPages: 2));
        var decodedToken = new string('t', 1400);
        var escapedToken = string.Concat(Enumerable.Repeat("\\u0074", decodedToken.Length));
        var firstPage =
            "{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"continue\":\"" +
            escapedToken + "\"},\"items\":[]}";
        host.Api.ListHandler = (_, _, _, continueToken, _, _) => continueToken switch
        {
            null => Task.FromResult(firstPage),
            _ when continueToken == decodedToken => Task.FromResult(KubernetesJson.ListBody([], null)),
            _ => throw new InvalidOperationException("unexpected continue token")
        };

        var result = await host.Reader.ReadAsync(
            "pods",
            "production",
            null,
            CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.False(document.RootElement.GetProperty("limited").GetBoolean());
        Assert.Equal(2, host.Api.Calls.Count(call => call.StartsWith("LIST")));
    }

    [Fact]
    public async Task ItemCapMarksLimitedAndAvoidsExtraPageFetch()
    {
        var options = ReaderTestOptions.Options(maxListItems: 3, listPageSize: 2);
        using var host = new ReaderHost(options);
        host.Api.ListHandler = (_, _, _, cont, _, _) => cont switch
        {
            null => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p1"), KubernetesJson.PodItem("p2")], "c1")),
            "c1" => Task.FromResult(KubernetesJson.ListBody([KubernetesJson.PodItem("p3"), KubernetesJson.PodItem("p4")], "c2")),
            _ => throw new InvalidOperationException("unexpected continue token")
        };

        var result = await host.Reader.ReadAsync("pods", "production", null, CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.Equal(3, document.RootElement.GetProperty("count").GetInt32());
        Assert.True(document.RootElement.GetProperty("limited").GetBoolean());
        Assert.Equal(2, host.Api.Calls.Count(c => c.StartsWith("LIST")));
        Assert.Equal([2, 2], host.Api.ListPageSizes);
    }

    [Fact]
    public async Task IncrementalUtf8AccountingAcceptsExactSerializedBudget()
    {
        static ReaderHost CreateHost(int maxResponseBytes)
        {
            var host = new ReaderHost(ReaderTestOptions.Options(
                maxResponseBytes: maxResponseBytes,
                listPageSize: 1));
            host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
                KubernetesJson.ListBody([KubernetesJson.PodItem("pod-1", "nødé-東京")], null));
            return host;
        }

        int exactBytes;
        using (var baseline = CreateHost(4096))
        {
            var result = await baseline.Reader.ReadAsync(
                "pods",
                "production",
                null,
                CancellationToken.None);
            exactBytes = Encoding.UTF8.GetByteCount(result.Json);
        }

        using (var exact = CreateHost(exactBytes))
        {
            var result = await exact.Reader.ReadAsync(
                "pods",
                "production",
                null,
                CancellationToken.None);
            using var document = JsonDocument.Parse(result.Json);
            Assert.Equal(1, document.RootElement.GetProperty("count").GetInt32());
            Assert.Equal(exactBytes, Encoding.UTF8.GetByteCount(result.Json));
        }

        using (var oneByteShort = CreateHost(exactBytes - 1))
        {
            var result = await oneByteShort.Reader.ReadAsync(
                "pods",
                "production",
                null,
                CancellationToken.None);
            using var document = JsonDocument.Parse(result.Json);
            Assert.Equal(0, document.RootElement.GetProperty("count").GetInt32());
            Assert.True(document.RootElement.GetProperty("limited").GetBoolean());
        }
    }

    [Fact]
    public async Task IncrementalAccountingUsesExactLimitedMarkerSize()
    {
        var page = new[]
        {
            KubernetesJson.PodItem("pod-1"),
            KubernetesJson.PodItem("pod-2"),
            KubernetesJson.PodItem("pod-3")
        };

        int exactLimitedBytes;
        using (var baseline = new ReaderHost(ReaderTestOptions.Options(
                   maxListItems: 2,
                   maxResponseBytes: 4096)))
        {
            baseline.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
                KubernetesJson.ListBody(page, null));
            var result = await baseline.Reader.ReadAsync(
                "pods",
                "production",
                null,
                CancellationToken.None);
            exactLimitedBytes = Encoding.UTF8.GetByteCount(result.Json);
        }

        using var exact = new ReaderHost(ReaderTestOptions.Options(
            maxListItems: 100,
            maxResponseBytes: exactLimitedBytes));
        exact.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody(page, null));

        var exactResult = await exact.Reader.ReadAsync(
            "pods",
            "production",
            null,
            CancellationToken.None);

        using var document = JsonDocument.Parse(exactResult.Json);
        Assert.Equal(2, document.RootElement.GetProperty("count").GetInt32());
        Assert.True(document.RootElement.GetProperty("limited").GetBoolean());
        Assert.Equal(exactLimitedBytes, Encoding.UTF8.GetByteCount(exactResult.Json));
    }

    [Fact]
    public async Task ResponseBudgetMarksLimitedAndKeepsOutputUnderBudget()
    {
        var options = ReaderTestOptions.Options(maxResponseBytes: 600, listPageSize: 50);
        using var host = new ReaderHost(options);
        var items = Enumerable.Range(1, 20).Select(i => KubernetesJson.PodItem($"pod-{i:D3}")).ToArray();
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(KubernetesJson.ListBody(items, null));

        var result = await host.Reader.ReadAsync("pods", "production", null, CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.True(document.RootElement.GetProperty("limited").GetBoolean());
        Assert.True(document.RootElement.GetProperty("count").GetInt32() < 20);
        Assert.True(document.RootElement.GetProperty("count").GetInt32() > 0);
        Assert.True(Encoding.UTF8.GetByteCount(result.Json) <= 600);
    }

    [Fact]
    public async Task SecretListUsesSmallerPageSizeThanOtherResources()
    {
        var options = ReaderTestOptions.Options(
            resources: new()
            {
                ["pods"] = ReaderTestOptions.R("", "v1", "pods", "Pod"),
                ["secrets"] = ReaderTestOptions.R("", "v1", "secrets", "Secret")
            },
            listPageSize: 50,
            secretListPageSize: 10);

        using var host = new ReaderHost(options);
        host.Api.ListHandler = (descriptor, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([], null, descriptor.ApiVersion, descriptor.Kind + "List"));

        await host.Reader.ReadAsync("pods", "production", null, CancellationToken.None);
        Assert.Equal(50, host.Api.LastListPageSize);

        await host.Reader.ReadAsync("secrets", "production", null, CancellationToken.None);
        Assert.Equal(10, host.Api.LastListPageSize);
    }

    [Fact]
    public async Task ListPreservesConfiguredNameAndExposesCanonicalResource()
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["cnpg-clusters"] = ReaderTestOptions.R("postgresql.cnpg.io", "v1", "clusters", "Cluster")
        });
        using var host = new ReaderHost(options);
        host.Api.ListHandler = (_, _, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([], null, "postgresql.cnpg.io/v1", "ClusterList"));

        var result = await host.Reader.ReadAsync("cnpg-clusters", "db", null, CancellationToken.None);

        using var document = JsonDocument.Parse(result.Json);
        Assert.Equal("cnpg-clusters", document.RootElement.GetProperty("resource").GetString());
        Assert.Equal("clusters.postgresql.cnpg.io", document.RootElement.GetProperty("canonicalResource").GetString());
    }
}
