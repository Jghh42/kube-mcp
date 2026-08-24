using System.Net;
using System.Net.Http.Json;
using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Client;

namespace KubeMcp.Tests;

public sealed class EndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private readonly WebApplicationFactory<Program> factory;
    private readonly HttpClient client;

    public EndpointTests(WebApplicationFactory<Program> factory)
    {
        this.factory = factory.WithWebHostBuilder(builder =>
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey));
        client = this.factory.CreateClient();
    }

    [Fact]
    public async Task RootDescribesRunningService()
    {
        var response = await client.GetAsync("/");
        var body = await response.Content.ReadFromJsonAsync<ServiceStatus>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(new ServiceStatus("kube-mcp", "running"), body);
    }

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/readyz")]
    public async Task HealthEndpointsReportHealthy(string path)
    {
        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public void DefaultAllowlistIncludesCoreResourcesOnly()
    {
        var allowlist = factory.Services.GetRequiredService<ResourceAllowlist>();

        Assert.False(allowlist.AllowsAll);
        Assert.Equal("pods", allowlist.Resolve("pods").QualifiedName);
        Assert.Equal(
            "deployments.apps",
            allowlist.Resolve("deployments").QualifiedName);
        Assert.Equal(
            "endpointslices.discovery.k8s.io",
            allowlist.Resolve("endpointslices").QualifiedName);
        // Optional CloudNativePG and Traefik CRDs are deliberately excluded from
        // the default allowlist and shipped as overlays so the default surface
        // stays small and cannot drift from the default RBAC.
        Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("clusters.postgresql.cnpg.io"));
        Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("ingressroutes.traefik.io"));
        Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("namespaces"));
    }

    [Fact]
    public async Task McpEndpointExposesExactlyOneTool()
    {
        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(client.BaseAddress!, "/mcp"),
                Name = "kube-mcp-test"
            },
            client,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);

        var tools = await mcpClient.ListToolsAsync();

        var tool = Assert.Single(tools);
        Assert.Equal("k8s_get", tool.Name);
        Assert.Equal(
            ["name", "namespace", "resource"],
            tool.JsonSchema.GetProperty("properties")
                .EnumerateObject()
                .Select(property => property.Name)
                .Order()
                .ToArray());
        Assert.Equal(
            ["namespace", "resource"],
            tool.JsonSchema.GetProperty("required")
                .EnumerateArray()
                .Select(value => value.GetString()!)
                .Order()
                .ToArray());
        Assert.True(tool.ProtocolTool.Annotations?.ReadOnlyHint);
        Assert.False(tool.ProtocolTool.Annotations?.DestructiveHint);
    }

    [Fact]
    public void OverallTimeoutPolicyIsValidatedAndAttachedOnlyToMcpEndpoints()
    {
        _ = client; // Ensure the application and endpoint data source are initialized.
        var timeoutOptions = factory.Services.GetRequiredService<IOptions<RequestTimeoutOptions>>().Value;
        Assert.Equal(
            TimeSpan.FromSeconds(30),
            timeoutOptions.Policies[McpRequestTimeoutOptionsSetup.PolicyName].Timeout);

        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints;

        // Inspect the concrete endpoint route and its timeout metadata without
        // relying on display names.
        var routed = endpoints.OfType<RouteEndpoint>().ToArray();
        Assert.Contains(routed, endpoint =>
            endpoint.RoutePattern.RawText?.StartsWith("/mcp", StringComparison.Ordinal) == true &&
            endpoint.Metadata.GetMetadata<RequestTimeoutAttribute>()?.PolicyName == McpRequestTimeoutOptionsSetup.PolicyName);
        Assert.DoesNotContain(routed, endpoint =>
            endpoint.RoutePattern.RawText is "/" or "/healthz" or "/readyz" &&
            endpoint.Metadata.GetMetadata<RequestTimeoutAttribute>() is not null);
    }

    [Fact]
    public async Task OverallDeadlineCancelsTheReaderAndIsAuditedAsServerTimeout()
    {
        var reader = new CancellationObservingReader();
        var sink = new CapturingAuditSink();
        await using var timeoutFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "None");
            builder.UseSetting("KubeMcp:OverallMcpRequestTimeoutSeconds", "2");
            builder.UseSetting("KubeMcp:KubernetesRequestTimeoutSeconds", "1");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IKubernetesReader>();
                services.AddSingleton<IKubernetesReader>(reader);
                services.AddSingleton<IAuditSink>(sink);
            });
        });
        using var timeoutClient = timeoutFactory.CreateClient();
        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(timeoutClient.BaseAddress!, "/mcp"),
                Name = "overall-timeout-test"
            },
            timeoutClient,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);

        await Assert.ThrowsAnyAsync<Exception>(() => mcpClient.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "pods",
                ["namespace"] = "default"
            },
            cancellationToken: CancellationToken.None).AsTask());

        await reader.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var audit = await sink.WaitForKubernetesCategoryAsync(AuditCategories.ServerTimeout);
        Assert.Equal("timeout", audit.Result);
    }

    [Fact]
    public async Task CallerCancellationPropagatesWithoutBecomingServerTimeout()
    {
        var reader = new CancellationObservingReader();
        var sink = new CapturingAuditSink();
        await using var cancellationFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "None");
            builder.UseSetting("KubeMcp:OverallMcpRequestTimeoutSeconds", "30");
            builder.UseSetting("KubeMcp:KubernetesRequestTimeoutSeconds", "15");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IKubernetesReader>();
                services.AddSingleton<IKubernetesReader>(reader);
                services.AddSingleton<IAuditSink>(sink);
            });
        });
        using var cancellationClient = cancellationFactory.CreateClient();
        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(cancellationClient.BaseAddress!, "/mcp"),
                Name = "caller-cancellation-test"
            },
            cancellationClient,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);
        using var callerCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        // The MCP transport represents the aborted server response as HTTP 499;
        // the server-side audit category below is the cancellation source of truth.
        await Assert.ThrowsAnyAsync<Exception>(() => mcpClient.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "pods",
                ["namespace"] = "default"
            },
            cancellationToken: callerCancellation.Token).AsTask());

        await reader.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var audit = await sink.WaitForKubernetesCategoryAsync(AuditCategories.ClientCancelled);
        Assert.Equal("cancelled", audit.Result);
        Assert.DoesNotContain(sink.Snapshot(), record => record.Category == AuditCategories.ServerTimeout);
    }

    private sealed record ServiceStatus(string Service, string Status);

    private sealed class CancellationObservingReader : IKubernetesReader
    {
        public TaskCompletionSource CancellationObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken)
        {
            using var registration = cancellationToken.Register(() => CancellationObserved.TrySetResult());
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class CapturingAuditSink : IAuditSink
    {
        private readonly object sync = new();
        private readonly List<AuditRecord> records = [];

        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
        {
            lock (sync)
            {
                records.Add(record);
            }

            return ValueTask.CompletedTask;
        }

        public IReadOnlyList<AuditRecord> Snapshot()
        {
            lock (sync)
            {
                return records.ToArray();
            }
        }

        public async Task<AuditRecord> WaitForKubernetesCategoryAsync(string category)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                lock (sync)
                {
                    var found = records.FirstOrDefault(record =>
                        record.EventType == AuditEventType.KubernetesAccess &&
                        record.Category == category);
                    if (found is not null)
                    {
                        return found;
                    }
                }

                await Task.Delay(10);
            }

            throw new TimeoutException($"Audit category {category} was not delivered.");
        }
    }
}
