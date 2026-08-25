using System.Net;
using System.Net.Http.Json;
using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
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

    [Fact]
    public async Task LivenessEndpointReportsHealthyWithoutForwardedHeaderConfiguration()
    {
        var response = await client.GetAsync("/healthz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AllowedHostsUsesDirectHostAndIgnoresForwardedHost()
    {
        await using var hostFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("AllowedHosts", "k-mcp.example.internal");
        });
        using var hostClient = hostFactory.CreateClient();

        using var allowed = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        allowed.Headers.Host = "k-mcp.example.internal";
        allowed.Headers.TryAddWithoutValidation("X-Forwarded-Host", "evil.example.com");
        Assert.Equal(HttpStatusCode.OK, (await hostClient.SendAsync(allowed)).StatusCode);

        using var rejected = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        rejected.Headers.Host = "evil.example.com";
        rejected.Headers.TryAddWithoutValidation("X-Forwarded-Host", "k-mcp.example.internal");
        Assert.Equal(HttpStatusCode.BadRequest, (await hostClient.SendAsync(rejected)).StatusCode);
    }

    [Fact]
    public void DefaultMappingsIncludeBuiltInResourcesOnly()
    {
        var allowlist = factory.Services.GetRequiredService<ResourceAllowlist>();

        Assert.Equal("pods", allowlist.Resolve("pods").QualifiedName);
        Assert.Equal(
            "deployments.apps",
            allowlist.Resolve("deployments").QualifiedName);
        Assert.Equal(
            "endpointslices.discovery.k8s.io",
            allowlist.Resolve("endpointslices").QualifiedName);
        // Optional CloudNativePG and Traefik CRDs are deliberately excluded from
        // the default mappings and shipped as overlays so the default surface
        // stays small and cannot drift from the default RBAC.
        Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("clusters.postgresql.cnpg.io"));
        Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("ingressroutes.traefik.io"));
        Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("namespaces"));
    }

    [Fact]
    public async Task McpEndpointExposesExactlyOneToolWithoutForwardedHeaderConfiguration()
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
    public void HealthAndMcpRoutesHaveExpectedTimeoutAndNoRateLimiterMetadata()
    {
        _ = client; // Ensure the application and endpoint data source are initialized.
        var timeoutOptions = factory.Services.GetRequiredService<IOptions<RequestTimeoutOptions>>().Value;
        Assert.Equal(
            TimeSpan.FromSeconds(30),
            timeoutOptions.Policies[McpRequestTimeoutOptionsSetup.PolicyName].Timeout);

        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints;

        // Inspect concrete routes without relying on display names. MCP retains
        // its overall deadline, while health routes remain independent.
        var routed = endpoints.OfType<RouteEndpoint>().ToArray();
        Assert.Contains(routed, endpoint =>
            endpoint.RoutePattern.RawText?.StartsWith("/mcp", StringComparison.Ordinal) == true &&
            endpoint.Metadata.GetMetadata<RequestTimeoutAttribute>()?.PolicyName == McpRequestTimeoutOptionsSetup.PolicyName);
        Assert.Contains(routed, endpoint => endpoint.RoutePattern.RawText == "/healthz");
        Assert.Contains(routed, endpoint => endpoint.RoutePattern.RawText == "/readyz");
        Assert.DoesNotContain(routed, endpoint =>
            endpoint.RoutePattern.RawText is "/" or "/healthz" or "/readyz" &&
            endpoint.Metadata.GetMetadata<RequestTimeoutAttribute>() is not null);
        Assert.All(routed, endpoint =>
            Assert.Null(endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>()));
    }

    [Fact]
    public async Task OverallDeadlineCancelsTheReaderAndIsAuditedAsServerTimeout()
    {
        var reader = new CancellationObservingReader();
        var auditLogs = new CapturingAuditLogProvider();
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
                services.AddSingleton<ILoggerProvider>(auditLogs);
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
        var audit = await auditLogs.WaitForCategoryAsync(AuditCategories.ServerTimeout);
        Assert.Equal("timeout", audit.Properties["Result"]);
    }

    [Fact]
    public async Task CallerCancellationPropagatesWithoutBecomingServerTimeout()
    {
        var reader = new CancellationObservingReader();
        var auditLogs = new CapturingAuditLogProvider();
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
                services.AddSingleton<ILoggerProvider>(auditLogs);
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
        using var callerCancellation = new CancellationTokenSource();

        // Wait until the request is executing so the test deterministically
        // exercises propagation of a caller cancellation rather than cancelling
        // before an asynchronously scheduled request reaches the server.
        var call = mcpClient.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "pods",
                ["namespace"] = "default"
            },
            cancellationToken: callerCancellation.Token).AsTask();
        await reader.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        callerCancellation.Cancel();

        // The MCP transport represents the aborted server response as HTTP 499;
        // the server-side audit category below is the cancellation source of truth.
        await Assert.ThrowsAnyAsync<Exception>(() => call);
        await reader.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var audit = await auditLogs.WaitForCategoryAsync(AuditCategories.ClientCancelled);
        Assert.Equal("cancelled", audit.Properties["Result"]);
        Assert.DoesNotContain(auditLogs.Snapshot(), entry =>
            Equals(entry.Properties.GetValueOrDefault("Category"), AuditCategories.ServerTimeout));
    }

    private sealed record ServiceStatus(string Service, string Status);

    private sealed class CancellationObservingReader : IKubernetesReader
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource CancellationObserved { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            using var registration = cancellationToken.Register(() => CancellationObserved.TrySetResult());
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

}
