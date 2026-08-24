using System.Net;
using System.Net.Http.Headers;
using KubeMcp.Audit;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;

namespace KubeMcp.Tests;

public sealed class ForwardedHeadersConfigurationTests
{
    internal const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    [Fact]
    public void ApplyTrustsConfiguredProxiesNetworksAndLoopbackOnly()
    {
        var config = new KubeMcpForwardedHeadersOptions
        {
            KnownProxies = ["10.0.0.5"],
            KnownNetworks = ["10.0.0.0/8", "2001:db8::/32"]
        };
        var options = new ForwardedHeadersOptions();

        ForwardedHeadersConfiguration.Apply(
            config,
            options,
            "k-mcp.example.internal;kube-mcp");

        Assert.Equal(
            ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
            options.ForwardedHeaders);
        Assert.Equal(1, options.ForwardLimit);
        Assert.Equal(["k-mcp.example.internal", "kube-mcp"], options.AllowedHosts);
        Assert.Equal([IPAddress.Parse("10.0.0.5")], options.KnownProxies);
        // Loopback (IPv4 + IPv6) plus the two configured networks, never a wildcard.
        Assert.Equal(4, options.KnownIPNetworks.Count);
        Assert.Contains(options.KnownIPNetworks, n => n.BaseAddress.Equals(IPAddress.Parse("127.0.0.0")));
        Assert.Contains(options.KnownIPNetworks, n => n.BaseAddress.Equals(IPAddress.Parse("::1")));
        Assert.Contains(options.KnownIPNetworks, n => n.BaseAddress.Equals(IPAddress.Parse("10.0.0.0")) && n.PrefixLength == 8);
        Assert.Contains(options.KnownIPNetworks, n => n.BaseAddress.Equals(IPAddress.Parse("2001:db8::")) && n.PrefixLength == 32);
    }

    [Fact]
    public async Task TrustedProxyAppliesForwardedClientIpHostAndScheme()
    {
        var (pipeline, capture) = BuildPipeline();
        var context = new DefaultHttpContext();
        // The immediate connection is a trusted (loopback) reverse proxy.
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("proxy-internal");
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.7";
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        context.Request.Headers["X-Forwarded-Host"] = "k-mcp.example.internal";

        await pipeline(context);

        Assert.Equal(IPAddress.Parse("198.51.100.7"), capture.RemoteIpAddress);
        Assert.Equal("https", capture.Scheme);
        Assert.Equal("k-mcp.example.internal", capture.Host);
    }

    [Fact]
    public async Task TrustedProxyDoesNotApplyUnallowedForwardedHost()
    {
        var (pipeline, capture) = BuildPipeline();
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("proxy-internal");
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.7";
        context.Request.Headers["X-Forwarded-Host"] = "evil.example.internal";

        await pipeline(context);

        Assert.Equal(IPAddress.Parse("198.51.100.7"), capture.RemoteIpAddress);
        Assert.Equal("proxy-internal", capture.Host);
    }

    [Fact]
    public async Task UntrustedProxyDoesNotApplyForwardedHeaders()
    {
        var (pipeline, capture) = BuildPipeline();
        var context = new DefaultHttpContext();
        // The immediate connection is NOT a trusted proxy, so forwarded headers
        // must be ignored to prevent spoofing by an arbitrary peer.
        context.Connection.RemoteIpAddress = IPAddress.Parse("8.8.8.8");
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("direct-host");
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.7";
        context.Request.Headers["X-Forwarded-Host"] = "evil.example.internal";

        await pipeline(context);

        Assert.Equal(IPAddress.Parse("8.8.8.8"), capture.RemoteIpAddress);
        Assert.Equal("http", capture.Scheme);
        Assert.Equal("direct-host", capture.Host);
    }

    private static (RequestDelegate pipeline, Capture capture) BuildPipeline()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider);
        var forwardedHeadersOptions = new ForwardedHeadersOptions();
        ForwardedHeadersConfiguration.Apply(
            new KubeMcpForwardedHeadersOptions(),
            forwardedHeadersOptions,
            "k-mcp.example.internal;proxy-internal;direct-host");
        app.UseForwardedHeaders(forwardedHeadersOptions);
        var capture = new Capture();
        app.Run(async context =>
        {
            capture.RemoteIpAddress = context.Connection.RemoteIpAddress;
            capture.Scheme = context.Request.Scheme;
            capture.Host = context.Request.Host.Value;
            await Task.CompletedTask;
        });
        return (app.Build(), capture);
    }

    private sealed class Capture
    {
        public IPAddress? RemoteIpAddress { get; set; }
        public string? Scheme { get; set; }
        public string? Host { get; set; }
    }
}

public sealed class AllowedHostsTests
{
    [Fact]
    public async Task AcceptsProductionHostAndRejectsUnknownHost()
    {
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", ForwardedHeadersConfigurationTests.TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "ApiKey");
            builder.UseSetting("KubeMcp:Authentication:ApiKey", "stage-five-test-api-key-32-bytes-minimum");
            builder.UseSetting("AllowedHosts", "k-mcp.example.internal");
        });
        using var client = factory.CreateClient();

        using var allowed = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        allowed.Headers.Host = "k-mcp.example.internal";
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(allowed)).StatusCode);

        using var rejected = new HttpRequestMessage(HttpMethod.Get, "/healthz");
        rejected.Headers.Host = "evil.example.com";
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(rejected)).StatusCode);
    }
}

public sealed class ReverseProxyAuditTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-five-test-api-key-32-bytes-minimum";

    [Fact]
    public async Task AuditRecordsForwardedClientIpBehindTrustedProxy()
    {
        var capturer = new CapturingLoggerProvider();
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "ApiKey");
            builder.UseSetting("KubeMcp:Authentication:ApiKey", ApiKey);
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<IStartupFilter, FakeTrustedProxyRemoteIpStartupFilter>();
                services.RemoveAll<IKubernetesReader>();
                services.AddSingleton<IKubernetesReader, StubKubernetesReader>();
            });
            builder.ConfigureLogging(loggingBuilder => loggingBuilder.AddProvider(capturer));
        });
        using var httpClient = factory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ApiKey);
        httpClient.DefaultRequestHeaders.Add("X-Forwarded-For", "198.51.100.7");

        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(httpClient.BaseAddress!, "/mcp"),
                Name = "reverse-proxy-audit-test"
            },
            httpClient,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);

        await mcpClient.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "pods",
                ["namespace"] = "default"
            },
            cancellationToken: CancellationToken.None);

        var entry = capturer.Entries.SingleOrDefault(e => e.EventId == AuditLogger.KubernetesAccessEvent);
        Assert.NotNull(entry);
        Assert.Equal("198.51.100.7", entry!.Properties["ClientIp"]);
    }

    private sealed class StubKubernetesReader : IKubernetesReader
    {
        public Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken) =>
            Task.FromResult(new KubernetesReadResult("{}", 1));
    }

    private sealed class FakeTrustedProxyRemoteIpStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.Use(async (context, nextMiddleware) =>
                {
                    // Simulate a trusted loopback reverse-proxy connection so the
                    // forwarded-headers middleware honors X-Forwarded-For.
                    context.Connection.RemoteIpAddress = IPAddress.Loopback;
                    await nextMiddleware();
                });
                next(app);
            };
    }
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    public List<CapturedEntry> Entries { get; } = [];

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var properties = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? pairs.Where(pair => pair.Key != "{OriginalFormat}")
                    .ToDictionary(pair => pair.Key, pair => pair.Value)
                : new Dictionary<string, object?>();
            owner.Entries.Add(new CapturedEntry(eventId, properties));
        }
    }

    public sealed record CapturedEntry(EventId EventId, IReadOnlyDictionary<string, object?> Properties);
}
