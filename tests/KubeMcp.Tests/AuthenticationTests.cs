using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KubeMcp.Tests;

public sealed class AuthenticationTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-one-test-api-key-32-bytes-minimum";

    [Fact]
    public async Task ApiKeyModeRejectsInvalidCredentialsAndInvokesNamespaceDiscoveryForCorrectKey()
    {
        var reader = new NamespaceInvocationReader();
        await using var factory = CreateFactory(new Dictionary<string, string?>
        {
            ["KubeMcp:Authentication:Mode"] = "ApiKey",
            ["KubeMcp:Authentication:ApiKey"] = ApiKey
        }, services =>
        {
            services.RemoveAll<IKubernetesReader>();
            services.AddSingleton<IKubernetesReader>(reader);
        });
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz")).StatusCode);
        using (var missing = await client.PostAsync("/mcp", JsonContent.Create(new { })))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, missing.StatusCode);
            Assert.Equal("Bearer", Assert.Single(missing.Headers.WwwAuthenticate).Scheme);
        }

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            "incorrect-api-key-that-is-long-enough");
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        client.DefaultRequestHeaders.Authorization = null;
        Assert.True(client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer"));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        client.DefaultRequestHeaders.Remove("Authorization");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ApiKey);
        await AssertToolsAndNamespaceInvocationAsync(client);
        Assert.Equal(1, reader.NamespaceCalls);
    }

    [Fact]
    public async Task ExplicitDevelopmentAnonymousModeInvokesNamespaceDiscovery()
    {
        var reader = new NamespaceInvocationReader();
        await using var factory = CreateFactory(
            new Dictionary<string, string?>
            {
                ["KubeMcp:Authentication:Mode"] = "None"
            },
            services =>
            {
                services.RemoveAll<IKubernetesReader>();
                services.AddSingleton<IKubernetesReader>(reader);
            });
        using var client = factory.CreateClient();

        await AssertToolsAndNamespaceInvocationAsync(client);

        Assert.Equal(1, reader.NamespaceCalls);
        Assert.Null(client.DefaultRequestHeaders.Authorization);
    }

    [Fact]
    public async Task ApiKeyNeverAppearsInAuthenticationErrorsOrLogs()
    {
        var logProvider = new CapturingLogProvider();
        await using var factory = CreateFactory(new Dictionary<string, string?>
        {
            ["KubeMcp:Authentication:Mode"] = "ApiKey",
            ["KubeMcp:Authentication:ApiKey"] = ApiKey
        }, services => services.AddSingleton<ILoggerProvider>(logProvider));
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ApiKey + "-wrong");

        using var response = await client.PostAsync("/mcp", JsonContent.Create(new { }));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(ApiKey, body, StringComparison.Ordinal);
        Assert.DoesNotContain(ApiKey, string.Join('\n', logProvider.Messages), StringComparison.Ordinal);
    }

    private static WebApplicationFactory<Program> CreateFactory(
        IReadOnlyDictionary<string, string?> settings,
        Action<IServiceCollection>? configureServices = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            foreach (var setting in settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            if (configureServices is not null)
            {
                builder.ConfigureServices(configureServices);
            }
        });

    private static async Task AssertToolsAndNamespaceInvocationAsync(HttpClient client)
    {
        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(client.BaseAddress!, "/mcp"),
                Name = "authentication-test"
            },
            client,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);

        Assert.Equal(
            ["k8s_get", "k8s_list_namespaces"],
            (await mcpClient.ListToolsAsync()).Select(tool => tool.Name).Order().ToArray());

        var result = await mcpClient.CallToolAsync(
            "k8s_list_namespaces",
            new Dictionary<string, object?>(),
            cancellationToken: CancellationToken.None);
        Assert.NotEqual(true, result.IsError);
        Assert.Equal(
            "{\"operation\":\"LIST\",\"resource\":\"namespaces\",\"items\":[],\"count\":0,\"limited\":false}",
            Assert.Single(result.Content.OfType<TextContentBlock>()).Text);
    }

    private static async Task<HttpStatusCode> PostMcpAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/mcp", JsonContent.Create(new { }));
        return response.StatusCode;
    }

    private sealed class NamespaceInvocationReader : IKubernetesReader
    {
        public int NamespaceCalls { get; private set; }

        public Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<KubernetesReadResult> ListNamespacesAsync(CancellationToken cancellationToken)
        {
            NamespaceCalls++;
            return Task.FromResult(new KubernetesReadResult(
                "{\"operation\":\"LIST\",\"resource\":\"namespaces\",\"items\":[],\"count\":0,\"limited\":false}",
                0));
        }
    }

    private sealed class CapturingLogProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(formatter(state, exception));
        }
    }
}
