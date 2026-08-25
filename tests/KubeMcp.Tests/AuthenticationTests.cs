using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Client;

namespace KubeMcp.Tests;

public sealed class AuthenticationTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-one-test-api-key-32-bytes-minimum";

    [Fact]
    public async Task ApiKeyModeRejectsInvalidCredentialsAndExposesOneToolForCorrectKey()
    {
        await using var factory = CreateFactory(new Dictionary<string, string?>
        {
            ["KubeMcp:Authentication:Mode"] = "ApiKey",
            ["KubeMcp:Authentication:ApiKey"] = ApiKey
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
        await AssertSingleToolAsync(client);
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

    private static async Task AssertSingleToolAsync(HttpClient client)
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

        Assert.Equal("k8s_get", Assert.Single(await mcpClient.ListToolsAsync()).Name);
    }

    private static async Task<HttpStatusCode> PostMcpAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/mcp", JsonContent.Create(new { }));
        return response.StatusCode;
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
