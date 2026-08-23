using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
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

    private sealed record ServiceStatus(string Service, string Status);
}
