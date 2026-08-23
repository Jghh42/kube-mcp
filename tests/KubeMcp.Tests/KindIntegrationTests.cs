using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KubeMcp.Tests;

public sealed class KindIntegrationTests
{
    private const string Namespace = "kube-mcp-e2e";
    private const string SecretValue = "correct-horse-battery-staple";

    [Fact]
    [Trait("Category", "Integration")]
    public async Task McpReadsRealKindResourcesAndSanitizesSecrets()
    {
        var endpoint = Environment.GetEnvironmentVariable("KUBE_MCP_INTEGRATION_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return;
        }

        await using var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(endpoint),
            Name = "kube-mcp-kind-integration"
        });
        await using var client = await McpClient.CreateAsync(transport);

        var tools = await client.ListToolsAsync();
        Assert.Equal("k8s_get", Assert.Single(tools).Name);

        var configMapList = await CallAsync(client, "configmaps");
        Assert.NotEqual(true, configMapList.IsError);
        using (var json = ParseText(configMapList))
        {
            var items = json.RootElement.GetProperty("items");
            var item = Assert.Single(items.EnumerateArray(), item =>
                item.GetProperty("metadata").GetProperty("name").GetString() == "stage-two");
            Assert.Equal("v1", item.GetProperty("apiVersion").GetString());
            Assert.Equal("ConfigMap", item.GetProperty("kind").GetString());
        }

        var configMapGet = await CallAsync(client, "configmaps", "stage-two");
        Assert.NotEqual(true, configMapGet.IsError);
        using (var json = ParseText(configMapGet))
        {
            Assert.Equal(
                "integration",
                json.RootElement.GetProperty("data").GetProperty("test").GetString());
        }

        var secretList = await CallAsync(client, "secrets");
        Assert.NotEqual(true, secretList.IsError);
        var secretListText = Text(secretList);
        Assert.Contains("integration-secret", secretListText);
        Assert.Contains("password", secretListText);
        Assert.DoesNotContain(SecretValue, secretListText);
        Assert.DoesNotContain("hmac-sha256:", secretListText);

        var secretGet = await CallAsync(client, "secrets", "integration-secret");
        Assert.NotEqual(true, secretGet.IsError);
        var secretText = Text(secretGet);
        Assert.DoesNotContain(SecretValue, secretText);
        Assert.DoesNotContain(Convert.ToBase64String("correct-horse-battery-staple"u8), secretText);
        Assert.DoesNotContain("annotation-must-not-leak", secretText);
        Assert.DoesNotContain("annotations", secretText);
        using (var json = JsonDocument.Parse(secretText))
        {
            var data = json.RootElement.GetProperty("data");
            var password = data.GetProperty("password").GetString();
            Assert.StartsWith("hmac-sha256:", password);
            Assert.Equal(password, data.GetProperty("duplicate").GetString());
            Assert.NotEqual(password, data.GetProperty("username").GetString());
        }

        var unknownResource = await CallAsync(client, "definitely-not-a-resource");
        Assert.True(unknownResource.IsError);
        Assert.Contains("not found in Kubernetes API discovery", Text(unknownResource));

        var invalidNamespace = await client.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "configmaps",
                ["namespace"] = "../default"
            },
            cancellationToken: CancellationToken.None);
        Assert.True(invalidNamespace.IsError);
        Assert.Contains("valid lowercase Kubernetes DNS label", Text(invalidNamespace));
    }

    private static ValueTask<CallToolResult> CallAsync(
        McpClient client,
        string resource,
        string? name = null)
    {
        var arguments = new Dictionary<string, object?>
        {
            ["resource"] = resource,
            ["namespace"] = Namespace
        };
        if (name is not null)
        {
            arguments["name"] = name;
        }

        return client.CallToolAsync("k8s_get", arguments, cancellationToken: CancellationToken.None);
    }

    private static JsonDocument ParseText(CallToolResult result) => JsonDocument.Parse(Text(result));

    private static string Text(CallToolResult result) =>
        Assert.Single(result.Content.OfType<TextContentBlock>()).Text;
}
