using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace KubeMcp.Tests;

public sealed class KindIntegrationTests
{
    private const string Namespace = "kube-mcp-e2e";
    private const string SecretValue = "correct-horse-battery-staple";

    [IntegrationTest]
    [Trait("Category", "Integration")]
    public async Task McpReadsRealKindResourcesAndSanitizesSecrets()
    {
        var endpoint = Environment.GetEnvironmentVariable(IntegrationTestAttribute.EndpointVariable);
        Assert.False(string.IsNullOrWhiteSpace(endpoint),
            $"{IntegrationTestAttribute.EndpointVariable} must be set when this test runs; " +
            "if you see this, the skip attribute was bypassed.");

        var accessToken = Environment.GetEnvironmentVariable("KUBE_MCP_INTEGRATION_ACCESS_TOKEN");
        using var httpClient = new HttpClient();
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            await AssertOAuthDenialsAsync(endpoint);
        }

        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(endpoint),
                Name = "kube-mcp-kind-integration"
            },
            httpClient,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var client = await McpClient.CreateAsync(transport);

        var tools = await client.ListToolsAsync();
        Assert.Equal("k8s_get", Assert.Single(tools).Name);

        var configMapList = await CallAsync(client, "configmaps");
        Assert.NotEqual(true, configMapList.IsError);
        var configMapListText = Text(configMapList);
        Assert.DoesNotContain("integration", configMapListText);
        Assert.DoesNotContain("\"data\"", configMapListText);
        using (var json = JsonDocument.Parse(configMapListText))
        {
            var root = json.RootElement;
            var items = root.GetProperty("items");
            var item = Assert.Single(items.EnumerateArray(), item =>
                item.GetProperty("name").GetString() == "stage-two");
            Assert.Equal("test", Assert.Single(item.GetProperty("keys").EnumerateArray()).GetString());
            Assert.Equal(1, item.GetProperty("keyCount").GetInt32());
            Assert.True(item.TryGetProperty("age", out _));
            Assert.Equal(items.GetArrayLength(), root.GetProperty("count").GetInt32());
            Assert.False(root.GetProperty("limited").GetBoolean());
        }

        var podList = await CallAsync(client, "pods", @namespace: "kube-mcp");
        Assert.NotEqual(true, podList.IsError);
        var podListText = Text(podList);
        Assert.DoesNotContain("\"spec\"", podListText);
        Assert.DoesNotContain("containerStatuses", podListText);
        Assert.DoesNotContain("managedFields", podListText);
        using (var json = JsonDocument.Parse(podListText))
        {
            var item = Assert.Single(
                json.RootElement.GetProperty("items").EnumerateArray(),
                item => item.GetProperty("name").GetString()!.StartsWith("kube-mcp-", StringComparison.Ordinal));
            Assert.Equal(JsonValueKind.String, item.GetProperty("ready").ValueKind);
            Assert.Equal(JsonValueKind.String, item.GetProperty("status").ValueKind);
            Assert.True(item.TryGetProperty("restarts", out _));
            Assert.True(item.TryGetProperty("ip", out _));
            Assert.True(item.TryGetProperty("node", out _));
        }

        var deploymentList = await CallAsync(client, "deployments", @namespace: "kube-mcp");
        Assert.NotEqual(true, deploymentList.IsError);
        var deploymentListText = Text(deploymentList);
        Assert.DoesNotContain("\"spec\"", deploymentListText);
        Assert.DoesNotContain("conditions", deploymentListText);
        using (var json = JsonDocument.Parse(deploymentListText))
        {
            var item = Assert.Single(
                json.RootElement.GetProperty("items").EnumerateArray(),
                item => item.GetProperty("name").GetString() == "kube-mcp");
            Assert.True(item.TryGetProperty("ready", out _));
            Assert.True(item.TryGetProperty("replicas", out _));
            Assert.True(item.TryGetProperty("available", out _));
            Assert.True(item.TryGetProperty("age", out _));
        }

        var serviceList = await CallAsync(client, "services", @namespace: "kube-mcp");
        Assert.NotEqual(true, serviceList.IsError);
        using (var json = ParseText(serviceList))
        {
            var item = Assert.Single(
                json.RootElement.GetProperty("items").EnumerateArray(),
                item => item.GetProperty("name").GetString() == "kube-mcp");
            Assert.Equal("ClusterIP", item.GetProperty("type").GetString());
            Assert.True(item.TryGetProperty("clusterIp", out _));
            Assert.Equal(JsonValueKind.Array, item.GetProperty("ports").ValueKind);
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
        Assert.DoesNotContain(
            Convert.ToBase64String(Encoding.UTF8.GetBytes(SecretValue)),
            secretListText);
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

        var resourcePolicyMode = Environment.GetEnvironmentVariable("KUBE_MCP_RESOURCE_POLICY_MODE");
        var unknownResource = await CallAsync(client, "definitely-not-a-resource");
        Assert.True(unknownResource.IsError);
        Assert.Contains(
            resourcePolicyMode == "AllowAll"
                ? "The Kubernetes resource was not found."
                : "The Kubernetes resource is not allowed.",
            Text(unknownResource));

        if (resourcePolicyMode == "AllowAll")
        {
            var discoveredResource = await CallAsync(
                client,
                "leases.coordination.k8s.io");
            Assert.NotEqual(true, discoveredResource.IsError);
            using var json = ParseText(discoveredResource);
            Assert.Equal("leases.coordination.k8s.io", json.RootElement.GetProperty("resource").GetString());
        }

        var policyMode = Environment.GetEnvironmentVariable("KUBE_MCP_NAMESPACE_POLICY_MODE");
        var deniedNamespace = await CallAsync(client, "pods", @namespace: "kube-system");
        Assert.True(deniedNamespace.IsError);
        Assert.Contains("The Kubernetes namespace is not allowed.", Text(deniedNamespace));

        if (policyMode == "LabelSelector")
        {
            var unlabelledNamespace = await CallAsync(client, "configmaps", @namespace: "default");
            Assert.True(unlabelledNamespace.IsError);
            Assert.Contains(
                "The Kubernetes namespace is not allowed.",
                Text(unlabelledNamespace));
        }

        var invalidNamespace = await client.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "configmaps",
                ["namespace"] = "../default"
            },
            cancellationToken: CancellationToken.None);
        Assert.True(invalidNamespace.IsError);
        Assert.Contains("The Kubernetes request is invalid.", Text(invalidNamespace));
    }

    private static async Task AssertOAuthDenialsAsync(string endpoint)
    {
        var wrongAudienceToken = Environment.GetEnvironmentVariable("KUBE_MCP_INTEGRATION_WRONG_AUDIENCE_TOKEN");
        var missingPermissionToken = Environment.GetEnvironmentVariable("KUBE_MCP_INTEGRATION_MISSING_PERMISSION_TOKEN");
        Assert.False(string.IsNullOrWhiteSpace(wrongAudienceToken));
        Assert.False(string.IsNullOrWhiteSpace(missingPermissionToken));

        using var unauthenticated = new HttpClient();
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(unauthenticated, endpoint));

        using var wrongAudience = new HttpClient();
        wrongAudience.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", wrongAudienceToken);
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(wrongAudience, endpoint));

        using var missingPermission = new HttpClient();
        missingPermission.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", missingPermissionToken);
        Assert.Equal(HttpStatusCode.Forbidden, await PostMcpAsync(missingPermission, endpoint));
    }

    private static async Task<HttpStatusCode> PostMcpAsync(HttpClient client, string endpoint)
    {
        using var response = await client.PostAsync(endpoint, JsonContent.Create(new { }));
        return response.StatusCode;
    }

    private static ValueTask<CallToolResult> CallAsync(
        McpClient client,
        string resource,
        string? name = null,
        string @namespace = Namespace)
    {
        var arguments = new Dictionary<string, object?>
        {
            ["resource"] = resource,
            ["namespace"] = @namespace
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
