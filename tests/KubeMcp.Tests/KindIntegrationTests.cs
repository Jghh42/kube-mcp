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

        var apiKey = Environment.GetEnvironmentVariable("KUBE_MCP_INTEGRATION_API_KEY");
        Assert.False(string.IsNullOrWhiteSpace(apiKey));
        await AssertApiKeyDenialsAsync(endpoint);

        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

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
        var configMapListText = Text(configMapList);
        Assert.False(configMapList.IsError == true, configMapListText);
        Assert.DoesNotContain("integration", configMapListText);
        Assert.DoesNotContain("\"data\"", configMapListText);
        using (var json = JsonDocument.Parse(configMapListText))
        {
            var root = json.RootElement;
            var items = root.GetProperty("items");
            var item = Assert.Single(items.EnumerateArray(), item =>
                item.GetProperty("name").GetString() == "stage-two");
            AssertGenericListItem(item, "stage-two", Namespace, "ConfigMap");
            Assert.Equal(items.GetArrayLength(), root.GetProperty("count").GetInt32());
            Assert.False(root.GetProperty("limited").GetBoolean());
        }

        var podList = await CallAsync(client, "pods", @namespace: "kube-mcp");
        Assert.NotEqual(true, podList.IsError);
        var podListText = Text(podList);
        Assert.DoesNotContain("\"spec\"", podListText);
        Assert.DoesNotContain("\"status\"", podListText);
        Assert.DoesNotContain("containerStatuses", podListText);
        Assert.DoesNotContain("managedFields", podListText);
        Assert.DoesNotContain("annotations", podListText);
        using (var json = JsonDocument.Parse(podListText))
        {
            var item = Assert.Single(
                json.RootElement.GetProperty("items").EnumerateArray(),
                item => item.GetProperty("name").GetString()!.StartsWith("kube-mcp-", StringComparison.Ordinal));
            AssertGenericListItem(item, item.GetProperty("name").GetString()!, "kube-mcp", "Pod");
        }

        var deploymentList = await CallAsync(client, "deployments", @namespace: "kube-mcp");
        Assert.NotEqual(true, deploymentList.IsError);
        using (var json = ParseText(deploymentList))
        {
            var item = Assert.Single(
                json.RootElement.GetProperty("items").EnumerateArray(),
                item => item.GetProperty("name").GetString() == "kube-mcp");
            AssertGenericListItem(item, "kube-mcp", "kube-mcp", "Deployment");
        }

        var serviceList = await CallAsync(client, "services", @namespace: "kube-mcp");
        Assert.NotEqual(true, serviceList.IsError);
        using (var json = ParseText(serviceList))
        {
            var item = Assert.Single(
                json.RootElement.GetProperty("items").EnumerateArray(),
                item => item.GetProperty("name").GetString() == "kube-mcp");
            AssertGenericListItem(item, "kube-mcp", "kube-mcp", "Service");
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

        var unknownResource = await CallAsync(client, "definitely-not-a-resource");
        Assert.True(unknownResource.IsError);
        Assert.Contains("The Kubernetes resource is not allowed.", Text(unknownResource));

        // The harness explicitly maps Roles but deliberately does not grant them
        // in Kubernetes RBAC, proving that application policy cannot substitute
        // for the service account's independent authorization boundary.
        var rbacDenied = await CallAsync(client, "roles.rbac.authorization.k8s.io");
        Assert.True(rbacDenied.IsError);
        Assert.Contains("Access to the Kubernetes resource was denied.", Text(rbacDenied));

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

    private static async Task AssertApiKeyDenialsAsync(string endpoint)
    {
        using var unauthenticated = new HttpClient();
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(unauthenticated, endpoint));

        using var malformed = new HttpClient();
        Assert.True(malformed.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer"));
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(malformed, endpoint));

        using var incorrect = new HttpClient();
        incorrect.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            "incorrect-api-key-that-is-long-enough");
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(incorrect, endpoint));
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

    private static void AssertGenericListItem(
        JsonElement item,
        string name,
        string @namespace,
        string kind)
    {
        Assert.Equal(name, item.GetProperty("name").GetString());
        Assert.Equal(@namespace, item.GetProperty("namespace").GetString());
        Assert.Equal(kind, item.GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.String, item.GetProperty("age").ValueKind);
        Assert.Equal(
            ["age", "kind", "name", "namespace"],
            item.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
    }

    private static JsonDocument ParseText(CallToolResult result) => JsonDocument.Parse(Text(result));

    private static string Text(CallToolResult result) =>
        Assert.Single(result.Content.OfType<TextContentBlock>()).Text;
}
