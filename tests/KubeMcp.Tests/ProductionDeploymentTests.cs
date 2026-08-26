using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Client;

namespace KubeMcp.Tests;

public sealed class ProductionDeploymentTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-one-test-api-key-32-bytes-minimum";

    [Fact]
    public void ProductionManifestSourcesApiAndHmacKeysFromSecrets()
    {
        var production = File.ReadAllText(RepositoryFile("deployment.yaml"));

        Assert.Matches(
            @"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: ApiKey$",
            production);
        AssertSecretReference(
            production,
            "KubeMcp__Authentication__ApiKey",
            "kube-mcp-api-key",
            "api-key");
        AssertSecretReference(production, "KubeMcp__SecretHmacKey", "kube-mcp-hmac", "key");
        Assert.DoesNotMatch(
            @"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: None$",
            production);
        Assert.DoesNotMatch(
            @"(?s)- name: KubeMcp__(?:Authentication__ApiKey|SecretHmacKey)\s+value:",
            production);
    }

    [Fact]
    public async Task DevelopmentOverlayChangesOnlyDevelopmentRuntimeSettings()
    {
        var kustomization = File.ReadAllText(
            RepositoryFile("overlays/development/kustomization.yaml"));
        var patch = File.ReadAllText(
            RepositoryFile("overlays/development/deployment-patch.yaml"));

        Assert.Contains("../../deployment.yaml", kustomization, StringComparison.Ordinal);
        Assert.Contains("path: deployment-patch.yaml", kustomization, StringComparison.Ordinal);
        Assert.Matches(
            @"(?m)- name: DOTNET_ENVIRONMENT\s*\r?\n\s*value: Development$",
            patch);
        Assert.Matches(
            @"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: None$",
            patch);
        Assert.Matches(
            @"(?m)- name: KubeMcp__Authentication__ApiKey\s*\r?\n\s*\$patch: delete$",
            patch);
        Assert.Contains("imagePullPolicy: IfNotPresent", patch, StringComparison.Ordinal);
        Assert.DoesNotContain("SecretHmacKey", patch, StringComparison.Ordinal);
        Assert.DoesNotContain("readinessProbe", patch, StringComparison.Ordinal);
        Assert.DoesNotContain("livenessProbe", patch, StringComparison.Ordinal);
        Assert.DoesNotContain("securityContext", patch, StringComparison.Ordinal);
        Assert.DoesNotContain("resources:", patch, StringComparison.Ordinal);
        Assert.False(File.Exists(RepositoryFile("deployment-development.yaml")));

        var rendered = await RenderKustomizationAsync("overlays/development");

        Assert.Equal(6, Regex.Matches(rendered, @"(?m)^kind: ").Count);
        foreach (var kind in new[]
                 {
                     "Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding",
                     "Deployment", "Service"
                 })
        {
            Assert.Matches($@"(?m)^kind: {kind}$", rendered);
        }
        Assert.Matches(@"(?m)- name: DOTNET_ENVIRONMENT\s*\r?\n\s*value: Development$", rendered);
        Assert.Matches(@"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: None$", rendered);
        Assert.DoesNotContain("KubeMcp__Authentication__ApiKey", rendered, StringComparison.Ordinal);
        AssertSecretReference(rendered, "KubeMcp__SecretHmacKey", "kube-mcp-hmac", "key");
        Assert.Contains("imagePullPolicy: IfNotPresent", rendered, StringComparison.Ordinal);
        Assert.Contains("path: /readyz", rendered, StringComparison.Ordinal);
        Assert.Contains("path: /healthz", rendered, StringComparison.Ordinal);
        Assert.Contains("runAsNonRoot: true", rendered, StringComparison.Ordinal);
        Assert.Contains("readOnlyRootFilesystem: true", rendered, StringComparison.Ordinal);
        Assert.Contains("cpu: 25m", rendered, StringComparison.Ordinal);
        Assert.Contains("memory: 256Mi", rendered, StringComparison.Ordinal);
        Assert.Matches(@"(?ms)^kind: Service\s+metadata:.*?^spec:.*?^\s*type: ClusterIP$", rendered);
        Assert.Matches(@"(?s)resources:\s*\r?\n\s*- namespaces\s+verbs:\s*\r?\n\s*- list", rendered);
    }

    [Fact]
    public void ReferenceDeploymentRetainsIntentionalOperationalHardening()
    {
        var production = File.ReadAllText(RepositoryFile("deployment.yaml"));

        Assert.Matches(
            @"(?s)readinessProbe:\s+httpGet:\s+path: /readyz.*?timeoutSeconds:\s*1",
            production);
        Assert.Matches(@"(?s)livenessProbe:\s+httpGet:\s+path: /healthz", production);
        Assert.Matches(
            @"(?s)resources:\s+requests:\s+cpu:\s*25m\s+memory:\s*64Mi\s+limits:\s+cpu:\s*250m\s+memory:\s*256Mi",
            production);
        Assert.Contains("runAsNonRoot: true", production, StringComparison.Ordinal);
        Assert.Contains("type: RuntimeDefault", production, StringComparison.Ordinal);
        Assert.Contains("allowPrivilegeEscalation: false", production, StringComparison.Ordinal);
        Assert.Contains("readOnlyRootFilesystem: true", production, StringComparison.Ordinal);
        Assert.Matches(@"(?s)capabilities:\s+drop:\s+- ALL", production);
        Assert.Matches(@"(?s)kind: Service\s+metadata:.*?spec:\s+type: ClusterIP", production);
    }

    [Fact]
    public void DefaultResourceMappingsMatchNarrowRbac()
    {
        using var settings = JsonDocument.Parse(File.ReadAllText(
            RepositoryFile("src/KubeMcp/appsettings.json")));
        var expected = settings.RootElement
            .GetProperty("KubeMcp")
            .GetProperty("AllowedResources")
            .EnumerateObject()
            .Select(entry => (
                Group: entry.Value.GetProperty("Group").GetString()!,
                Resource: entry.Value.GetProperty("Resource").GetString()!))
            .OrderBy(item => item.Group, StringComparer.Ordinal)
            .ThenBy(item => item.Resource, StringComparer.Ordinal)
            .ToArray();

        var production = File.ReadAllText(RepositoryFile("deployment.yaml"));
        var actual = new List<(string Group, string Resource)>();
        foreach (Match rule in Regex.Matches(
                     production,
                     @"(?ms)^\s*- apiGroups:\s*\[(?<groups>[^\]]*)\]\s+resources:\s*(?<resources>.*?)(?=^\s+verbs:)^\s+verbs:\s*\[(?<verbs>[^\]]*)\]"))
        {
            var groups = Regex.Matches(rule.Groups["groups"].Value, "\"(?<value>[^\"]*)\"")
                .Select(match => match.Groups["value"].Value)
                .ToArray();
            var resources = Regex.Matches(rule.Groups["resources"].Value, "[a-z][a-z0-9-]*")
                .Select(match => match.Value)
                .ToArray();
            var verbs = Regex.Matches(rule.Groups["verbs"].Value, "\"(?<value>[^\"]*)\"")
                .Select(match => match.Groups["value"].Value)
                .Order(StringComparer.Ordinal)
                .ToArray();

            if (resources.Contains("namespaces", StringComparer.Ordinal))
            {
                Assert.Equal(["list"], verbs);
                continue;
            }

            Assert.Equal(["get", "list"], verbs);
            foreach (var group in groups)
            foreach (var resource in resources)
            {
                actual.Add((group, resource));
            }
        }

        Assert.Equal(expected, actual
            .OrderBy(item => item.Group, StringComparer.Ordinal)
            .ThenBy(item => item.Resource, StringComparer.Ordinal));
    }

    [Fact]
    public void DefaultDeploymentExcludesOptionalCrdRbac()
    {
        var production = File.ReadAllText(RepositoryFile("deployment.yaml"));
        var cnpgOverlay = File.ReadAllText(RepositoryFile("overlays/cnpg/rbac.yaml"));
        var traefikOverlay = File.ReadAllText(RepositoryFile("overlays/traefik/rbac.yaml"));

        Assert.DoesNotContain("postgresql.cnpg.io", production, StringComparison.Ordinal);
        Assert.DoesNotContain("traefik.io", production, StringComparison.Ordinal);
        Assert.Contains("postgresql.cnpg.io", cnpgOverlay, StringComparison.Ordinal);
        Assert.Contains("traefik.io", traefikOverlay, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("cnpg")]
    [InlineData("traefik")]
    public void CrdOverlayMappingsMatchRbacResources(string overlay)
    {
        using var mappings = JsonDocument.Parse(File.ReadAllText(
            RepositoryFile($"overlays/{overlay}/resources.json")));
        var mappedValues = mappings.RootElement
            .GetProperty("KubeMcp")
            .GetProperty("AllowedResources")
            .EnumerateObject()
            .Select(entry => entry.Value)
            .ToArray();
        var mappedGroups = mappedValues
            .Select(value => value.GetProperty("Group").GetString()!)
            .ToHashSet(StringComparer.Ordinal);
        var mappedResources = mappedValues
            .Select(value => value.GetProperty("Resource").GetString()!)
            .ToHashSet(StringComparer.Ordinal);
        var rbac = File.ReadAllText(RepositoryFile($"overlays/{overlay}/rbac.yaml"));
        var groupRule = Regex.Match(rbac, @"apiGroups:\s*\[\s*""(?<group>[^""]+)""\s*\]");
        var resourcesBlock = Regex.Match(
            rbac,
            @"(?ms)^\s*resources:\s*(?<resources>\[[^\r\n]*\]|.*?)(?=^\s*verbs:)");
        var verbsRule = Regex.Match(rbac, @"verbs:\s*\[(?<verbs>[^\]]+)\]");
        var rbacResources = Regex.Matches(resourcesBlock.Groups["resources"].Value, @"[a-z][a-z0-9-]*")
            .Select(match => match.Value)
            .ToHashSet(StringComparer.Ordinal);
        var rbacVerbs = Regex.Matches(verbsRule.Groups["verbs"].Value, @"[a-z]+")
            .Select(match => match.Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(groupRule.Success, $"{overlay} RBAC must contain one explicit API group.");
        Assert.True(resourcesBlock.Success, $"{overlay} RBAC must contain a resources rule.");
        Assert.True(verbsRule.Success, $"{overlay} RBAC must contain a verbs rule.");
        Assert.Equal(mappedGroups.Order(), new[] { groupRule.Groups["group"].Value });
        Assert.Equal(mappedResources.Order(), rbacResources.Order());
        Assert.Equal(new[] { "get", "list" }, rbacVerbs.Order());
    }

    [Fact]
    public void NoWildcardResourceModeOrRbacManifestRemains()
    {
        Assert.False(File.Exists(RepositoryFile("deployment-allow-all-rbac.yaml")));
        Assert.DoesNotContain(
            "ResourcePolicy",
            File.ReadAllText(RepositoryFile("src/KubeMcp/appsettings.json")),
            StringComparison.Ordinal);

        foreach (var manifest in Directory.EnumerateFiles(
                     Path.GetDirectoryName(RepositoryFile("deployment.yaml"))!,
                     "*.yaml",
                     SearchOption.AllDirectories))
        {
            var yaml = File.ReadAllText(manifest);
            Assert.DoesNotMatch("""(?m)^\s*(apiGroups|resources):[^\r\n]*["']?\*["']?""", yaml);
            Assert.DoesNotMatch("""(?m)^\s*(apiGroups|resources):\s*\r?\n\s*-\s*["']?\*["']?""", yaml);
        }
    }

    [Fact]
    public void ProductionDefaultsFailClosedWithoutAnApiKey()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Production);
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
        });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        AssertExceptionMessageContains(exception, "ApiKey must contain at least 32 bytes");
    }

    [Fact]
    public void ProductionRejectsUnauthenticatedModeAtStartup()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Production);
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "None");
        });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        AssertExceptionMessageContains(
            exception,
            "not permitted outside the Development environment");
    }

    [Fact]
    public void NullAllowedResourceGroupIsRejectedAtStartup()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Development);
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddJsonStream(new MemoryStream(
                    """
                    {
                      "KubeMcp": {
                        "AllowedResources": {
                          "pods": { "Group": null }
                        }
                      }
                    }
                    """u8.ToArray())));
        });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        AssertExceptionMessageContains(exception, "Group must not be null");
    }

    [Fact]
    public async Task DevelopmentAllowsNoneModeWithoutOptIn()
    {
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Development);
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            // appsettings.Development.json explicitly selects Mode=None.
        });
        using var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/healthz")).StatusCode);
    }

    [Fact]
    public async Task ProductionApiKeyManifestReturnsUnauthorizedWithoutCredentials()
    {
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Production);
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "ApiKey");
            builder.UseSetting("KubeMcp:Authentication:ApiKey", ApiKey);
        });
        using var client = factory.CreateClient();

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            await PostMcpMethodAsync(client, "tools/list", new { }));

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "incorrect-api-key-that-is-long-enough");
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            await PostMcpMethodAsync(
                client,
                "tools/call",
                new { name = "k8s_list_namespaces", arguments = new { } }));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ApiKey);
        await AssertTwoToolsAsync(client);
    }

    private static async Task<HttpStatusCode> PostMcpAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/mcp", JsonContent.Create(new { }));
        return response.StatusCode;
    }

    private static async Task<HttpStatusCode> PostMcpMethodAsync(
        HttpClient client,
        string method,
        object parameters)
    {
        using var response = await client.PostAsync(
            "/mcp",
            JsonContent.Create(new
            {
                jsonrpc = "2.0",
                id = 1,
                method,
                @params = parameters
            }));
        return response.StatusCode;
    }

    private static async Task AssertTwoToolsAsync(HttpClient client)
    {
        await using var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(client.BaseAddress!, "/mcp"),
                Name = "production-deployment-test"
            },
            client,
            loggerFactory: null,
            ownsHttpClient: false);
        await using var mcpClient = await McpClient.CreateAsync(transport);

        Assert.Equal(
            ["k8s_get", "k8s_list_namespaces"],
            (await mcpClient.ListToolsAsync()).Select(tool => tool.Name).Order().ToArray());
    }

    private static void AssertSecretReference(
        string manifest,
        string environmentVariable,
        string secretName,
        string secretKey)
    {
        Assert.Matches(
            $@"(?s)- name: {Regex.Escape(environmentVariable)}\s+valueFrom:\s+secretKeyRef:\s+(?:name: {Regex.Escape(secretName)}\s+key: {Regex.Escape(secretKey)}|key: {Regex.Escape(secretKey)}\s+name: {Regex.Escape(secretName)})",
            manifest);
    }

    private static async Task<string> RenderKustomizationAsync(string relativePath)
    {
        var startInfo = new ProcessStartInfo("kubectl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add("kustomize");
        startInfo.ArgumentList.Add("--load-restrictor");
        startInfo.ArgumentList.Add("LoadRestrictionsNone");
        startInfo.ArgumentList.Add(RepositoryFile(relativePath));

        Process? process;
        try
        {
            process = Process.Start(startInfo);
        }
        catch (Win32Exception exception)
        {
            throw new InvalidOperationException(
                "kubectl must be installed before running this test.", exception);
        }

        using (process)
        {
            Assert.NotNull(process);
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            var output = await outputTask;
            var error = await errorTask;
            Assert.True(process.ExitCode == 0, $"kubectl kustomize failed: {error}");
            return output;
        }
    }

    private static string RepositoryFile(string relativePath)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "KubeMcp.slnx")))
            {
                return Path.Combine(directory.FullName, relativePath);
            }
        }

        throw new DirectoryNotFoundException("Could not locate the repository root.");
    }

    private static void AssertExceptionMessageContains(Exception? exception, string expected)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current.Message.Contains(expected, StringComparison.Ordinal))
            {
                return;
            }
        }

        Assert.Fail($"Expected an exception whose message contains \"{expected}\". Actual: {exception}");
    }
}
