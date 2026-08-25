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
    public void ReferenceDeploymentIsAuthenticatedAndNoneIsDevelopmentOnly()
    {
        var production = File.ReadAllText(RepositoryFile("deployment.yaml"));
        var development = File.ReadAllText(RepositoryFile("deployment-development.yaml"));

        Assert.Matches(
            new Regex(
                @"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: ApiKey$"),
            production);
        Assert.Matches(
            new Regex(
                @"(?s)- name: KubeMcp__Authentication__ApiKey\s+valueFrom:\s+secretKeyRef:\s+name: kube-mcp-api-key\s+key: api-key"),
            production);
        Assert.DoesNotMatch(
            new Regex(
                @"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: None$"),
            production);
        Assert.Matches(
            new Regex(
                @"(?m)- name: KubeMcp__Authentication__Mode\s*\r?\n\s*value: None$"),
            development);
        Assert.DoesNotContain("AllowUnauthenticated", development, StringComparison.Ordinal);
    }

    [Fact]
    public void ReadinessProbeTimeoutExceedsInternalDeadline()
    {
        foreach (var manifestName in new[] { "deployment.yaml", "deployment-development.yaml" })
        {
            var manifest = File.ReadAllText(RepositoryFile(manifestName));
            var readiness = Regex.Match(
                manifest,
                @"(?s)readinessProbe:.*?timeoutSeconds:\s*(\d+).*?livenessProbe:");

            Assert.True(readiness.Success, $"{manifestName} readinessProbe must set timeoutSeconds.");
            Assert.True(
                int.Parse(readiness.Groups[1].Value) > 2,
                $"{manifestName} readinessProbe timeout must exceed the internal 2s deadline.");
        }
    }

    [Fact]
    public void ReferenceDeploymentDelegatesTrafficLimitsButRetainsPodResources()
    {
        var production = File.ReadAllText(RepositoryFile("deployment.yaml"));
        var settings = File.ReadAllText(RepositoryFile("src/KubeMcp/appsettings.json"));

        Assert.DoesNotContain("KubeMcp__McpAdmission", production, StringComparison.Ordinal);
        Assert.DoesNotContain("KubeMcp__McpConcurrency", production, StringComparison.Ordinal);
        Assert.DoesNotContain("ForwardedHeaders", production, StringComparison.Ordinal);
        Assert.DoesNotContain("ForwardedHeaders", settings, StringComparison.Ordinal);
        Assert.Matches(@"(?s)resources:\s+requests:\s+cpu:\s*25m\s+memory:\s*64Mi\s+limits:\s+cpu:\s*250m\s+memory:\s*256Mi", production);
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

        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "incorrect-api-key-that-is-long-enough");
        Assert.Equal(HttpStatusCode.Unauthorized, await PostMcpAsync(client));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ApiKey);
        await AssertSingleToolAsync(client);
    }

    private static async Task<HttpStatusCode> PostMcpAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/mcp", JsonContent.Create(new { }));
        return response.StatusCode;
    }

    private static async Task AssertSingleToolAsync(HttpClient client)
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

        Assert.Equal("k8s_get", Assert.Single(await mcpClient.ListToolsAsync()).Name);
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
