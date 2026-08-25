using System.Net;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace KubeMcp.Tests;

public sealed class ReadinessTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-six-test-api-key-32-bytes-minimum";
    private const string SensitiveDetail = "/sensitive/kubeconfig bearer=secret-token exception=upstream-body";

    [Theory]
    [InlineData("/healthz", "Healthy")]
    [InlineData("/readyz", "Ready")]
    public async Task ProcessEndpointIsFixedSmallOpaqueAndUnauthenticated(
        string path,
        string expectedBody)
    {
        var kubernetesFactory = new ThrowingKubernetesClientFactory();
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "ApiKey");
            builder.UseSetting("KubeMcp:Authentication:ApiKey", ApiKey);
            builder.UseSetting("KubeMcp:KubeConfigPath", SensitiveDetail);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IKubernetesClientFactory>();
                services.AddSingleton<IKubernetesClientFactory>(kubernetesFactory);
            });
        });
        using var client = factory.CreateClient();

        // No Authorization header is supplied even though production MCP access
        // requires one.
        using var response = await client.GetAsync(path);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/plain", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(expectedBody, body);
        Assert.True(body.Length <= 16);
        Assert.DoesNotContain(SensitiveDetail, body, StringComparison.Ordinal);
        Assert.Equal(0, kubernetesFactory.CreateCalls);
    }

    private sealed class ThrowingKubernetesClientFactory : IKubernetesClientFactory
    {
        public int CreateCalls { get; private set; }

        public IKubernetesApi Create()
        {
            CreateCalls++;
            throw new InvalidOperationException(SensitiveDetail);
        }
    }
}
