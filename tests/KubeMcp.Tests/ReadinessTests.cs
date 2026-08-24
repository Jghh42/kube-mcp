using System.Net;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KubeMcp.Tests;

public sealed class ReadinessTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    [Fact]
    public async Task ReadinessIsHealthyWhenKubernetesGetAndListAreAuthorized()
    {
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = (_, _, _) => Task.FromResult(true)
        };
        await using var factory = CreateFactory(api);
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/readyz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
        Assert.Equal(
            [
                $"AUTH get pods maxBody={KubernetesReadinessHealthCheck.MaximumAuthorizationResponseBytes}",
                $"AUTH list pods maxBody={KubernetesReadinessHealthCheck.MaximumAuthorizationResponseBytes}"
            ],
            api.Calls);
    }

    [Fact]
    public async Task AuthorizationFailureMakesOnlyReadinessUnhealthy()
    {
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = (_, verb, _) => verb == "get"
                ? Task.FromResult(true)
                : Task.FromResult(false)
        };
        await using var factory = CreateFactory(api);
        using var client = factory.CreateClient();

        using var liveness = await client.GetAsync("/healthz");

        Assert.Equal(HttpStatusCode.OK, liveness.StatusCode);
        Assert.Equal("Healthy", await liveness.Content.ReadAsStringAsync());
        Assert.Empty(api.Calls);

        using var readiness = await client.GetAsync("/readyz");
        var body = await readiness.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, readiness.StatusCode);
        Assert.Equal("Unhealthy", body);
    }

    [Fact]
    public async Task DependencyExceptionDetailsAreNotExposed()
    {
        const string sensitiveFailure =
            "kubeconfig=/sensitive/config bearer=secret-token upstream-body={secret-data}";
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = (_, _, _) => Task.FromException<bool>(
                new KubernetesApiException(
                    KubernetesErrorCategory.AccessDenied,
                    sensitiveFailure,
                    (int)HttpStatusCode.Forbidden))
        };
        await using var factory = CreateFactory(api);
        using var client = factory.CreateClient();

        using var readiness = await client.GetAsync("/readyz");
        var body = await readiness.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, readiness.StatusCode);
        Assert.Equal("Unhealthy", body);
        Assert.DoesNotContain(sensitiveFailure, body, StringComparison.Ordinal);
        Assert.DoesNotContain("kubeconfig", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("upstream", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadinessDependencyCallHasItsOwnDeadline()
    {
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = async (_, _, cancellationToken) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return true;
            }
        };
        var check = new KubernetesReadinessHealthCheck(
            new SimpleFactory(api),
            TimeSpan.Zero);

        var result = await check.CheckHealthAsync(
            new HealthCheckContext(),
            CancellationToken.None);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Null(result.Description);
        Assert.Null(result.Exception);
    }

    private static WebApplicationFactory<Program> CreateFactory(FakeKubernetesApi api) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<IKubernetesClientFactory>();
                services.AddSingleton<IKubernetesClientFactory>(new SimpleFactory(api));
            });
        });
}
