using System.Net;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace KubeMcp.Tests;

public sealed class ReadinessTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    [Fact]
    public async Task ReadinessIsHealthyWhenKubernetesGetAndListAreAuthorized()
    {
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = (_, _, _, _) => Task.FromResult(true)
        };
        await using var factory = CreateFactory(api);
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/readyz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync());
        Assert.Equal(
            [
                $"AUTH get pods namespace=<cluster> maxBody={KubernetesReadinessHealthCheck.MaximumAuthorizationResponseBytes}",
                $"AUTH list pods namespace=<cluster> maxBody={KubernetesReadinessHealthCheck.MaximumAuthorizationResponseBytes}"
            ],
            api.Calls);
    }

    [Fact]
    public async Task ConfiguredReadinessNamespaceScopesNamespacedAccessReviews()
    {
        var api = new FakeKubernetesApi();
        await using var factory = CreateFactory(api, new Dictionary<string, string?>
        {
            ["KubeMcp:ReadinessNamespace"] = "production"
        });
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/readyz");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.All(api.Calls, call => Assert.Contains("namespace=production", call));
    }

    [Fact]
    public async Task AuthorizationFailureMakesOnlyReadinessUnhealthy()
    {
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = (_, verb, _, _) => verb == "get"
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
            ResourceAccessHandler = (_, _, _, _) => Task.FromException<bool>(
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
            ResourceAccessHandler = async (_, _, _, cancellationToken) =>
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

    [Fact]
    public async Task ConcurrentPublicReadinessRequestsShareOneKubernetesProbe()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = async (_, verb, _, cancellationToken) =>
            {
                if (verb == "get")
                {
                    entered.TrySetResult();
                    await release.Task.WaitAsync(cancellationToken);
                }

                return true;
            }
        };
        await using var factory = CreateFactory(api);
        using var client = factory.CreateClient();

        var requests = Enumerable.Range(0, 12)
            .Select(_ => client.GetAsync("/readyz"))
            .ToArray();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Single(api.Calls);
        release.TrySetResult();

        var responses = await Task.WhenAll(requests);
        try
        {
            Assert.All(responses, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
            Assert.Equal(2, api.Calls.Count);
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }
    }

    [Fact]
    public async Task OpaqueReadinessResultIsShortCachedThenRefreshed()
    {
        var api = new FakeKubernetesApi();
        var time = new FakeTimeProvider(DateTimeOffset.UnixEpoch);
        var options = ReaderTestOptions.Options();
        var check = new KubernetesReadinessHealthCheck(
            new SimpleFactory(api),
            Options.Create(options),
            time);
        var context = new HealthCheckContext();

        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(context)).Status);
        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(context)).Status);
        Assert.Equal(2, api.Calls.Count);

        time.Advance(KubernetesReadinessHealthCheck.CacheDuration + TimeSpan.FromTicks(1));
        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(context)).Status);
        Assert.Equal(4, api.Calls.Count);
    }

    [Fact]
    public async Task LabelSelectorReadinessAlsoRequiresClusterScopedNamespaceList()
    {
        var api = new FakeKubernetesApi
        {
            ResourceAccessHandler = (descriptor, verb, _, _) =>
                Task.FromResult(descriptor.Resource != "namespaces" || verb != "list")
        };
        await using var factory = CreateFactory(api, new Dictionary<string, string?>
        {
            ["KubeMcp:NamespacePolicy:Mode"] = "LabelSelector",
            ["KubeMcp:NamespacePolicy:LabelSelector"] = "environment=production"
        });
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/readyz");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("Unhealthy", await response.Content.ReadAsStringAsync());
        Assert.Equal(
            $"AUTH list namespaces namespace=<cluster> maxBody={KubernetesReadinessHealthCheck.MaximumAuthorizationResponseBytes}",
            Assert.Single(api.Calls));
    }

    private static WebApplicationFactory<Program> CreateFactory(
        FakeKubernetesApi api,
        IReadOnlyDictionary<string, string?>? settings = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            foreach (var setting in settings ?? new Dictionary<string, string?>())
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IKubernetesClientFactory>();
                services.AddSingleton<IKubernetesClientFactory>(new SimpleFactory(api));
            });
        });
}
