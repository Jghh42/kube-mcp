using KubeMcp.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

/// <summary>
/// Verifies Kubernetes connectivity and representative namespaced GET/LIST
/// authorization without reading workload objects. Concurrent public readiness
/// calls share one opaque probe result, which is cached briefly to avoid turning
/// the endpoint into an unauthenticated Kubernetes API amplifier.
/// </summary>
internal sealed class KubernetesReadinessHealthCheck : IHealthCheck
{
    internal const string Name = "kubernetes-api";
    internal const string Tag = "ready";
    internal const int MaximumAuthorizationResponseBytes = 16 * 1024;
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);
    internal static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(1);

    private static readonly KubernetesResourceDescriptor PodDescriptor =
        new(string.Empty, "v1", "pods", "Pod");
    private static readonly KubernetesResourceDescriptor NamespaceDescriptor =
        new(string.Empty, "v1", "namespaces", "Namespace");

    private readonly object cacheLock = new();
    private readonly IKubernetesClientFactory clientFactory;
    private readonly KubernetesResourceDescriptor authorizationTarget;
    private readonly string? authorizationNamespace;
    private readonly bool verifyNamespaceListAuthorization;
    private readonly TimeSpan timeout;
    private readonly TimeProvider timeProvider;
    private HealthCheckResult? cachedResult;
    private long cacheTimestamp;
    private Task<HealthCheckResult>? inFlight;

    public KubernetesReadinessHealthCheck(
        IKubernetesClientFactory clientFactory,
        IOptions<KubeMcpOptions> options,
        TimeProvider timeProvider)
        : this(
            clientFactory,
            SelectAuthorizationTarget(options.Value),
            options.Value.ReadinessNamespace,
            options.Value.NamespacePolicy.Mode == NamespacePolicyMode.LabelSelector,
            Timeout,
            timeProvider)
    {
    }

    internal KubernetesReadinessHealthCheck(
        IKubernetesClientFactory clientFactory,
        TimeSpan timeout)
        : this(
            clientFactory,
            PodDescriptor,
            authorizationNamespace: null,
            verifyNamespaceListAuthorization: false,
            timeout,
            TimeProvider.System)
    {
    }

    private KubernetesReadinessHealthCheck(
        IKubernetesClientFactory clientFactory,
        KubernetesResourceDescriptor authorizationTarget,
        string? authorizationNamespace,
        bool verifyNamespaceListAuthorization,
        TimeSpan timeout,
        TimeProvider timeProvider)
    {
        this.clientFactory = clientFactory;
        this.authorizationTarget = authorizationTarget;
        this.authorizationNamespace = authorizationNamespace;
        this.verifyNamespaceListAuthorization = verifyNamespaceListAuthorization;
        this.timeout = timeout;
        this.timeProvider = timeProvider;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        Task<HealthCheckResult> probe;
        lock (cacheLock)
        {
            if (cachedResult is { } cached &&
                timeProvider.GetElapsedTime(cacheTimestamp) < CacheDuration)
            {
                return cached;
            }

            probe = inFlight ??= RefreshAsync();
        }

        try
        {
            // A disconnected readiness caller stops waiting but does not cancel
            // the shared Kubernetes probe used by other callers.
            return await probe.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return HealthCheckResult.Unhealthy();
        }
    }

    private async Task<HealthCheckResult> RefreshAsync()
    {
        // Ensure inFlight is assigned before a fake or in-memory API can complete
        // the whole probe synchronously and update the cache.
        await Task.Yield();
        var result = await ProbeAsync().ConfigureAwait(false);

        lock (cacheLock)
        {
            cachedResult = result;
            cacheTimestamp = timeProvider.GetTimestamp();
            inFlight = null;
        }

        return result;
    }

    private async Task<HealthCheckResult> ProbeAsync()
    {
        using var timeoutSource = new CancellationTokenSource(timeout);

        try
        {
            using var api = clientFactory.Create();
            if (verifyNamespaceListAuthorization &&
                !await api.IsResourceAccessAllowedAsync(
                        NamespaceDescriptor,
                        "list",
                        @namespace: null,
                        MaximumAuthorizationResponseBytes,
                        timeoutSource.Token).ConfigureAwait(false))
            {
                return HealthCheckResult.Unhealthy();
            }

            foreach (var verb in new[] { "get", "list" })
            {
                if (!await api.IsResourceAccessAllowedAsync(
                        authorizationTarget,
                        verb,
                        authorizationNamespace,
                        MaximumAuthorizationResponseBytes,
                        timeoutSource.Token).ConfigureAwait(false))
                {
                    return HealthCheckResult.Unhealthy();
                }
            }

            return HealthCheckResult.Healthy();
        }
        catch (Exception)
        {
            // Keep the report deliberately opaque: construction failures can
            // contain kubeconfig paths and upstream failures can contain response
            // details. Readiness needs only the binary ready/unready result.
            return HealthCheckResult.Unhealthy();
        }
    }

    private static KubernetesResourceDescriptor SelectAuthorizationTarget(
        KubeMcpOptions options)
    {
        var configured = options.AllowedResources.TryGetValue("pods", out var pods)
            ? pods
            : options.AllowedResources
                .OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .Select(entry => entry.Value)
                .FirstOrDefault();
        return configured is null
            ? PodDescriptor
            : new KubernetesResourceDescriptor(
                configured.Group,
                configured.Version,
                configured.Resource,
                configured.Kind);
    }
}
