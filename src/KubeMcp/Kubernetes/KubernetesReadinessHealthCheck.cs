using KubeMcp.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

/// <summary>
/// Verifies Kubernetes connectivity and representative GET/LIST authorization
/// without reading any workload object. Authorization is evaluated by the API
/// server for the current credentials through SelfSubjectAccessReview.
/// </summary>
internal sealed class KubernetesReadinessHealthCheck : IHealthCheck
{
    internal const string Name = "kubernetes-api";
    internal const string Tag = "ready";
    internal const int MaximumAuthorizationResponseBytes = 16 * 1024;
    internal static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private static readonly KubernetesResourceDescriptor PodDescriptor =
        new(string.Empty, "v1", "pods", "Pod");

    private readonly IKubernetesClientFactory clientFactory;
    private readonly KubernetesResourceDescriptor authorizationTarget;
    private readonly TimeSpan timeout;

    public KubernetesReadinessHealthCheck(
        IKubernetesClientFactory clientFactory,
        IOptions<KubeMcpOptions> options)
        : this(clientFactory, SelectAuthorizationTarget(options.Value), Timeout)
    {
    }

    internal KubernetesReadinessHealthCheck(
        IKubernetesClientFactory clientFactory,
        TimeSpan timeout)
        : this(clientFactory, PodDescriptor, timeout)
    {
    }

    private KubernetesReadinessHealthCheck(
        IKubernetesClientFactory clientFactory,
        KubernetesResourceDescriptor authorizationTarget,
        TimeSpan timeout)
    {
        this.clientFactory = clientFactory;
        this.authorizationTarget = authorizationTarget;
        this.timeout = timeout;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            using var api = clientFactory.Create();
            foreach (var verb in new[] { "get", "list" })
            {
                if (!await api.IsResourceAccessAllowedAsync(
                        authorizationTarget,
                        verb,
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
        if (options.ResourcePolicy.Mode == ResourcePolicyMode.AllowAll)
        {
            return PodDescriptor;
        }

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
