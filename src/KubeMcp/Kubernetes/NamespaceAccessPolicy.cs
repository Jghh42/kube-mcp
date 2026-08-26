using KubeMcp.Configuration;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

public sealed class NamespaceAccessPolicy
{
    private readonly NamespacePolicyMode mode;
    private readonly HashSet<string> deniedNamespaces;

    public NamespaceAccessPolicy(IOptions<KubeMcpOptions> options)
    {
        var policy = options.Value.NamespacePolicy;
        mode = policy.Mode;
        LabelSelector = mode == NamespacePolicyMode.LabelSelector
            ? policy.LabelSelector
            : null;
        deniedNamespaces = new HashSet<string>(
            policy.DeniedNamespaces,
            StringComparer.Ordinal);
    }

    public string? LabelSelector { get; }

    public bool RequiresLabelCheck => mode == NamespacePolicyMode.LabelSelector;

    public bool IsDiscoveredNamespaceAllowed(string @namespace) =>
        mode != NamespacePolicyMode.Blacklist || !deniedNamespaces.Contains(@namespace);

    public void EnsureStaticallyAllowed(string @namespace)
    {
        if (!IsDiscoveredNamespaceAllowed(@namespace))
        {
            throw new KubernetesReadException(
                $"Namespace \"{@namespace}\" is denied by the configured namespace blacklist.",
                KubernetesErrorCategory.NamespaceNotAllowed);
        }
    }

    public void EnsureLabelCheckMatched(string @namespace, bool matched)
    {
        if (mode == NamespacePolicyMode.LabelSelector && !matched)
        {
            throw new KubernetesReadException(
                $"Namespace \"{@namespace}\" does not match the configured namespace label selector.",
                KubernetesErrorCategory.NamespaceNotAllowed);
        }
    }
}
