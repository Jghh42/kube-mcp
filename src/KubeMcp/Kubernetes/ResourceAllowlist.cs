using KubeMcp.Configuration;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

public sealed class ResourceAllowlist
{
    private readonly IReadOnlyDictionary<string, KubernetesResourceDescriptor> resources;

    public ResourceAllowlist(IOptions<KubeMcpOptions> options)
    {
        resources = (options.Value.AllowedResources ?? []).ToDictionary(
            entry => entry.Key,
            entry => new KubernetesResourceDescriptor(
                entry.Value.Group,
                entry.Value.Version,
                entry.Value.Resource,
                entry.Value.Kind),
            StringComparer.OrdinalIgnoreCase);
    }

    internal KubernetesResourceDescriptor Resolve(string requestedResource)
    {
        if (resources.TryGetValue(requestedResource, out var descriptor))
        {
            return descriptor;
        }

        throw new KubernetesReadException(
            $"Resource \"{requestedResource}\" is not included in the configured resource allowlist.",
            KubernetesErrorCategory.ResourceNotAllowed);
    }
}
