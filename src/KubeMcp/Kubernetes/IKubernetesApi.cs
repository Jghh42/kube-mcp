namespace KubeMcp.Kubernetes;

/// <summary>
/// Narrow, testable access to the Kubernetes API. All network access used by
/// <see cref="KubernetesReader"/> and readiness passes through this boundary.
/// </summary>
/// <remarks>
/// GET and LIST bodies remain capped UTF-8 bytes until the reader parses them.
/// This avoids creating an additional UTF-16 copy of raw responses, especially
/// raw Secret LIST pages. Policy responses are capped by the same adapter before
/// they are deserialized.
/// </remarks>
public interface IKubernetesApi : IDisposable
{
    Task<ReadOnlyMemory<byte>> GetNamespacedAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string name,
        int maxBodyBytes,
        CancellationToken cancellationToken);

    Task<ReadOnlyMemory<byte>> ListNamespacedAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        int pageSize,
        string? continueToken,
        int maxBodyBytes,
        CancellationToken cancellationToken);

    Task<bool> IsResourceAccessAllowedAsync(
        KubernetesResourceDescriptor descriptor,
        string verb,
        string? @namespace,
        int maxBodyBytes,
        CancellationToken cancellationToken);

    Task<bool> NamespaceMatchesLabelSelectorAsync(
        string @namespace,
        string labelSelector,
        int maxBodyBytes,
        CancellationToken cancellationToken);
}
