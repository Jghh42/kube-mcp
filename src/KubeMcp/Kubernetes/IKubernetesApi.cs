namespace KubeMcp.Kubernetes;

/// <summary>
/// Lightweight discovery DTO that decouples the reader from Kubernetes client
/// model types so deterministic tests can provide canned discovery results.
/// </summary>
public sealed record ApiResourceInfo(
    string Name,
    string SingularName,
    string Kind,
    bool Namespaced,
    IReadOnlyList<string>? ShortNames,
    IReadOnlyList<string>? Verbs);

/// <summary>One Kubernetes API group and its preferred discovery version.</summary>
public sealed record ApiGroupInfo(string Name, string PreferredVersion);

/// <summary>
/// Narrow, testable access to the Kubernetes API. All network access used by
/// <see cref="KubernetesReader"/> passes through this boundary.
/// </summary>
/// <remarks>
/// GET and LIST bodies remain capped UTF-8 bytes until the reader parses them.
/// This avoids creating an additional UTF-16 copy of raw responses, especially
/// raw Secret LIST pages. Discovery and policy responses are capped by the same
/// adapter before they are deserialized.
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

    Task<IReadOnlyList<ApiResourceInfo>> GetCoreResourcesAsync(
        int maxBodyBytes,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ApiGroupInfo>> GetApiGroupsAsync(
        int maxBodyBytes,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<ApiResourceInfo>> GetGroupResourcesAsync(
        string group,
        string version,
        int maxBodyBytes,
        CancellationToken cancellationToken);

    Task<bool> NamespaceMatchesLabelSelectorAsync(
        string @namespace,
        string labelSelector,
        int maxBodyBytes,
        CancellationToken cancellationToken);
}
