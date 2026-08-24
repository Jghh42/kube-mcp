namespace KubeMcp.Kubernetes;

public interface IKubernetesReader
{
    Task<KubernetesReadResult> ReadAsync(
        string resource,
        string @namespace,
        string? name,
        CancellationToken cancellationToken);
}

public sealed record KubernetesReadResult(string Json, int ObjectCount);
