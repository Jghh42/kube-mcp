namespace KubeMcp.Kubernetes;

public interface IKubernetesReader
{
    Task<string> ReadAsync(
        string resource,
        string @namespace,
        string? name,
        CancellationToken cancellationToken);
}
