namespace KubeMcp.Kubernetes;

/// <summary>
/// Creates the narrow <see cref="IKubernetesApi"/> access surface. Injected into
/// <see cref="KubernetesReader"/> so the Kubernetes HTTP client construction is
/// isolated and substitutable for tests.
/// </summary>
public interface IKubernetesClientFactory
{
    IKubernetesApi Create();
}
