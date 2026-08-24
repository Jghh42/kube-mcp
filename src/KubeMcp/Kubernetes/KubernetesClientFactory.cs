using KubeMcp.Configuration;
using k8s;

namespace KubeMcp.Kubernetes;

/// <summary>
/// Default factory that builds the real k8s client from the configured kubeconfig
/// (or in-cluster defaults) and wraps it behind <see cref="IKubernetesApi"/>.
/// </summary>
internal sealed class KubernetesClientFactory : IKubernetesClientFactory
{
    private readonly KubeMcpOptions options;

    public KubernetesClientFactory(KubeMcpOptions options)
    {
        this.options = options;
    }

    public IKubernetesApi Create()
    {
        var configuration = string.IsNullOrWhiteSpace(options.KubeConfigPath)
            ? KubernetesClientConfiguration.BuildDefaultConfig()
            : KubernetesClientConfiguration.BuildConfigFromConfigFile(options.KubeConfigPath);

        var client = new k8s.Kubernetes(configuration);

        // The reader owns a linked cancellation token that enforces the configured
        // Kubernetes request timeout. Disable the HttpClient's own default deadline
        // so the linked token is the single timeout authority (it also covers the
        // configured range up to 120s, which exceeds the client's 100s default).
        client.HttpClient.Timeout = Timeout.InfiniteTimeSpan;

        return new KubernetesApi(
            client,
            ownsClient: true,
            configuration.TlsServerName);
    }
}
