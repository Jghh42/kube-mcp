namespace KubeMcp.Kubernetes;

public sealed class KubernetesReadException : Exception
{
    public KubernetesReadException(string message)
        : base(message)
    {
    }
}
