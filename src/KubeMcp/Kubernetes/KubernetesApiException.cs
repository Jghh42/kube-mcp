namespace KubeMcp.Kubernetes;

/// <summary>
/// Safe exception emitted by the Kubernetes adapter. It contains only a fixed
/// category/message and an optional status code; upstream response bodies and
/// transport exceptions are deliberately not retained.
/// </summary>
public sealed class KubernetesApiException : Exception
{
    public KubernetesApiException(
        KubernetesErrorCategory category,
        string message,
        int? statusCode = null)
        : base(message)
    {
        Category = category;
        StatusCode = statusCode;
    }

    public KubernetesErrorCategory Category { get; }

    public int? StatusCode { get; }
}
