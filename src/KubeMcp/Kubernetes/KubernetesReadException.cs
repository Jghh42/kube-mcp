namespace KubeMcp.Kubernetes;

/// <summary>
/// The public boundary exception surfaced to the MCP tool layer. The safe
/// <see cref="Category"/> is available for safe errors and audit; the upstream
/// Kubernetes response body is never part of the message.
/// </summary>
public sealed class KubernetesReadException : Exception
{
    public KubernetesErrorCategory Category { get; }

    public KubernetesReadException(string message)
        : this(message, KubernetesErrorCategory.Internal)
    {
    }

    public KubernetesReadException(string message, KubernetesErrorCategory category)
        : base(message)
    {
        Category = category;
    }

    public KubernetesReadException(string message, KubernetesErrorCategory category, Exception inner)
        : base(message, inner)
    {
        Category = category;
    }
}
