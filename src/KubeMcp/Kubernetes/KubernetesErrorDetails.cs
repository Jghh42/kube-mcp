namespace KubeMcp.Kubernetes;

/// <summary>
/// Stable, low-cardinality error details safe for MCP responses and audit records.
/// Messages are fixed and never include an upstream body,
/// resource coordinate, token, or arbitrary exception text.
/// </summary>
public static class KubernetesErrorDetails
{
    public static KubernetesSafeError Get(KubernetesErrorCategory category) => category switch
    {
        KubernetesErrorCategory.ResourceNotAllowed => new(
            "resource_not_allowed",
            "The Kubernetes resource is not allowed."),
        KubernetesErrorCategory.NamespaceNotAllowed => new(
            "namespace_not_allowed",
            "The Kubernetes namespace is not allowed."),
        KubernetesErrorCategory.InvalidRequest => new(
            "invalid_request",
            "The Kubernetes request is invalid."),
        KubernetesErrorCategory.NotFound => new(
            "resource_not_found",
            "The Kubernetes resource was not found."),
        KubernetesErrorCategory.AccessDenied => new(
            "kubernetes_access_denied",
            "Access to the Kubernetes resource was denied."),
        KubernetesErrorCategory.RateLimited => new(
            "upstream_throttled",
            "The Kubernetes API is throttling requests. Try again later."),
        KubernetesErrorCategory.ServerError => new(
            "upstream_server_error",
            "The Kubernetes API returned a server error."),
        KubernetesErrorCategory.MalformedResponse => new(
            "upstream_malformed_response",
            "The Kubernetes API returned a malformed response."),
        KubernetesErrorCategory.NetworkError => new(
            "upstream_network_error",
            "The Kubernetes API could not be reached."),
        KubernetesErrorCategory.Timeout => new(
            "upstream_timeout",
            "The Kubernetes request timed out."),
        KubernetesErrorCategory.ResponseTooLarge => new(
            "response_too_large",
            "The Kubernetes response exceeded the configured size limit."),
        _ => new(
            "internal_error",
            "The Kubernetes API request failed."),
    };
}

public readonly record struct KubernetesSafeError(string Category, string Message);
