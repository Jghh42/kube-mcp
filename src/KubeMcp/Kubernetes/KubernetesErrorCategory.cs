namespace KubeMcp.Kubernetes;

/// <summary>
/// Safe, low-cardinality Kubernetes failure categories used across the boundary,
/// error and audit surfaces. Upstream HTTP bodies are never carried by this
/// category; only the coarse reason is retained.
/// </summary>
public enum KubernetesErrorCategory
{
    /// <summary>Not an error; used as the default for non-boundary exceptions.</summary>
    None,

    /// <summary>The requested resource is not permitted by the resource policy.</summary>
    ResourceNotAllowed,

    /// <summary>The requested namespace is not permitted by the namespace policy.</summary>
    NamespaceNotAllowed,

    /// <summary>The caller-supplied request shape is invalid.</summary>
    InvalidRequest,

    /// <summary>The Kubernetes resource was not found (HTTP 404).</summary>
    NotFound,

    /// <summary>Kubernetes RBAC denied access (HTTP 403).</summary>
    AccessDenied,

    /// <summary>Kubernetes is rate-limiting requests (HTTP 429).</summary>
    RateLimited,

    /// <summary>Kubernetes returned a server error (HTTP 5xx).</summary>
    ServerError,

    /// <summary>The upstream response could not be parsed as valid Kubernetes JSON.</summary>
    MalformedResponse,

    /// <summary>The Kubernetes API could not be reached (connection/DNS failure).</summary>
    NetworkError,

    /// <summary>The Kubernetes request exceeded the configured server-side timeout.</summary>
    Timeout,

    /// <summary>The upstream response exceeded the configured body/output size limit.</summary>
    ResponseTooLarge,

    /// <summary>An unhandled internal failure that did not fit another category.</summary>
    Internal,
}
