namespace KubeMcp.Audit;

public interface IAuditLogger
{
    void LogKubernetesAccess(KubernetesAuditEvent auditEvent);

    void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent);
}

public sealed record KubernetesAuditEvent(
    string Operation,
    string Resource,
    string Namespace,
    string? Name,
    string Result,
    int? ObjectCount,
    TimeSpan Duration,
    string Category = AuditCategories.InternalError);

/// <summary>
/// Safe pre-tool denial event. Kubernetes coordinates are deliberately absent:
/// logging middleware must not parse an arbitrary MCP request body to find them.
/// </summary>
public sealed record McpAccessDeniedAuditEvent(
    string Category,
    int StatusCode,
    TimeSpan Duration);

public static class AuditCategories
{
    public const string Success = "success";
    public const string AuthenticationDenied = "authentication_denied";
    public const string AuthorizationDenied = "authorization_denied";
    public const string InvalidRequest = "invalid_request";
    public const string ClientCancelled = "client_cancelled";
    public const string ServerTimeout = "server_timeout";
    public const string InternalError = "internal_error";
}
