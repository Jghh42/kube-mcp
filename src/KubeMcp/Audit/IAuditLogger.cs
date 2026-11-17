namespace KubeMcp.Audit;

public interface IAuditLogger
{
    void LogKubernetesAccess(KubernetesAuditEvent auditEvent);
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

public static class AuditCategories
{
    public const string Success = "success";
    public const string ClientCancelled = "client_cancelled";
    public const string ServerTimeout = "server_timeout";
    public const string InternalError = "internal_error";
}
