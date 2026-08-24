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
    TimeSpan Duration);
