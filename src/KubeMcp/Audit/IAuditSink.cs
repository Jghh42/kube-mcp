namespace KubeMcp.Audit;

/// <summary>
/// Integration point for an organization's durable audit provider. Implementations
/// receive already-sanitized records and should honor cancellation during shutdown.
/// Registering additional sinks fans each record out alongside the default
/// structured-logger sink.
/// </summary>
public interface IAuditSink
{
    ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken);
}

public enum AuditEventType
{
    KubernetesAccess,
    McpAccessDenied,
}

/// <summary>
/// Sanitized audit envelope. Coordinate fields are populated only after tool
/// dispatch; pre-tool access denials intentionally leave them null.
/// </summary>
public sealed record AuditRecord(
    AuditEventType EventType,
    DateTimeOffset Timestamp,
    string ClientIdentity,
    string AuthenticationMethod,
    string? Operation,
    string? Resource,
    string? Namespace,
    string? Name,
    string Result,
    string Category,
    int? ObjectCount,
    TimeSpan Duration,
    string RequestId,
    string ClientIp,
    int? StatusCode);

public interface IAuditEventPublisher
{
    /// <summary>
    /// Attempts to enqueue without waiting. Returns false when the bounded queue
    /// is full or stopping. Implementations must not throw into request handling.
    /// </summary>
    bool TryPublish(AuditRecord record);
}
