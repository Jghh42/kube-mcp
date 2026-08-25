namespace KubeMcp.Audit;

/// <summary>Default audit sink using the application's structured ILogger pipeline.</summary>
public sealed class StructuredLoggerAuditSink(ILogger<StructuredLoggerAuditSink> logger) : IAuditSink
{
    public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (record.EventType == AuditEventType.McpAccessDenied)
        {
            logger.LogInformation(
                AuditLogger.McpAccessDeniedEvent,
                "MCP access-denial audit: timestamp={Timestamp} client={ClientIdentity} authentication={AuthenticationMethod} result={Result} category={Category} statusCode={StatusCode} durationMs={DurationMs} requestId={RequestId}",
                record.Timestamp,
                record.ClientIdentity,
                record.AuthenticationMethod,
                record.Result,
                record.Category,
                record.StatusCode,
                Math.Round(record.Duration.TotalMilliseconds, 2),
                record.RequestId);
        }
        else
        {
            logger.LogInformation(
                AuditLogger.KubernetesAccessEvent,
                "Kubernetes audit: timestamp={Timestamp} client={ClientIdentity} authentication={AuthenticationMethod} operation={Operation} resource={Resource} namespace={Namespace} name={ResourceName} result={Result} objectCount={ObjectCount} category={Category} durationMs={DurationMs} requestId={RequestId}",
                record.Timestamp,
                record.ClientIdentity,
                record.AuthenticationMethod,
                record.Operation,
                record.Resource,
                record.Namespace,
                record.Name,
                record.Result,
                record.ObjectCount,
                record.Category,
                Math.Round(record.Duration.TotalMilliseconds, 2),
                record.RequestId);
        }

        return ValueTask.CompletedTask;
    }
}
