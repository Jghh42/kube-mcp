namespace KubeMcp.Audit;

/// <summary>
/// Best-effort sequential fan-out. A slow sink applies backpressure only to the
/// bounded background audit queue, never to an MCP request. One sink failure is
/// reduced to a safe local warning and does not prevent delivery to other sinks.
/// </summary>
public sealed class CompositeAuditSink(
    IEnumerable<IAuditSink> sinks,
    ILogger<CompositeAuditSink> logger)
{
    internal static readonly EventId SinkFailureEvent = new(1098, "AuditSinkFailure");

    public async ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        foreach (var sink in sinks)
        {
            try
            {
                await sink.WriteAsync(record, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                // Never include exception messages or exception objects: a provider
                // failure may contain credentials, payloads, or high-cardinality data.
                try
                {
                    logger.LogWarning(
                        SinkFailureEvent,
                        "Audit sink {SinkType} failed with exception type {ExceptionType}; delivery to remaining sinks will continue.",
                        sink.GetType().Name,
                        exception.GetType().Name);
                }
                catch
                {
                    // Even a failing logging provider is an audit sink failure.
                    // Continue fan-out and never fault the dispatcher/host.
                }
            }
        }
    }
}
