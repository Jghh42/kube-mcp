namespace KubeMcp.Audit;

/// <summary>
/// Best-effort sequential fan-out from the bounded dispatcher. Each sink call is
/// isolated on a worker and receives a strict deadline. A sink that ignores
/// cancellation is left with at most one invocation in flight and is skipped for
/// later records until that invocation completes, so it cannot starve later sinks.
/// </summary>
public sealed class CompositeAuditSink
{
    internal static readonly EventId SinkTimeoutEvent = new(1096, "AuditSinkTimeout");
    internal static readonly EventId SinkFailureEvent = new(1098, "AuditSinkFailure");
    internal static readonly TimeSpan DefaultSinkTimeout = TimeSpan.FromSeconds(2);

    private readonly SinkState[] sinks;
    private readonly ILogger<CompositeAuditSink> logger;
    private readonly TimeSpan sinkTimeout;
    private int warningInFlight;

    public CompositeAuditSink(
        IEnumerable<IAuditSink> sinks,
        ILogger<CompositeAuditSink> logger)
        : this(sinks, logger, DefaultSinkTimeout)
    {
    }

    internal CompositeAuditSink(
        IEnumerable<IAuditSink> sinks,
        ILogger<CompositeAuditSink> logger,
        TimeSpan sinkTimeout)
    {
        if (sinkTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(sinkTimeout));
        }

        this.sinks = sinks.Select(static sink => new SinkState(sink)).ToArray();
        this.logger = logger;
        this.sinkTimeout = sinkTimeout;
    }

    public async ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        foreach (var sink in sinks)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            Task operation;
            CancellationTokenSource deadlineSource;
            lock (sink.Sync)
            {
                if (sink.InFlight is { IsCompleted: false })
                {
                    // A previous timed-out invocation ignored cancellation. Do
                    // not accumulate more permanently blocked calls for this sink.
                    continue;
                }

                sink.InFlight = null;
                // Do not link the dispatcher token directly: CancellationTokenSource
                // invokes callbacks synchronously, and a hostile sink could block
                // the thread that signals shutdown. Cancellation is requested on an
                // isolated worker below.
                deadlineSource = new CancellationTokenSource();
                operation = Task.Run(
                    async () => await sink.Sink
                        .WriteAsync(record, deadlineSource.Token)
                        .ConfigureAwait(false),
                    CancellationToken.None);
                sink.InFlight = operation;

                // If WaitAsync times out, the underlying task remains alive. This
                // continuation observes a later fault without retaining details.
                _ = operation.ContinueWith(
                    static completed => _ = completed.Exception,
                    CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted |
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }

            var disposeDeadlineSource = true;
            try
            {
                await operation
                    .WaitAsync(sinkTimeout, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                disposeDeadlineSource = false;
                CancelWithoutBlocking(sink, operation, deadlineSource);
                TryLogTimeout(sink.Name);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                disposeDeadlineSource = false;
                CancelWithoutBlocking(sink, operation, deadlineSource);
                return;
            }
            catch (Exception exception)
            {
                TryLogFailure(sink.Name, exception.GetType().Name);
            }
            finally
            {
                if (disposeDeadlineSource)
                {
                    deadlineSource.Dispose();
                }
            }
        }
    }

    private void TryLogTimeout(string sinkType) =>
        TryLog(() => logger.LogWarning(
            SinkTimeoutEvent,
            "Audit sink {SinkType} exceeded its dispatch deadline; delivery to remaining sinks will continue.",
            sinkType));

    private void TryLogFailure(string sinkType, string exceptionType) =>
        TryLog(() => logger.LogWarning(
            SinkFailureEvent,
            "Audit sink {SinkType} failed with exception type {ExceptionType}; delivery to remaining sinks will continue.",
            sinkType,
            exceptionType));

    private void TryLog(Action writeWarning)
    {
        // A warning provider can itself be the failed/hung logging pipeline. Keep
        // at most one isolated warning call in flight so diagnostics cannot stall
        // fan-out or create an unbounded secondary task stream.
        if (Interlocked.CompareExchange(ref warningInFlight, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(() =>
        {
            try
            {
                writeWarning();
            }
            catch
            {
                // Logging is part of best-effort audit delivery.
            }
            finally
            {
                Volatile.Write(ref warningInFlight, 0);
            }
        });
    }

    private static void CancelWithoutBlocking(
        SinkState sink,
        Task operation,
        CancellationTokenSource source)
    {
        // Even CancelAsync itself is invoked on a worker so no provider callback
        // can regain the dispatcher thread. Include cancellation completion in the
        // sink's in-flight task, preserving the one-stuck-call bound when a callback
        // ignores the deadline too.
        var cancellation = Task.Run(async () =>
        {
            try
            {
                await source.CancelAsync().ConfigureAwait(false);
            }
            catch
            {
                // Cancellation callback failures are sink failures.
            }
        });
        var cleanup = CompleteCancellationAsync(operation, cancellation, source);

        lock (sink.Sync)
        {
            if (ReferenceEquals(sink.InFlight, operation))
            {
                sink.InFlight = cleanup;
            }
        }
    }

    private static async Task CompleteCancellationAsync(
        Task operation,
        Task cancellation,
        CancellationTokenSource source)
    {
        try
        {
            await operation.ConfigureAwait(false);
        }
        catch
        {
            // The operation has a separate fault-observing continuation.
        }

        try
        {
            await cancellation.ConfigureAwait(false);
        }
        catch
        {
            // The cancellation worker is explicitly no-throw.
        }

        source.Dispose();
    }

    private sealed class SinkState(IAuditSink sink)
    {
        public object Sync { get; } = new();

        public IAuditSink Sink { get; } = sink;

        public string Name { get; } = sink.GetType().Name;

        public Task? InFlight { get; set; }
    }
}
