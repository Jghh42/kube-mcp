using System.Threading.Channels;

namespace KubeMcp.Audit;

/// <summary>
/// Non-blocking request-path publisher backed by a bounded single-reader queue.
/// When capacity is exhausted, the new record is dropped. Drop warnings are
/// aggregated by a separate background loop so request handling never waits for a
/// logging provider. This explicit best-effort policy prevents audit sink latency,
/// backpressure, or exceptions from changing an MCP response or hiding its error.
/// </summary>
public sealed class AuditSinkDispatcher : BackgroundService, IAuditEventPublisher
{
    internal const int DefaultCapacity = 1024;
    private static readonly TimeSpan DefaultDropReportInterval = TimeSpan.FromSeconds(30);
    internal static readonly EventId QueueFullEvent = new(1099, "AuditQueueFull");
    internal static readonly EventId DispatchFailureEvent = new(1097, "AuditDispatchFailure");

    private readonly CompositeAuditSink sink;
    private readonly ILogger<AuditSinkDispatcher> logger;
    private readonly Channel<AuditRecord> queue;
    private readonly TimeSpan dropReportInterval;
    private readonly CancellationTokenSource dispatchCancellation = new();
    private long droppedCount;
    private long unreportedDropCount;

    public AuditSinkDispatcher(
        CompositeAuditSink sink,
        ILogger<AuditSinkDispatcher> logger)
        : this(sink, logger, DefaultCapacity, DefaultDropReportInterval)
    {
    }

    internal AuditSinkDispatcher(
        CompositeAuditSink sink,
        ILogger<AuditSinkDispatcher> logger,
        int capacity,
        TimeSpan? dropReportInterval = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        this.sink = sink;
        this.logger = logger;
        this.dropReportInterval = dropReportInterval ?? DefaultDropReportInterval;
        if (this.dropReportInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(dropReportInterval));
        }

        queue = Channel.CreateBounded<AuditRecord>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false
        });
    }

    internal long DroppedCount => Interlocked.Read(ref droppedCount);

    public bool TryPublish(AuditRecord record)
    {
        try
        {
            if (queue.Writer.TryWrite(record))
            {
                return true;
            }
        }
        catch
        {
            // Channel failures are not expected, but audit must remain no-throw.
        }

        Interlocked.Increment(ref droppedCount);
        Interlocked.Increment(ref unreportedDropCount);
        return false;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // BackgroundService cancels stoppingToken as soon as shutdown starts. Use
        // a separate token for dispatch so completing the writer drains queued
        // records throughout the host's graceful-shutdown window.
        var dispatchTask = DispatchAsync(dispatchCancellation.Token);
        var reportTask = ReportDropsAsync(stoppingToken);
        await Task.WhenAll(dispatchTask, reportTask).ConfigureAwait(false);
    }

    private async Task DispatchAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var record in queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await sink.WriteAsync(record, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception)
                {
                    TryLog(
                        DispatchFailureEvent,
                        "Audit dispatch failed with exception type {ExceptionType}; processing will continue.",
                        exception.GetType().Name);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Best effort: shutdown cancellation may leave queued records undelivered.
        }
    }

    private async Task ReportDropsAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(dropReportInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                ReportDrops();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            ReportDrops();
        }
    }

    private void ReportDrops()
    {
        var dropped = Interlocked.Exchange(ref unreportedDropCount, 0);
        if (dropped > 0)
        {
            TryLog(
                QueueFullEvent,
                "Audit records were dropped by the best-effort bounded queue. DroppedCount={DroppedCount}",
                dropped);
        }
    }

    private void TryLog(EventId eventId, string message, object value)
    {
        try
        {
            logger.LogWarning(eventId, message, value);
        }
        catch
        {
            // Logging is itself best effort. Never fault the dispatcher or host.
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        queue.Writer.TryComplete();
        using var registration = cancellationToken.Register(dispatchCancellation.Cancel);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
