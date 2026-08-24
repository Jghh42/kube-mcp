using KubeMcp.Audit;
using Microsoft.Extensions.Logging.Abstractions;

namespace KubeMcp.Tests;

public sealed class AuditSinkTests
{
    [Fact]
    public async Task CompositeFansOutAndContainsProviderFailure()
    {
        var capture = new CapturingSink();
        var logger = new AuditLoggerTests.CapturingLogger<CompositeAuditSink>();
        var composite = new CompositeAuditSink(
            [new ThrowingSink(), capture],
            logger);
        var record = Record("upstream_server_error");

        var exception = await Xunit.Record.ExceptionAsync(async () =>
            await composite.WriteAsync(record, CancellationToken.None));

        Assert.Null(exception);
        Assert.Same(record, Assert.Single(capture.Records));
        var warning = Assert.Single(logger.Entries);
        Assert.Equal(CompositeAuditSink.SinkFailureEvent, warning.EventId);
        Assert.Null(warning.Exception);
        Assert.Equal("ThrowingSink", warning.Properties["SinkType"]);
        Assert.Equal("InvalidOperationException", warning.Properties["ExceptionType"]);
        Assert.DoesNotContain("provider-sensitive-detail", warning.Properties.Values.OfType<string>());
    }

    [Fact]
    public async Task CompositeContinuesWhenItsFailureLoggerAlsoThrows()
    {
        var capture = new CapturingSink();
        var composite = new CompositeAuditSink(
            [new ThrowingSink(), capture],
            new ThrowingLogger<CompositeAuditSink>());
        var record = Record("internal_error");

        var exception = await Xunit.Record.ExceptionAsync(async () =>
            await composite.WriteAsync(record, CancellationToken.None));

        Assert.Null(exception);
        Assert.Same(record, Assert.Single(capture.Records));
    }

    [Fact]
    public async Task BoundedDispatcherNeverBlocksPublisherAndDropsNewestAtCapacity()
    {
        var blocking = new BlockingSink();
        var composite = new CompositeAuditSink(
            [blocking],
            NullLogger<CompositeAuditSink>.Instance);
        var logger = new AuditLoggerTests.CapturingLogger<AuditSinkDispatcher>();
        var dispatcher = new AuditSinkDispatcher(composite, logger, capacity: 1);
        await dispatcher.StartAsync(CancellationToken.None);

        Assert.True(dispatcher.TryPublish(Record("success")));
        await blocking.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(dispatcher.TryPublish(Record("resource_not_found")));

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        Assert.False(dispatcher.TryPublish(Record("upstream_throttled")));
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
        Assert.Equal(1, dispatcher.DroppedCount);
        Assert.Empty(logger.Entries); // no request-path warning/backpressure

        blocking.Release.TrySetResult();
        await dispatcher.StopAsync(CancellationToken.None);
        Assert.Equal(2, blocking.Records.Count);
        Assert.Equal(AuditSinkDispatcher.QueueFullEvent, Assert.Single(logger.Entries).EventId);
    }

    private static AuditRecord Record(string category) => new(
        AuditEventType.KubernetesAccess,
        DateTimeOffset.UnixEpoch,
        "anonymous",
        "None",
        "LIST",
        "pods",
        "default",
        "-",
        category == "success" ? "success" : "failed",
        category,
        null,
        TimeSpan.Zero,
        "request-1",
        "127.0.0.1",
        null);

    private sealed class CapturingSink : IAuditSink
    {
        public List<AuditRecord> Records { get; } = [];

        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
        {
            Records.Add(record);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ThrowingSink : IAuditSink
    {
        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("provider-sensitive-detail");
    }

    private sealed class ThrowingLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            throw new InvalidOperationException("logging-provider-sensitive-detail");
    }

    private sealed class BlockingSink : IAuditSink
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<AuditRecord> Records { get; } = [];

        public async ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            Records.Add(record);
        }
    }
}
