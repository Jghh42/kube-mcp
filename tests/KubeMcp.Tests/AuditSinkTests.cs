using System.Diagnostics;
using KubeMcp.Audit;
using KubeMcp.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

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
        var warning = await WaitForEntryAsync(logger, CompositeAuditSink.SinkFailureEvent);
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
    public async Task HungSinkTimesOutAndCannotStarveLaterSinksOrAccumulateCalls()
    {
        var hanging = new CancellationBlockingSink();
        var capture = new CapturingSink();
        var logger = new AuditLoggerTests.CapturingLogger<CompositeAuditSink>();
        var composite = new CompositeAuditSink(
            [hanging, capture],
            logger,
            sinkTimeout: TimeSpan.FromMilliseconds(50));

        try
        {
            await composite.WriteAsync(Record("first"), CancellationToken.None)
                .AsTask()
                .WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Single(capture.Records);
            Assert.Equal(1, hanging.InvocationCount);
            var warning = await WaitForEntryAsync(logger, CompositeAuditSink.SinkTimeoutEvent);
            Assert.Equal("CancellationBlockingSink", warning.Properties["SinkType"]);
            Assert.Null(warning.Exception);

            var stopwatch = Stopwatch.StartNew();
            await composite.WriteAsync(Record("second"), CancellationToken.None);
            stopwatch.Stop();

            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(1));
            Assert.Equal(2, capture.Records.Count);
            Assert.Equal(1, hanging.InvocationCount);
        }
        finally
        {
            hanging.CallbackRelease.TrySetResult();
            hanging.Release.TrySetResult();
        }
    }

    [Fact]
    public async Task DefaultStructuredLoggerRunsOnlyBehindBoundedDispatcher()
    {
        var blockingLogger = new BlockingLogger<StructuredLoggerAuditSink>();
        var structuredSink = new StructuredLoggerAuditSink(blockingLogger);
        var composite = new CompositeAuditSink(
            [structuredSink],
            NullLogger<CompositeAuditSink>.Instance,
            sinkTimeout: TimeSpan.FromSeconds(5));
        var dispatcher = new AuditSinkDispatcher(
            composite,
            NullLogger<AuditSinkDispatcher>.Instance,
            capacity: 1);
        var auditLogger = new AuditLogger(
            dispatcher,
            new HttpContextAccessor { HttpContext = new DefaultHttpContext() },
            Options.Create(new KubeMcpOptions
            {
                Authentication = new KubeMcpAuthenticationOptions
                {
                    Mode = AuthenticationMode.None
                }
            }),
            TimeProvider.System);
        await dispatcher.StartAsync(CancellationToken.None);

        var requestThreadCall = Task.Run(() => auditLogger.LogKubernetesAccess(
            new KubernetesAuditEvent(
                "LIST",
                "pods",
                "default",
                null,
                "success",
                1,
                TimeSpan.Zero,
                AuditCategories.Success)));

        try
        {
            await requestThreadCall.WaitAsync(TimeSpan.FromSeconds(1));
            await blockingLogger.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        }
        finally
        {
            blockingLogger.Release.TrySetResult();
            await dispatcher.StopAsync(CancellationToken.None);
        }
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

        var stopwatch = Stopwatch.StartNew();
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

    private static async Task<AuditLoggerTests.LogEntry> WaitForEntryAsync<T>(
        AuditLoggerTests.CapturingLogger<T> logger,
        EventId eventId)
    {
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (DateTime.UtcNow < deadline)
        {
            var entry = logger.Entries.FirstOrDefault(candidate => candidate.EventId == eventId);
            if (entry is not null)
            {
                return entry;
            }

            await Task.Delay(10);
        }

        throw new TimeoutException($"Log event {eventId} was not written.");
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

    private sealed class ThrowingLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            throw new InvalidOperationException("logging-provider-sensitive-detail");
    }

    private sealed class BlockingLogger<T> : ILogger<T>
    {
        public TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entered.TrySetResult();
            Release.Task.GetAwaiter().GetResult();
        }
    }

    private sealed class CancellationBlockingSink : IAuditSink
    {
        private int invocationCount;

        public TaskCompletionSource CallbackRelease { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int InvocationCount => Volatile.Read(ref invocationCount);

        public async ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref invocationCount);
            using var registration = cancellationToken.Register(() =>
                CallbackRelease.Task.GetAwaiter().GetResult());
            await Release.Task;
        }
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
