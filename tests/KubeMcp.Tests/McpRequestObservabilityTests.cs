using System.Collections.Concurrent;
using System.Diagnostics;
using KubeMcp.Audit;
using KubeMcp.Observability;
using Microsoft.AspNetCore.Http;

namespace KubeMcp.Tests;

public sealed class McpRequestObservabilityTests
{
    [Theory]
    [InlineData(StatusCodes.Status401Unauthorized, AuditCategories.AuthenticationDenied)]
    [InlineData(StatusCodes.Status403Forbidden, AuditCategories.AuthorizationDenied)]
    public async Task AuditsPreToolDenialWithoutReadingBodyOrInventingCoordinates(
        int statusCode,
        string expectedCategory)
    {
        var body = new ThrowIfReadStream();
        var context = new DefaultHttpContext();
        context.Request.Path = "/mcp";
        context.Request.Body = body;
        var audit = new CapturingAuditLogger();
        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor { HttpContext = context });
        var middleware = new McpRequestObservabilityMiddleware(
            next: requestContext =>
            {
                requestContext.Response.StatusCode = statusCode;
                return Task.CompletedTask;
            },
            audit,
            telemetry);

        await middleware.InvokeAsync(context);

        Assert.Equal(0, body.ReadAttempts);
        var denial = Assert.Single(audit.Denials);
        Assert.Equal(expectedCategory, denial.Category);
        Assert.Equal(statusCode, denial.StatusCode);
        Assert.Empty(audit.KubernetesEvents);
    }

    [Theory]
    [InlineData(StatusCodes.Status400BadRequest, AuditCategories.InvalidRequest)]
    [InlineData(StatusCodes.Status500InternalServerError, AuditCategories.InternalError)]
    public async Task ClassifiesHandledHttpFailures(int statusCode, string expectedCategory)
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = ListenForStoppedActivities(stopped);
        var context = new DefaultHttpContext();
        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor { HttpContext = context });
        var middleware = new McpRequestObservabilityMiddleware(
            next: requestContext =>
            {
                requestContext.Response.StatusCode = statusCode;
                return Task.CompletedTask;
            },
            new CapturingAuditLogger(),
            telemetry);

        await middleware.InvokeAsync(context);

        var activity = Assert.Single(stopped, item => item.OperationName == "mcp.request");
        Assert.Equal(expectedCategory, activity.GetTagItem("mcp.error.category"));
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
    }

    [Fact]
    public async Task UnhandledFailureOverridesEarlierToolCategory()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = ListenForStoppedActivities(stopped);
        var context = new DefaultHttpContext();
        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor { HttpContext = context });
        var middleware = new McpRequestObservabilityMiddleware(
            next: requestContext =>
            {
                requestContext.Features.Get<McpRequestState>()!.Category = "resource_not_found";
                throw new InvalidOperationException("post-tool-transport-failure");
            },
            new CapturingAuditLogger(),
            telemetry);

        await Assert.ThrowsAsync<InvalidOperationException>(() => middleware.InvokeAsync(context));

        var activity = Assert.Single(stopped, item => item.OperationName == "mcp.request");
        Assert.Equal(AuditCategories.InternalError, activity.GetTagItem("mcp.error.category"));
    }

    [Fact]
    public async Task AuditExceptionCannotReplaceDenialResponse()
    {
        var context = new DefaultHttpContext();
        using var telemetry = new KubeMcpTelemetry(new HttpContextAccessor { HttpContext = context });
        var middleware = new McpRequestObservabilityMiddleware(
            next: requestContext =>
            {
                requestContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            },
            new ThrowingAuditLogger(),
            telemetry);

        var exception = await Record.ExceptionAsync(() => middleware.InvokeAsync(context));

        Assert.Null(exception);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    private static ActivityListener ListenForStoppedActivities(ConcurrentBag<Activity> stopped)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == KubeMcpTelemetry.InstrumentationName,
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = stopped.Add
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    private sealed class CapturingAuditLogger : IAuditLogger
    {
        public List<KubernetesAuditEvent> KubernetesEvents { get; } = [];
        public List<McpAccessDeniedAuditEvent> Denials { get; } = [];

        public void LogKubernetesAccess(KubernetesAuditEvent auditEvent) =>
            KubernetesEvents.Add(auditEvent);

        public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent) =>
            Denials.Add(auditEvent);
    }

    private sealed class ThrowingAuditLogger : IAuditLogger
    {
        public void LogKubernetesAccess(KubernetesAuditEvent auditEvent) =>
            throw new InvalidOperationException("provider-sensitive-detail");

        public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent) =>
            throw new InvalidOperationException("provider-sensitive-detail");
    }

    private sealed class ThrowIfReadStream : Stream
    {
        public int ReadAttempts { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadAttempts++;
            throw new InvalidOperationException("Request body must not be read.");
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ReadAttempts++;
            throw new InvalidOperationException("Request body must not be read.");
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
