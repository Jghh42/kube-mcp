using KubeMcp.Audit;
using Microsoft.AspNetCore.Http;

namespace KubeMcp.Tests;

public sealed class McpAccessAuditMiddlewareTests
{
    [Fact]
    public async Task AuditsApplicationAuthorizationDenialWithoutReadingBodyOrInventingCoordinates()
    {
        const int statusCode = StatusCodes.Status403Forbidden;
        const string expectedCategory = AuditCategories.AuthorizationDenied;
        var body = new ThrowIfReadStream();
        var context = new DefaultHttpContext();
        context.Request.Path = "/mcp";
        context.Request.Body = body;
        var audit = new CapturingAuditLogger();
        var middleware = new McpAccessAuditMiddleware(
            next: requestContext =>
            {
                requestContext.Response.StatusCode = statusCode;
                return Task.CompletedTask;
            },
            audit);

        await middleware.InvokeAsync(context);

        Assert.Equal(0, body.ReadAttempts);
        var denial = Assert.Single(audit.Denials);
        Assert.Equal(expectedCategory, denial.Category);
        Assert.Equal(statusCode, denial.StatusCode);
        Assert.Empty(audit.KubernetesEvents);
    }

    [Fact]
    public async Task LeavesAuthenticationFailuresToAspNetAccessLogging()
    {
        var body = new ThrowIfReadStream();
        var context = new DefaultHttpContext();
        context.Request.Body = body;
        var audit = new CapturingAuditLogger();
        var middleware = new McpAccessAuditMiddleware(
            next: requestContext =>
            {
                requestContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            },
            audit);

        await middleware.InvokeAsync(context);

        Assert.Equal(0, body.ReadAttempts);
        Assert.Empty(audit.Denials);
        Assert.Empty(audit.KubernetesEvents);
    }

    [Fact]
    public async Task AuditExceptionCannotReplaceDenialResponse()
    {
        var context = new DefaultHttpContext();
        var middleware = new McpAccessAuditMiddleware(
            next: requestContext =>
            {
                requestContext.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            },
            new ThrowingAuditLogger());

        var exception = await Record.ExceptionAsync(() => middleware.InvokeAsync(context));

        Assert.Null(exception);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
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
