using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;

namespace KubeMcp.Tests;

public sealed class KubernetesGetToolAuditTests
{
    [Fact]
    public async Task AuditsSuccessfulListWithObjectCount()
    {
        var reader = new StubReader(new KubernetesReadResult("{\"items\":[]}", 3));
        var audit = new CapturingAuditLogger();
        var tool = new KubernetesGetTool(
            reader,
            audit,
            NullLogger<KubernetesGetTool>.Instance);

        var response = await tool.GetAsync("pods", "production");

        Assert.Equal("{\"items\":[]}", response);
        var entry = Assert.Single(audit.Events);
        Assert.Equal("LIST", entry.Operation);
        Assert.Equal("pods", entry.Resource);
        Assert.Equal("production", entry.Namespace);
        Assert.Null(entry.Name);
        Assert.Equal("success", entry.Result);
        Assert.Equal(3, entry.ObjectCount);
        Assert.True(entry.Duration >= TimeSpan.Zero);
    }

    [Fact]
    public async Task AuditsRejectedGetWithoutLoggingExceptionOrResponseContent()
    {
        var reader = new StubReader(new KubernetesReadException(
            "UPSTREAM-OR-DYNAMIC-DETAIL-MUST-NOT-LEAK",
            KubernetesErrorCategory.ResourceNotAllowed));
        var audit = new CapturingAuditLogger();
        var tool = new KubernetesGetTool(
            reader,
            audit,
            NullLogger<KubernetesGetTool>.Instance);

        var exception = await Assert.ThrowsAsync<McpException>(() =>
            tool.GetAsync("secrets", "production", "credentials"));

        Assert.Equal("The Kubernetes resource is not allowed.", exception.Message);
        var entry = Assert.Single(audit.Events);
        Assert.Equal("GET", entry.Operation);
        Assert.Equal("secrets", entry.Resource);
        Assert.Equal("production", entry.Namespace);
        Assert.Equal("credentials", entry.Name);
        Assert.Equal("failed", entry.Result);
        Assert.Equal("resource_not_allowed", entry.Category);
        Assert.Null(entry.ObjectCount);
    }

    public static TheoryData<KubernetesErrorCategory, string, string> SafeErrors => new()
    {
        { KubernetesErrorCategory.AccessDenied, "kubernetes_access_denied", "Access to the Kubernetes resource was denied." },
        { KubernetesErrorCategory.NotFound, "resource_not_found", "The Kubernetes resource was not found." },
        { KubernetesErrorCategory.RateLimited, "upstream_throttled", "The Kubernetes API is throttling requests. Try again later." },
        { KubernetesErrorCategory.ServerError, "upstream_server_error", "The Kubernetes API returned a server error." },
        { KubernetesErrorCategory.NetworkError, "upstream_network_error", "The Kubernetes API could not be reached." },
        { KubernetesErrorCategory.MalformedResponse, "upstream_malformed_response", "The Kubernetes API returned a malformed response." },
        { KubernetesErrorCategory.ResponseTooLarge, "response_too_large", "The Kubernetes response exceeded the configured size limit." },
        { KubernetesErrorCategory.Timeout, "upstream_timeout", "The Kubernetes request timed out." },
        { KubernetesErrorCategory.Internal, "internal_error", "The Kubernetes API request failed." }
    };

    [Theory]
    [MemberData(nameof(SafeErrors))]
    public async Task MapsTypedFailuresToFixedMessageAndMatchingAuditCategory(
        KubernetesErrorCategory errorCategory,
        string expectedCategory,
        string expectedMessage)
    {
        const string sensitiveBody = "{\"message\":\"upstream-secret-body\"}";
        var audit = new CapturingAuditLogger();
        var tool = new KubernetesGetTool(
            new StubReader(new KubernetesReadException(sensitiveBody, errorCategory)),
            audit,
            NullLogger<KubernetesGetTool>.Instance);

        var exception = await Assert.ThrowsAsync<McpException>(() =>
            tool.GetAsync("secrets", "production", "credentials"));

        Assert.Equal(expectedMessage, exception.Message);
        Assert.DoesNotContain(sensitiveBody, exception.ToString());
        var entry = Assert.Single(audit.Events);
        Assert.Equal(expectedCategory, entry.Category);
        Assert.Equal("failed", entry.Result);
    }

    [Fact]
    public async Task DistinguishesCallerCancellationFromServerDeadline()
    {
        using var callerCancellation = new CancellationTokenSource();
        callerCancellation.Cancel();
        var callerAudit = new CapturingAuditLogger();
        var callerTool = new KubernetesGetTool(
            new StubReader(new OperationCanceledException(callerCancellation.Token)),
            callerAudit,
            NullLogger<KubernetesGetTool>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            callerTool.GetAsync("pods", "production", cancellationToken: callerCancellation.Token));

        var callerEntry = Assert.Single(callerAudit.Events);
        Assert.Equal("cancelled", callerEntry.Result);
        Assert.Equal(AuditCategories.ClientCancelled, callerEntry.Category);

        using var serverDeadline = new CancellationTokenSource();
        serverDeadline.Cancel();
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpRequestTimeoutFeature>(new TimeoutFeature(serverDeadline.Token));
        var serverAudit = new CapturingAuditLogger();
        var serverTool = new KubernetesGetTool(
            new StubReader(new OperationCanceledException(serverDeadline.Token)),
            serverAudit,
            NullLogger<KubernetesGetTool>.Instance,
            new HttpContextAccessor { HttpContext = context });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            serverTool.GetAsync("pods", "production", cancellationToken: serverDeadline.Token));

        var serverEntry = Assert.Single(serverAudit.Events);
        Assert.Equal("timeout", serverEntry.Result);
        Assert.Equal(AuditCategories.ServerTimeout, serverEntry.Category);
    }

    [Fact]
    public async Task AuditFailureNeverReplacesSuccessfulResponse()
    {
        var tool = new KubernetesGetTool(
            new StubReader(new KubernetesReadResult("{}", 1)),
            new ThrowingAuditLogger(),
            NullLogger<KubernetesGetTool>.Instance);

        Assert.Equal("{}", await tool.GetAsync("pods", "production", "pod-1"));
    }

    private sealed class StubReader : IKubernetesReader
    {
        private readonly KubernetesReadResult? result;
        private readonly Exception? exception;

        public StubReader(KubernetesReadResult result) => this.result = result;

        public StubReader(Exception exception) => this.exception = exception;

        public Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken) =>
            exception is null
                ? Task.FromResult(result!)
                : Task.FromException<KubernetesReadResult>(exception);
    }

    private sealed class CapturingAuditLogger : IAuditLogger
    {
        public List<KubernetesAuditEvent> Events { get; } = [];

        public void LogKubernetesAccess(KubernetesAuditEvent auditEvent) => Events.Add(auditEvent);

        public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent)
        {
        }
    }

    private sealed class ThrowingAuditLogger : IAuditLogger
    {
        public void LogKubernetesAccess(KubernetesAuditEvent auditEvent) =>
            throw new InvalidOperationException("audit-provider-secret");

        public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent) =>
            throw new InvalidOperationException("audit-provider-secret");
    }

    private sealed class TimeoutFeature(CancellationToken token) : IHttpRequestTimeoutFeature
    {
        public CancellationToken RequestTimeoutToken => token;

        public void DisableTimeout()
        {
        }
    }
}
