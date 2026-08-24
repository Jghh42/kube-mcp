using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
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
        var reader = new StubReader(new KubernetesReadException("Resource is not allowed."));
        var audit = new CapturingAuditLogger();
        var tool = new KubernetesGetTool(
            reader,
            audit,
            NullLogger<KubernetesGetTool>.Instance);

        var exception = await Assert.ThrowsAsync<McpException>(() =>
            tool.GetAsync("secrets", "production", "credentials"));

        Assert.Equal("Resource is not allowed.", exception.Message);
        var entry = Assert.Single(audit.Events);
        Assert.Equal("GET", entry.Operation);
        Assert.Equal("secrets", entry.Resource);
        Assert.Equal("production", entry.Namespace);
        Assert.Equal("credentials", entry.Name);
        Assert.Equal("failed", entry.Result);
        Assert.Null(entry.ObjectCount);
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
    }
}
