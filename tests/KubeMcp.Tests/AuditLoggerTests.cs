using System.Security.Claims;
using KubeMcp.Audit;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ModelContextProtocol;

namespace KubeMcp.Tests;

public sealed class AuditLoggerTests
{
    [Fact]
    public void LogsSanitizedApiKeyKubernetesAuditFieldsWithoutSensitiveValuesOrClientIp()
    {
        const string apiKey = "api-key-must-not-appear";
        const string hmacKey = "hmac-key-must-not-appear";
        var timestamp = new DateTimeOffset(2026, 3, 20, 12, 34, 56, TimeSpan.Zero);
        var context = new DefaultHttpContext { TraceIdentifier = "request-123" };
        context.Request.Headers.Authorization = $"Bearer {apiKey}";
        context.Request.Headers["X-Forwarded-For"] = "198.51.100.7";
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("client_id", "static-api-key")],
            authenticationType: "ApiKey"));
        var output = new CapturingLogger<AuditLogger>();
        var audit = CreateLogger(output, context, AuthenticationMode.ApiKey, timestamp, hmacKey);

        audit.LogKubernetesAccess(new KubernetesAuditEvent(
            "GET",
            "secrets",
            "database",
            "credentials",
            "failed",
            null,
            TimeSpan.FromMilliseconds(12.345),
            "kubernetes_access_denied"));

        var entry = Assert.Single(output.Entries);
        Assert.Equal(AuditLogger.KubernetesAccessEvent, entry.EventId);
        Assert.Equal(timestamp, entry.Properties["Timestamp"]);
        Assert.Equal("static-api-key", entry.Properties["ClientIdentity"]);
        Assert.Equal("ApiKey", entry.Properties["AuthenticationMethod"]);
        Assert.Equal("GET", entry.Properties["Operation"]);
        Assert.Equal("secrets", entry.Properties["Resource"]);
        Assert.Equal("database", entry.Properties["Namespace"]);
        Assert.Equal("credentials", entry.Properties["ResourceName"]);
        Assert.Equal("failed", entry.Properties["Result"]);
        Assert.Equal("kubernetes_access_denied", entry.Properties["Category"]);
        Assert.Null(entry.Properties["ObjectCount"]);
        Assert.Equal(12.34, entry.Properties["DurationMs"]);
        Assert.Equal("request-123", entry.Properties["RequestId"]);
        Assert.DoesNotContain("ClientIp", entry.Properties.Keys);

        var rendered = entry.Rendered;
        Assert.DoesNotContain(apiKey, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(hmacKey, rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("198.51.100.7", rendered, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SecretFailureLogExcludesKubernetesBodyValueAndFingerprint()
    {
        const string rawSecret = "raw-secret-must-not-appear";
        const string fingerprint = "hmac-sha256:fingerprint-must-not-appear";
        var output = new CapturingLogger<AuditLogger>();
        var audit = CreateLogger(output, new DefaultHttpContext(), AuthenticationMode.None);
        var tool = new KubernetesGetTool(
            new SensitiveFailureReader(new KubernetesReadException(
                $"{{\"data\":{{\"password\":\"{rawSecret}\",\"fingerprint\":\"{fingerprint}\"}}}}",
                KubernetesErrorCategory.AccessDenied)),
            audit,
            NullLogger<KubernetesGetTool>.Instance);

        var exception = await Assert.ThrowsAsync<McpException>(() =>
            tool.GetAsync("secrets", "database", "credentials"));

        Assert.Equal("Access to the Kubernetes resource was denied.", exception.Message);
        var entry = Assert.Single(output.Entries);
        Assert.Equal("kubernetes_access_denied", entry.Properties["Category"]);
        Assert.DoesNotContain(rawSecret, entry.Rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(fingerprint, entry.Rendered, StringComparison.Ordinal);
        Assert.Null(entry.Exception);
    }

    [Fact]
    public void LogsCoordinateFreeApplicationAuthorizationDenial()
    {
        var output = new CapturingLogger<AuditLogger>();
        var audit = CreateLogger(output, new DefaultHttpContext(), AuthenticationMode.ApiKey);

        audit.LogMcpAccessDenied(new McpAccessDeniedAuditEvent(
            AuditCategories.AuthorizationDenied,
            StatusCodes.Status403Forbidden,
            TimeSpan.FromMilliseconds(4)));

        var entry = Assert.Single(output.Entries);
        Assert.Equal(AuditLogger.McpAccessDeniedEvent, entry.EventId);
        Assert.Equal("anonymous", entry.Properties["ClientIdentity"]);
        Assert.Equal("denied", entry.Properties["Result"]);
        Assert.Equal(AuditCategories.AuthorizationDenied, entry.Properties["Category"]);
        Assert.Equal(403, entry.Properties["StatusCode"]);
        Assert.DoesNotContain("Operation", entry.Properties.Keys);
        Assert.DoesNotContain("Resource", entry.Properties.Keys);
        Assert.DoesNotContain("Namespace", entry.Properties.Keys);
        Assert.DoesNotContain("ResourceName", entry.Properties.Keys);
    }

    [Fact]
    public void BoundsValuesStripsControlCharactersAndLoggingFailureNeverEscapes()
    {
        var output = new CapturingLogger<AuditLogger>();
        var unsafeValue = new string('x', 300) + "\r\nforged-entry";
        var context = new DefaultHttpContext { TraceIdentifier = unsafeValue };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("client_id", unsafeValue)],
            authenticationType: "ApiKey"));
        var audit = CreateLogger(output, context, AuthenticationMode.None);

        audit.LogKubernetesAccess(new KubernetesAuditEvent(
            unsafeValue,
            unsafeValue,
            unsafeValue,
            unsafeValue,
            unsafeValue,
            null,
            TimeSpan.Zero,
            unsafeValue));

        var entry = Assert.Single(output.Entries);
        foreach (var property in new[]
                 {
                     "ClientIdentity", "Operation", "Resource", "Namespace", "ResourceName",
                     "Result", "Category", "RequestId"
                 })
        {
            Assert.Equal(256, Assert.IsType<string>(entry.Properties[property]).Length);
        }
        Assert.DoesNotContain('\r', entry.Rendered);
        Assert.DoesNotContain('\n', entry.Rendered);

        var throwingAudit = CreateLogger(
            new ThrowingLogger<AuditLogger>(),
            context,
            AuthenticationMode.None);
        var exception = Record.Exception(() => throwingAudit.LogKubernetesAccess(new KubernetesAuditEvent(
            "LIST", "pods", "default", null, "failed", null, TimeSpan.Zero, "internal_error")));
        Assert.Null(exception);
    }

    private static AuditLogger CreateLogger(
        ILogger<AuditLogger> logger,
        HttpContext context,
        AuthenticationMode mode,
        DateTimeOffset? timestamp = null,
        string secretHmacKey = "") =>
        new(
            logger,
            new HttpContextAccessor { HttpContext = context },
            Options.Create(new KubeMcpOptions
            {
                SecretHmacKey = secretHmacKey,
                Authentication = new KubeMcpAuthenticationOptions { Mode = mode }
            }),
            new FixedTimeProvider(timestamp ?? DateTimeOffset.UnixEpoch));

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class SensitiveFailureReader(Exception exception) : IKubernetesReader
    {
        public Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken) =>
            Task.FromException<KubernetesReadResult>(exception);
    }

    internal sealed class CapturingLogger<T> : ILogger<T>
    {
        public System.Collections.Concurrent.ConcurrentQueue<LogEntry> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var properties = ((IEnumerable<KeyValuePair<string, object?>>)state!)
                .Where(property => property.Key != "{OriginalFormat}")
                .ToDictionary(property => property.Key, property => property.Value);
            Entries.Enqueue(new LogEntry(logLevel, eventId, properties, formatter(state, exception), exception));
        }
    }

    private sealed class ThrowingLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => throw new InvalidOperationException("logger-secret");
    }

    internal sealed record LogEntry(
        LogLevel Level,
        EventId EventId,
        IReadOnlyDictionary<string, object?> Properties,
        string Rendered,
        Exception? Exception);
}
