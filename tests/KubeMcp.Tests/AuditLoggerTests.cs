using System.Net;
using System.Security.Claims;
using KubeMcp.Audit;
using KubeMcp.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace KubeMcp.Tests;

public sealed class AuditLoggerTests
{
    [Fact]
    public void PublishesSanitizedOAuthKubernetesAuditRecord()
    {
        var timestamp = new DateTimeOffset(2026, 3, 20, 12, 34, 56, TimeSpan.Zero);
        var context = new DefaultHttpContext
        {
            TraceIdentifier = "request-123"
        };
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("client_id", "agent-production")],
            authenticationType: "Bearer"));
        var publisher = new CapturingPublisher();
        var logger = new AuditLogger(
            publisher,
            new HttpContextAccessor { HttpContext = context },
            Options.Create(new KubeMcpOptions
            {
                Authentication = new KubeMcpAuthenticationOptions
                {
                    Mode = AuthenticationMode.OAuthClientCredentials
                }
            }),
            new FixedTimeProvider(timestamp));

        logger.LogKubernetesAccess(new KubernetesAuditEvent(
            "GET",
            "secrets",
            "database",
            "credentials",
            "failed",
            null,
            TimeSpan.FromMilliseconds(12.345),
            "kubernetes_access_denied"));

        var record = Assert.Single(publisher.Records);
        Assert.Equal(AuditEventType.KubernetesAccess, record.EventType);
        Assert.Equal(timestamp, record.Timestamp);
        Assert.Equal("agent-production", record.ClientIdentity);
        Assert.Equal("OAuthClientCredentials", record.AuthenticationMethod);
        Assert.Equal("GET", record.Operation);
        Assert.Equal("secrets", record.Resource);
        Assert.Equal("database", record.Namespace);
        Assert.Equal("credentials", record.Name);
        Assert.Equal("failed", record.Result);
        Assert.Equal("kubernetes_access_denied", record.Category);
        Assert.Null(record.ObjectCount);
        Assert.Equal("request-123", record.RequestId);
        Assert.Equal("192.0.2.10", record.ClientIp);
    }

    [Fact]
    public void PublishesCoordinateFreeAuthenticationDenial()
    {
        var publisher = new CapturingPublisher();
        var logger = new AuditLogger(
            publisher,
            new HttpContextAccessor { HttpContext = new DefaultHttpContext() },
            Options.Create(new KubeMcpOptions
            {
                Authentication = new KubeMcpAuthenticationOptions
                {
                    Mode = AuthenticationMode.ApiKey
                }
            }),
            new FixedTimeProvider(DateTimeOffset.UnixEpoch));

        logger.LogMcpAccessDenied(new McpAccessDeniedAuditEvent(
            AuditCategories.AuthenticationDenied,
            StatusCodes.Status401Unauthorized,
            TimeSpan.FromMilliseconds(4)));

        var record = Assert.Single(publisher.Records);
        Assert.Equal(AuditEventType.McpAccessDenied, record.EventType);
        Assert.Equal("anonymous", record.ClientIdentity);
        Assert.Equal("denied", record.Result);
        Assert.Equal(AuditCategories.AuthenticationDenied, record.Category);
        Assert.Equal(401, record.StatusCode);
        Assert.Null(record.Operation);
        Assert.Null(record.Resource);
        Assert.Null(record.Namespace);
        Assert.Null(record.Name);
    }

    [Fact]
    public void SanitizesControlCharactersAndPublisherFailureNeverEscapes()
    {
        var publisher = new CapturingPublisher();
        var contextAccessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext() };
        var options = Options.Create(new KubeMcpOptions
        {
            Authentication = new KubeMcpAuthenticationOptions { Mode = AuthenticationMode.None }
        });
        var logger = new AuditLogger(
            publisher,
            contextAccessor,
            options,
            new FixedTimeProvider(DateTimeOffset.UnixEpoch));

        logger.LogKubernetesAccess(new KubernetesAuditEvent(
            "LIST",
            "unknown\r\nforged-entry",
            "default",
            null,
            "failed",
            null,
            TimeSpan.Zero,
            "invalid_request"));

        Assert.Equal("unknown  forged-entry", Assert.Single(publisher.Records).Resource);

        var throwingLogger = new AuditLogger(
            new ThrowingPublisher(),
            contextAccessor,
            options,
            new FixedTimeProvider(DateTimeOffset.UnixEpoch));
        var exception = Record.Exception(() => throwingLogger.LogKubernetesAccess(new KubernetesAuditEvent(
            "LIST", "pods", "default", null, "failed", null, TimeSpan.Zero, "internal_error")));
        Assert.Null(exception);
    }

    [Fact]
    public async Task StructuredLoggerSinkRetainsDefaultEventShapeAndCategory()
    {
        var logger = new CapturingLogger<StructuredLoggerAuditSink>();
        var sink = new StructuredLoggerAuditSink(logger);
        var record = new AuditRecord(
            AuditEventType.KubernetesAccess,
            DateTimeOffset.UnixEpoch,
            "anonymous",
            "None",
            "LIST",
            "pods",
            "default",
            "-",
            "success",
            "success",
            2,
            TimeSpan.FromMilliseconds(12.345),
            "request-1",
            "127.0.0.1",
            null);

        await sink.WriteAsync(record, CancellationToken.None);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(AuditLogger.KubernetesAccessEvent, entry.EventId);
        Assert.Equal("success", entry.Properties["Category"]);
        Assert.Equal(12.34, entry.Properties["DurationMs"]);
        Assert.Equal(2, entry.Properties["ObjectCount"]);
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class CapturingPublisher : IAuditEventPublisher
    {
        public List<AuditRecord> Records { get; } = [];

        public bool TryPublish(AuditRecord record)
        {
            Records.Add(record);
            return true;
        }
    }

    private sealed class ThrowingPublisher : IAuditEventPublisher
    {
        public bool TryPublish(AuditRecord record) => throw new InvalidOperationException("sink-secret");
    }

    internal sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<LogEntry> Entries { get; } = [];

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
            Entries.Add(new LogEntry(logLevel, eventId, properties, exception));
        }
    }

    internal sealed record LogEntry(
        LogLevel Level,
        EventId EventId,
        IReadOnlyDictionary<string, object?> Properties,
        Exception? Exception);
}
