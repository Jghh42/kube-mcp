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
    public void WritesStructuredOAuthAuditEventWithAuthenticatedClientAndRequestDetails()
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
        var sink = new CapturingLogger<AuditLogger>();
        var logger = new AuditLogger(
            sink,
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
            "success",
            1,
            TimeSpan.FromMilliseconds(12.345)));

        var entry = Assert.Single(sink.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal(AuditLogger.KubernetesAccessEvent, entry.EventId);
        Assert.Equal(timestamp, entry.Properties["Timestamp"]);
        Assert.Equal("agent-production", entry.Properties["ClientIdentity"]);
        Assert.Equal("OAuthClientCredentials", entry.Properties["AuthenticationMethod"]);
        Assert.Equal("GET", entry.Properties["Operation"]);
        Assert.Equal("secrets", entry.Properties["Resource"]);
        Assert.Equal("database", entry.Properties["Namespace"]);
        Assert.Equal("credentials", entry.Properties["ResourceName"]);
        Assert.Equal("success", entry.Properties["Result"]);
        Assert.Equal(1, entry.Properties["ObjectCount"]);
        Assert.Equal(12.34, entry.Properties["DurationMs"]);
        Assert.Equal("request-123", entry.Properties["RequestId"]);
        Assert.Equal("192.0.2.10", entry.Properties["ClientIp"]);
    }

    [Fact]
    public void UsesAnonymousIdentityInNoAuthenticationModeAndSanitizesLogValues()
    {
        var sink = new CapturingLogger<AuditLogger>();
        var logger = new AuditLogger(
            sink,
            new HttpContextAccessor { HttpContext = new DefaultHttpContext() },
            Options.Create(new KubeMcpOptions()),
            new FixedTimeProvider(DateTimeOffset.UnixEpoch));

        logger.LogKubernetesAccess(new KubernetesAuditEvent(
            "LIST",
            "unknown\r\nforged-entry",
            "default",
            null,
            "failed",
            null,
            TimeSpan.Zero));

        var properties = Assert.Single(sink.Entries).Properties;
        Assert.Equal("anonymous", properties["ClientIdentity"]);
        Assert.Equal("None", properties["AuthenticationMethod"]);
        Assert.Equal("unknown  forged-entry", properties["Resource"]);
        Assert.Equal("-", properties["ResourceName"]);
        Assert.Null(properties["ObjectCount"]);
    }

    private sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => value;
    }

    private sealed class CapturingLogger<T> : ILogger<T>
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
            Entries.Add(new LogEntry(logLevel, eventId, properties));
        }
    }

    private sealed record LogEntry(
        LogLevel Level,
        EventId EventId,
        IReadOnlyDictionary<string, object?> Properties);
}
