using System.Security.Claims;
using KubeMcp.Configuration;
using Microsoft.Extensions.Options;

namespace KubeMcp.Audit;

public sealed class AuditLogger(
    IAuditEventPublisher publisher,
    IHttpContextAccessor httpContextAccessor,
    IOptions<KubeMcpOptions> options,
    TimeProvider timeProvider) : IAuditLogger
{
    private const int MaximumValueLength = 256;
    internal static readonly EventId KubernetesAccessEvent = new(1000, "KubernetesAccess");
    internal static readonly EventId McpAccessDeniedEvent = new(1001, "McpAccessDenied");

    public void LogKubernetesAccess(KubernetesAuditEvent auditEvent)
    {
        var common = CommonFields();
        TryPublish(new AuditRecord(
            AuditEventType.KubernetesAccess,
            common.Timestamp,
            common.Identity,
            common.AuthenticationMethod,
            Safe(auditEvent.Operation),
            Safe(auditEvent.Resource),
            Safe(auditEvent.Namespace),
            Safe(auditEvent.Name ?? "-"),
            Safe(auditEvent.Result),
            Safe(auditEvent.Category),
            auditEvent.ObjectCount,
            auditEvent.Duration,
            common.RequestId,
            common.ClientIp,
            StatusCode: null));
    }

    public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent)
    {
        var common = CommonFields();
        TryPublish(new AuditRecord(
            AuditEventType.McpAccessDenied,
            common.Timestamp,
            common.Identity,
            common.AuthenticationMethod,
            Operation: null,
            Resource: null,
            Namespace: null,
            Name: null,
            Result: "denied",
            Category: Safe(auditEvent.Category),
            ObjectCount: null,
            auditEvent.Duration,
            common.RequestId,
            common.ClientIp,
            auditEvent.StatusCode));
    }

    private void TryPublish(AuditRecord record)
    {
        try
        {
            _ = publisher.TryPublish(record);
        }
        catch
        {
            // The production publisher is no-throw. Keep this final guard so a
            // replacement publisher can never alter the response or original error.
        }
    }

    private CommonAuditFields CommonFields()
    {
        var context = httpContextAccessor.HttpContext;
        return new CommonAuditFields(
            timeProvider.GetUtcNow(),
            Safe(ResolveIdentity(context?.User)),
            Safe(options.Value.Authentication.Mode.ToString()),
            Safe(context?.TraceIdentifier ?? "unknown"),
            Safe(context?.Connection.RemoteIpAddress?.ToString() ?? "unknown"));
    }

    private static string ResolveIdentity(ClaimsPrincipal? principal)
    {
        if (principal?.Identity?.IsAuthenticated != true)
        {
            return "anonymous";
        }

        return FirstClaim(principal, "client_id")
            ?? FirstClaim(principal, "azp")
            ?? FirstClaim(principal, ClaimTypes.NameIdentifier)
            ?? FirstClaim(principal, "sub")
            ?? principal.Identity.Name
            ?? "unknown";
    }

    private static string? FirstClaim(ClaimsPrincipal principal, string type)
    {
        var value = principal.FindFirst(type)?.Value;
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string Safe(string value)
    {
        var sanitized = string.Concat(value.Select(character =>
            char.IsControl(character) ? ' ' : character));
        return sanitized.Length <= MaximumValueLength
            ? sanitized
            : sanitized[..MaximumValueLength];
    }

    private sealed record CommonAuditFields(
        DateTimeOffset Timestamp,
        string Identity,
        string AuthenticationMethod,
        string RequestId,
        string ClientIp);
}
