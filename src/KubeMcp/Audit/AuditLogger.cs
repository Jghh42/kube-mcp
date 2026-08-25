using System.Security.Claims;
using KubeMcp.Configuration;
using Microsoft.Extensions.Options;

namespace KubeMcp.Audit;

public sealed class AuditLogger(
    ILogger<AuditLogger> logger,
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
        TryLog(() => logger.LogInformation(
            KubernetesAccessEvent,
            "Kubernetes audit: timestamp={Timestamp} client={ClientIdentity} authentication={AuthenticationMethod} operation={Operation} resource={Resource} namespace={Namespace} name={ResourceName} result={Result} objectCount={ObjectCount} category={Category} durationMs={DurationMs} requestId={RequestId}",
            common.Timestamp,
            common.Identity,
            common.AuthenticationMethod,
            Safe(auditEvent.Operation),
            Safe(auditEvent.Resource),
            Safe(auditEvent.Namespace),
            Safe(auditEvent.Name ?? "-"),
            Safe(auditEvent.Result),
            auditEvent.ObjectCount,
            Safe(auditEvent.Category),
            Math.Round(auditEvent.Duration.TotalMilliseconds, 2),
            common.RequestId));
    }

    public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent)
    {
        var common = CommonFields();
        TryLog(() => logger.LogInformation(
            McpAccessDeniedEvent,
            "MCP access-denial audit: timestamp={Timestamp} client={ClientIdentity} authentication={AuthenticationMethod} result={Result} category={Category} statusCode={StatusCode} durationMs={DurationMs} requestId={RequestId}",
            common.Timestamp,
            common.Identity,
            common.AuthenticationMethod,
            "denied",
            Safe(auditEvent.Category),
            auditEvent.StatusCode,
            Math.Round(auditEvent.Duration.TotalMilliseconds, 2),
            common.RequestId));
    }

    private static void TryLog(Action write)
    {
        try
        {
            write();
        }
        catch
        {
            // Logging is best effort and must never alter the response or original error.
        }
    }

    private CommonAuditFields CommonFields()
    {
        var context = httpContextAccessor.HttpContext;
        return new CommonAuditFields(
            timeProvider.GetUtcNow(),
            Safe(ResolveIdentity(context?.User)),
            Safe(options.Value.Authentication.Mode.ToString()),
            Safe(context?.TraceIdentifier ?? "unknown"));
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
        string RequestId);
}
