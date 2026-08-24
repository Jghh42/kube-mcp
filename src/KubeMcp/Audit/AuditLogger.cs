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

    public void LogKubernetesAccess(KubernetesAuditEvent auditEvent)
    {
        var context = httpContextAccessor.HttpContext;
        var identity = ResolveIdentity(context?.User);
        var authenticationMethod = options.Value.Authentication.Mode.ToString();
        var clientIp = context?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var requestId = context?.TraceIdentifier ?? "unknown";

        logger.LogInformation(
            KubernetesAccessEvent,
            "Kubernetes audit: timestamp={Timestamp} client={ClientIdentity} authentication={AuthenticationMethod} operation={Operation} resource={Resource} namespace={Namespace} name={ResourceName} result={Result} objectCount={ObjectCount} durationMs={DurationMs} requestId={RequestId} clientIp={ClientIp}",
            timeProvider.GetUtcNow(),
            Safe(identity),
            authenticationMethod,
            Safe(auditEvent.Operation),
            Safe(auditEvent.Resource),
            Safe(auditEvent.Namespace),
            Safe(auditEvent.Name ?? "-"),
            Safe(auditEvent.Result),
            auditEvent.ObjectCount,
            Math.Round(auditEvent.Duration.TotalMilliseconds, 2),
            Safe(requestId),
            Safe(clientIp));
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
}
