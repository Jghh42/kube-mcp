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
        try
        {
            var context = httpContextAccessor.HttpContext;
            logger.LogInformation(
                KubernetesAccessEvent,
                "Kubernetes audit: timestamp={Timestamp} client={ClientIdentity} authentication={AuthenticationMethod} operation={Operation} resource={Resource} namespace={Namespace} name={ResourceName} result={Result} objectCount={ObjectCount} category={Category} durationMs={DurationMs} requestId={RequestId}",
                timeProvider.GetUtcNow(),
                Safe(ResolveIdentity(context?.User)),
                Safe(options.Value.Authentication.Mode.ToString()),
                Safe(auditEvent.Operation),
                Safe(auditEvent.Resource),
                Safe(auditEvent.Namespace),
                Safe(auditEvent.Name ?? "-"),
                Safe(auditEvent.Result),
                auditEvent.ObjectCount,
                Safe(auditEvent.Category),
                Math.Round(auditEvent.Duration.TotalMilliseconds, 2),
                Safe(context?.TraceIdentifier ?? "unknown"));
        }
        catch
        {
            // Logging is best effort and must never alter the response or original error.
        }
    }

    // The API-key handler is the only authentication scheme and always sets client_id.
    private static string ResolveIdentity(ClaimsPrincipal? principal) =>
        principal?.Identity?.IsAuthenticated != true
            ? "anonymous"
            : principal.FindFirst("client_id")?.Value is { Length: > 0 } clientId
                ? clientId
                : "unknown";

    // Truncate before sanitizing so oversized caller values are never fully copied.
    private static string Safe(string value) =>
        string.Concat(value[..Math.Min(value.Length, MaximumValueLength)].Select(character =>
            char.IsControl(character) ? ' ' : character));
}
