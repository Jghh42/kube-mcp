using System.Diagnostics;

namespace KubeMcp.Audit;

/// <summary>
/// Audits application-owned authorization denials on the MCP endpoint without
/// reading the request body or inventing Kubernetes resource coordinates.
/// Authentication failures are left to ASP.NET Core and infrastructure access logs.
/// </summary>
internal sealed class McpAccessAuditMiddleware(
    RequestDelegate next,
    IAuditLogger auditLogger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();

        try
        {
            await next(context).ConfigureAwait(false);
        }
        finally
        {
            stopwatch.Stop();
            var category = context.Response.StatusCode == StatusCodes.Status403Forbidden
                ? AuditCategories.AuthorizationDenied
                : null;

            if (category is not null)
            {
                try
                {
                    auditLogger.LogMcpAccessDenied(new McpAccessDeniedAuditEvent(
                        category,
                        context.Response.StatusCode,
                        stopwatch.Elapsed));
                }
                catch
                {
                    // Audit logging is explicitly best effort and must never
                    // replace the authorization response.
                }
            }
        }
    }
}
