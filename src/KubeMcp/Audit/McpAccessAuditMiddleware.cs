using System.Diagnostics;

namespace KubeMcp.Audit;

/// <summary>
/// Audits authentication and authorization denials on the MCP endpoint without
/// reading the request body or inventing Kubernetes resource coordinates.
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
            var category = context.Response.StatusCode switch
            {
                StatusCodes.Status401Unauthorized => AuditCategories.AuthenticationDenied,
                StatusCodes.Status403Forbidden => AuditCategories.AuthorizationDenied,
                _ => null
            };

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
                    // Audit integration is explicitly best effort and must never
                    // replace an authentication/authorization response.
                }
            }
        }
    }
}
