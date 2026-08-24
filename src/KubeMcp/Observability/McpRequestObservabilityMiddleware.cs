using System.Diagnostics;
using KubeMcp.Audit;
using Microsoft.AspNetCore.Http.Timeouts;

namespace KubeMcp.Observability;

/// <summary>
/// Observes only the /mcp pipeline branch. It never reads or buffers the request
/// body; pre-tool denials are audited without Kubernetes coordinates.
/// </summary>
internal sealed class McpRequestObservabilityMiddleware(
    RequestDelegate next,
    IAuditLogger auditLogger,
    KubeMcpTelemetry telemetry)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var state = new McpRequestState();
        context.Features.Set(state);
        var stopwatch = Stopwatch.StartNew();
        var hostingActivity = Activity.Current;
        var activity = telemetry.StartMcpRequest();
        var unhandledFailure = false;

        try
        {
            await next(context).ConfigureAwait(false);
        }
        catch
        {
            unhandledFailure = true;
            throw;
        }
        finally
        {
            stopwatch.Stop();
            var timeoutFeature = context.Features.Get<IHttpRequestTimeoutFeature>();
            var category = ResolveCategory(context, state, timeoutFeature, unhandledFailure);
            // A non-started response will become the configured 504 in the outer
            // request-timeout middleware. If Streamable HTTP already started, keep
            // the actual status and rely on server_timeout as the outcome signal.
            var statusCode = category switch
            {
                AuditCategories.ServerTimeout when !context.Response.HasStarted =>
                    StatusCodes.Status504GatewayTimeout,
                AuditCategories.InternalError when unhandledFailure &&
                                                   !context.Response.HasStarted &&
                                                   context.Response.StatusCode < 400 =>
                    StatusCodes.Status500InternalServerError,
                _ => context.Response.StatusCode
            };

            if (category is AuditCategories.AuthenticationDenied or AuditCategories.AuthorizationDenied)
            {
                try
                {
                    auditLogger.LogMcpAccessDenied(new McpAccessDeniedAuditEvent(
                        category,
                        statusCode,
                        stopwatch.Elapsed));
                }
                catch
                {
                    // Audit integration is explicitly best effort and must never
                    // replace an authentication/authorization response.
                }
            }

            try
            {
                telemetry.RecordMcpRequest(stopwatch.Elapsed, statusCode, category);
                KubeMcpTelemetry.CompleteActivity(activity, category);
            }
            finally
            {
                activity?.Dispose();
                Activity.Current = hostingActivity;
            }
        }
    }

    private static string ResolveCategory(
        HttpContext context,
        McpRequestState state,
        IHttpRequestTimeoutFeature? timeoutFeature,
        bool unhandledFailure)
    {
        if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
        {
            return AuditCategories.AuthenticationDenied;
        }

        if (context.Response.StatusCode == StatusCodes.Status403Forbidden)
        {
            return AuditCategories.AuthorizationDenied;
        }

        // RequestTimeoutToken is the server deadline token, while RequestAborted
        // is linked to both the caller disconnect and that deadline. Check the
        // dedicated deadline token first to preserve the distinction.
        if (timeoutFeature?.RequestTimeoutToken.IsCancellationRequested == true)
        {
            return AuditCategories.ServerTimeout;
        }

        if (context.RequestAborted.IsCancellationRequested)
        {
            return AuditCategories.ClientCancelled;
        }

        if (unhandledFailure || context.Response.StatusCode >= 500)
        {
            return AuditCategories.InternalError;
        }

        if (context.Response.StatusCode >= 400)
        {
            return AuditCategories.InvalidRequest;
        }

        return state.Category;
    }
}
