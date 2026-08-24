using System.Threading.RateLimiting;
using KubeMcp.Configuration;
using Microsoft.Extensions.Options;

namespace KubeMcp.Mcp;

/// <summary>
/// Cheap process-wide admission bound placed before authentication and request
/// observability. It prevents credential floods from creating unbounded JWT,
/// API-key, or per-request audit work. The separate endpoint rate limiter remains
/// the smaller, oldest-first bound for authenticated MCP/Kubernetes execution.
/// </summary>
internal sealed class McpPreAuthenticationAdmissionMiddleware(
    RequestDelegate next,
    McpPreAuthenticationAdmissionGate gate)
{
    public async Task InvokeAsync(HttpContext context)
    {
        using var lease = await gate
            .AcquireAsync(context.RequestAborted)
            .ConfigureAwait(false);
        if (!lease.IsAcquired)
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            return;
        }

        await next(context).ConfigureAwait(false);
    }
}

internal sealed class McpPreAuthenticationAdmissionGate : IDisposable
{
    private readonly ConcurrencyLimiter limiter;

    public McpPreAuthenticationAdmissionGate(IOptions<KubeMcpOptions> options)
    {
        var admission = options.Value.McpAdmission;
        limiter = new ConcurrencyLimiter(new ConcurrencyLimiterOptions
        {
            PermitLimit = admission.PermitLimit,
            QueueLimit = admission.QueueLimit,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    }

    public ValueTask<RateLimitLease> AcquireAsync(CancellationToken cancellationToken) =>
        limiter.AcquireAsync(permitCount: 1, cancellationToken);

    public void Dispose() => limiter.Dispose();
}
