using Microsoft.AspNetCore.Http.Features;

namespace KubeMcp.Mcp;

/// <summary>
/// Applies a small MCP-only wire-body cap before admission, authentication,
/// observability, and protocol parsing. Declared oversized requests are rejected
/// without reading or logging their bodies; Kestrel enforces the same cap while
/// reading requests without a Content-Length header.
/// </summary>
internal sealed class McpRequestBodyLimitMiddleware(RequestDelegate next)
{
    internal const long MaximumBodyBytes = 64 * 1024;

    public async Task InvokeAsync(HttpContext context)
    {
        var maxBodySizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        var effectiveLimit = MaximumBodyBytes;
        if (maxBodySizeFeature is { IsReadOnly: false })
        {
            if (maxBodySizeFeature.MaxRequestBodySize is { } existingLimit)
            {
                effectiveLimit = Math.Min(existingLimit, MaximumBodyBytes);
            }

            // Never weaken a stricter host- or endpoint-level server limit.
            maxBodySizeFeature.MaxRequestBodySize = effectiveLimit;
        }

        if (context.Request.ContentLength > effectiveLimit)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        try
        {
            await next(context).ConfigureAwait(false);
        }
        catch (BadHttpRequestException exception)
            when (exception.StatusCode == StatusCodes.Status413PayloadTooLarge &&
                  !context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        }
    }
}
