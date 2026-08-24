using System.Threading.RateLimiting;
using KubeMcp.Configuration;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace KubeMcp.Mcp;

/// <summary>
/// A single process-wide partition bounds aggregate MCP and Kubernetes work.
/// The middleware is deliberately ordered after authentication/authorization so
/// invalid credentials cannot occupy permits or queue entries.
/// </summary>
internal sealed class McpConcurrencyRateLimiterOptionsSetup(IOptions<KubeMcpOptions> options)
    : IConfigureOptions<RateLimiterOptions>
{
    public const string PolicyName = "McpConcurrency";

    public void Configure(RateLimiterOptions rateLimiterOptions)
    {
        var concurrency = options.Value.McpConcurrency;
        rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        rateLimiterOptions.AddConcurrencyLimiter(PolicyName, limiterOptions =>
        {
            limiterOptions.PermitLimit = concurrency.PermitLimit;
            limiterOptions.QueueLimit = concurrency.QueueLimit;
            limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        });
    }
}
