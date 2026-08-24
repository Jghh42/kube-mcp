using KubeMcp.Configuration;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.Extensions.Options;

namespace KubeMcp.Mcp;

internal sealed class McpRequestTimeoutOptionsSetup(IOptions<KubeMcpOptions> options)
    : IConfigureOptions<RequestTimeoutOptions>
{
    public const string PolicyName = "OverallMcpRequest";

    public void Configure(RequestTimeoutOptions timeoutOptions)
    {
        timeoutOptions.AddPolicy(PolicyName, new RequestTimeoutPolicy
        {
            Timeout = TimeSpan.FromSeconds(options.Value.OverallMcpRequestTimeoutSeconds),
            TimeoutStatusCode = StatusCodes.Status504GatewayTimeout
        });
    }
}
