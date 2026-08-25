using KubeMcp.Configuration;
using Microsoft.AspNetCore.Authentication;

namespace KubeMcp.Authentication;

internal static class AuthenticationConfiguration
{
    public const string McpAccessPolicy = "McpAccess";

    public static AuthenticationMode AddKubeMcpAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var authentication = configuration
            .GetSection($"{KubeMcpOptions.SectionName}:Authentication")
            .Get<KubeMcpAuthenticationOptions>() ?? new KubeMcpAuthenticationOptions();

        switch (authentication.Mode)
        {
            case AuthenticationMode.None:
                services.AddAuthentication();
                break;

            case AuthenticationMode.ApiKey:
                services
                    .AddAuthentication(ApiKeyAuthenticationDefaults.Scheme)
                    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                        ApiKeyAuthenticationDefaults.Scheme,
                        _ => { });
                break;

            default:
                services.AddAuthentication();
                break;
        }

        services.AddAuthorization(options =>
        {
            options.AddPolicy(McpAccessPolicy, policy => policy.RequireAuthenticatedUser());
        });

        return authentication.Mode;
    }
}
