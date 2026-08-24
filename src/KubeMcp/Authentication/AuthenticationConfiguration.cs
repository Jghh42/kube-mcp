using KubeMcp.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

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

            case AuthenticationMode.OAuthClientCredentials:
                var oauth = authentication.OAuth;
                services
                    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.Authority = oauth.Authority.TrimEnd('/');
                        options.Audience = oauth.Audience;
                        options.RequireHttpsMetadata = oauth.RequireHttpsMetadata;
                        options.MapInboundClaims = false;
                        options.SaveToken = false;
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidateAudience = true,
                            ValidateLifetime = true,
                            RequireExpirationTime = true,
                            RequireSignedTokens = true,
                            ValidateIssuerSigningKey = true,
                            ClockSkew = TimeSpan.FromSeconds(oauth.ClockSkewSeconds),
                            NameClaimType = "client_id",
                            RoleClaimType = "roles"
                        };
                    });
                break;

            default:
                services.AddAuthentication();
                break;
        }

        services.AddAuthorization(options =>
        {
            options.AddPolicy(McpAccessPolicy, policy =>
            {
                policy.RequireAuthenticatedUser();
                if (authentication.Mode == AuthenticationMode.OAuthClientCredentials)
                {
                    policy.RequireAssertion(context =>
                        OAuthClaimEvaluator.HasAllScopes(context.User, authentication.OAuth.RequiredScopes) &&
                        OAuthClaimEvaluator.HasAllRoles(
                            context.User,
                            authentication.OAuth.RequiredRoles,
                            authentication.OAuth.Audience));
                }
            });
        });

        return authentication.Mode;
    }
}
