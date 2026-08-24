using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using KubeMcp.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace KubeMcp.Authentication;

internal static class ApiKeyAuthenticationDefaults
{
    public const string Scheme = "ApiKey";
}

internal sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> schemeOptions,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    IOptions<KubeMcpOptions> kubeMcpOptions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(schemeOptions, loggerFactory, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var values))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (values.Count != 1 ||
            !AuthenticationHeaderValue.TryParse(values[0], out var authorization) ||
            !string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(authorization.Parameter))
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid bearer authorization header."));
        }

        var supplied = Encoding.UTF8.GetBytes(authorization.Parameter);
        var expected = Encoding.UTF8.GetBytes(kubeMcpOptions.Value.Authentication.ApiKey);

        try
        {
            if (supplied.Length != expected.Length ||
                !CryptographicOperations.FixedTimeEquals(supplied, expected))
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid API key."));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(supplied);
            CryptographicOperations.ZeroMemory(expected);
        }

        var identity = new ClaimsIdentity(
            [new Claim("client_id", "static-api-key")],
            ApiKeyAuthenticationDefaults.Scheme,
            "client_id",
            ClaimTypes.Role);
        var ticket = new AuthenticationTicket(
            new ClaimsPrincipal(identity),
            ApiKeyAuthenticationDefaults.Scheme);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Bearer";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
