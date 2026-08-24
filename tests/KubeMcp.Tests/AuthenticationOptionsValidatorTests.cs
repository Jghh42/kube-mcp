using KubeMcp.Configuration;

namespace KubeMcp.Tests;

public sealed class AuthenticationOptionsValidatorTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private readonly KubeMcpOptionsValidator validator = new();

    [Fact]
    public void NoneModeDoesNotRequireAuthenticationSecrets()
    {
        var result = validator.Validate(null, Options(new KubeMcpAuthenticationOptions
        {
            Mode = AuthenticationMode.None
        }));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void ApiKeyModeRejectsShortKeys()
    {
        var result = validator.Validate(null, Options(new KubeMcpAuthenticationOptions
        {
            Mode = AuthenticationMode.ApiKey,
            ApiKey = "too-short"
        }));

        Assert.True(result.Failed);
        Assert.Contains("at least 32 bytes", result.FailureMessage);
    }

    [Fact]
    public void OAuthModeRequiresHttpsAudienceAndPermission()
    {
        var insecure = validator.Validate(null, OAuthOptions("http://identity.test", "k-mcp", ["k-mcp:read"]));
        var missingAudience = validator.Validate(null, OAuthOptions("https://identity.test", "", ["k-mcp:read"]));
        var missingPermission = validator.Validate(null, OAuthOptions("https://identity.test", "k-mcp", []));

        Assert.Contains("must use HTTPS", insecure.FailureMessage);
        Assert.Contains("Audience is required", missingAudience.FailureMessage);
        Assert.Contains("at least one scope or role", missingPermission.FailureMessage);
    }

    private static KubeMcpOptions OAuthOptions(string authority, string audience, string[] scopes) =>
        Options(new KubeMcpAuthenticationOptions
        {
            Mode = AuthenticationMode.OAuthClientCredentials,
            OAuth = new OAuthOptions
            {
                Authority = authority,
                Audience = audience,
                RequiredScopes = scopes,
                RequiredRoles = []
            }
        });

    private static KubeMcpOptions Options(KubeMcpAuthenticationOptions authentication) => new()
    {
        SecretHmacKey = TestHmacKey,
        ResourcePolicy = new ResourcePolicyOptions { Mode = ResourcePolicyMode.AllowAll },
        Authentication = authentication
    };
}
