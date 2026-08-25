using KubeMcp.Configuration;

namespace KubeMcp.Tests;

public sealed class AuthenticationOptionsValidatorTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private readonly KubeMcpOptionsValidator developmentValidator = new(new TestHostEnvironment("Development"));
    private readonly KubeMcpOptionsValidator productionValidator = new(new TestHostEnvironment("Production"));

    [Fact]
    public void AuthenticationDefaultsFailClosed()
    {
        Assert.Equal(AuthenticationMode.ApiKey, new KubeMcpAuthenticationOptions().Mode);
    }

    [Fact]
    public void NoneModeIsAllowedInDevelopmentWithoutAuthenticationSecrets()
    {
        var result = developmentValidator.Validate(null, Options(new KubeMcpAuthenticationOptions
        {
            Mode = AuthenticationMode.None
        }));

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void NoneModeIsRejectedInProduction()
    {
        var result = productionValidator.Validate(null, Options(new KubeMcpAuthenticationOptions
        {
            Mode = AuthenticationMode.None
        }));

        Assert.True(result.Failed);
        Assert.Contains("not permitted outside the Development environment", result.FailureMessage);
        Assert.Contains("Set Mode to ApiKey", result.FailureMessage);
    }

    [Fact]
    public void ApiKeyModeRejectsShortKeys()
    {
        var result = developmentValidator.Validate(null, Options(new KubeMcpAuthenticationOptions
        {
            Mode = AuthenticationMode.ApiKey,
            ApiKey = "too-short"
        }));

        Assert.True(result.Failed);
        Assert.Contains("at least 32 bytes", result.FailureMessage);
    }

    private static KubeMcpOptions Options(KubeMcpAuthenticationOptions authentication) => new()
    {
        SecretHmacKey = TestHmacKey,
        AllowedResources = new Dictionary<string, KubernetesResourceOptions>
        {
            ["pods"] = new() { Group = "", Version = "v1", Resource = "pods", Kind = "Pod" }
        },
        Authentication = authentication
    };
}
