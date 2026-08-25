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

    [Fact]
    public void ForwardedHeadersRejectInvalidProxiesAndNetworks()
    {
        var badProxy = productionValidator.Validate(null, OptionsWithForwardedHeaders(knownProxies: ["not-an-ip"]));
        var badNetwork = productionValidator.Validate(null, OptionsWithForwardedHeaders(knownNetworks: ["10.0.0.0/not-a-cidr"]));

        Assert.Contains("KnownProxies contains invalid IP address", badProxy.FailureMessage);
        Assert.Contains("KnownNetworks contains invalid CIDR network", badNetwork.FailureMessage);
    }

    [Fact]
    public void ForwardedHeadersAcceptValidProxiesAndNetworks()
    {
        var result = productionValidator.Validate(null, OptionsWithForwardedHeaders(
            knownProxies: ["10.0.0.5", "192.168.1.1"],
            knownNetworks: ["10.0.0.0/8", "2001:db8::/32"]));

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    public void ForwardedHeadersRejectTrustAllNetworks(string network)
    {
        var result = productionValidator.Validate(
            null,
            OptionsWithForwardedHeaders(knownNetworks: [network]));

        Assert.Contains("must not trust every address", result.FailureMessage);
    }

    private static KubeMcpOptions OptionsWithForwardedHeaders(
        string[]? knownProxies = null,
        string[]? knownNetworks = null) =>
        new()
        {
            SecretHmacKey = TestHmacKey,
            AllowedResources = new Dictionary<string, KubernetesResourceOptions>
            {
                ["pods"] = new() { Group = "", Version = "v1", Resource = "pods", Kind = "Pod" }
            },
            Authentication = new KubeMcpAuthenticationOptions
            {
                Mode = AuthenticationMode.ApiKey,
                ApiKey = "stage-five-test-api-key-32-bytes-minimum"
            },
            ForwardedHeaders = new KubeMcpForwardedHeadersOptions
            {
                KnownProxies = knownProxies ?? [],
                KnownNetworks = knownNetworks ?? []
            }
        };

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
