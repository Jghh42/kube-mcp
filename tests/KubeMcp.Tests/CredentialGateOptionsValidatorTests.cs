using KubeMcp.Configuration;

namespace KubeMcp.Tests;

public sealed class CredentialGateOptionsValidatorTests
{
    private const string HmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private readonly KubeMcpOptionsValidator validator = new(new TestHostEnvironment("Development"));

    [Fact]
    public void GateIsDisabledByDefault()
    {
        Assert.False(new CredentialGateOptions().Enabled);
        Assert.Null(new CredentialGateOptions().ProbabilityThreshold);
        Assert.Equal(5, new CredentialGateOptions().AttemptTimeoutSeconds);
        Assert.Equal(30, new KubeMcpOptions().OverallMcpRequestTimeoutSeconds);
    }

    [Fact]
    public void AcceptsCompleteEnabledConfiguration()
    {
        Assert.True(validator.Validate(null, Options(new CredentialGateOptions
        {
            Enabled = true,
            Endpoint = "https://decision-model.example/v1/systemone",
            RequestModel = "decision",
            ExpectedResponseModel = "physical-model",
            ProbabilityThreshold = 0.20,
            TotalTimeoutSeconds = 15
        }, overallTimeout: 35)).Succeeded);
    }

    [Theory]
    [InlineData("https://decision-model.example/v1/systemone")]
    [InlineData("http://decision-model.example/api/decision")]
    [InlineData("https://decision-model.example/")]
    public void AcceptsConfiguredEndpointPaths(string endpoint)
    {
        Assert.True(validator.Validate(null, Options(ValidGate() with { Endpoint = endpoint })).Succeeded);
    }

    [Theory]
    [InlineData(null, "RequestModel")]
    [InlineData("", "RequestModel")]
    public void RequiresRequestModel(string? model, string expected)
    {
        var result = validator.Validate(null, Options(ValidGate() with { RequestModel = model }));
        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage);
    }

    [Theory]
    [InlineData(null, "Endpoint")]
    [InlineData("", "Endpoint")]
    [InlineData("/api/decision", "Endpoint")]
    [InlineData("https://user@decision-model.example/api/decision", "Endpoint")]
    [InlineData("https://decision-model.example/api/decision?q=1", "Endpoint")]
    [InlineData("https://decision-model.example/api/decision#fragment", "Endpoint")]
    [InlineData("ftp://decision-model.example/api/decision", "Endpoint")]
    [InlineData("file:///api/decision", "Endpoint")]
    public void RejectsInvalidEndpoint(string? endpoint, string expected)
    {
        var result = validator.Validate(null, Options(ValidGate() with { Endpoint = endpoint }));
        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage);
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(-0.01)]
    [InlineData(0.5)]
    public void RejectsUnsafeThreshold(double threshold)
    {
        var result = validator.Validate(null, Options(ValidGate() with { ProbabilityThreshold = threshold }));
        Assert.True(result.Failed);
        Assert.Contains("ProbabilityThreshold", result.FailureMessage);
    }

    [Fact]
    public void RejectsExplicitlyEmptyPromptAndInsufficientOverallTimeout()
    {
        var emptyPrompt = validator.Validate(null, Options(ValidGate() with { Prompt = "" }));
        Assert.Contains("Prompt", emptyPrompt.FailureMessage);

        var timeout = validator.Validate(null, Options(ValidGate(), overallTimeout: 30));
        Assert.Contains("plus the enabled credential gate", timeout.FailureMessage);
    }

    [Fact]
    public void RejectsEveryNestedNumericBoundIncludingWhenDisabled()
    {
        var invalid = new (CredentialGateOptions Gate, string Field)[]
        {
            (ValidGate() with { RetryCount = 3 }, "RetryCount"),
            (ValidGate() with { ChunkSizeBytes = 255 }, "ChunkSizeBytes"),
            (ValidGate() with { ScalarOverlapBytes = 1025 }, "ScalarOverlapBytes"),
            (ValidGate() with { TotalTimeoutSeconds = 0 }, "TotalTimeoutSeconds"),
            (ValidGate() with { AttemptTimeoutSeconds = 0 }, "AttemptTimeoutSeconds"),
            (ValidGate() with { AttemptTimeoutSeconds = 16 }, "AttemptTimeoutSeconds"),
            (ValidGate() with { MaxInputTokens = 0 }, "MaxInputTokens"),
            (ValidGate() with { MaxInputTokens = 1_000_001 }, "MaxInputTokens"),
            (ValidGate() with { MaxResponseBodyBytes = 1023 }, "MaxResponseBodyBytes"),
            (new CredentialGateOptions { Enabled = false, RetryCount = 3 }, "RetryCount")
        };

        foreach (var (gate, field) in invalid)
        {
            var result = validator.Validate(null, Options(gate));
            Assert.True(result.Failed);
            Assert.Contains(field, result.FailureMessage);
        }
    }

    [Fact]
    public void EnforcesTrustedConfigurationLengthBoundsWhileAllowingEmptyApiKey()
    {
        Assert.True(validator.Validate(null, Options(ValidGate() with { ApiKey = "" })).Succeeded);

        var invalid = new (CredentialGateOptions Gate, string Field)[]
        {
            (ValidGate() with { ApiKey = new string('é', 4097) }, "ApiKey"),
            (ValidGate() with { Endpoint = "https://decision-model.example/" + new string('x', 2040) + "/systemone" }, "length"),
            (ValidGate() with { RequestModel = new string('m', 257) }, "length"),
            (ValidGate() with { ExpectedResponseModel = new string('m', 257) }, "length"),
            (ValidGate() with { Prompt = new string('p', 16_385) }, "length")
        };

        foreach (var (gate, field) in invalid)
        {
            var result = validator.Validate(null, Options(gate));
            Assert.True(result.Failed);
            Assert.Contains(field, result.FailureMessage, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static CredentialGateOptions ValidGate() => new()
    {
        Enabled = true,
        Endpoint = "https://decision-model.example/systemone",
        RequestModel = "decision",
        ExpectedResponseModel = "physical-model",
        ProbabilityThreshold = 0.20,
        TotalTimeoutSeconds = 15
    };

    private static KubeMcpOptions Options(CredentialGateOptions gate, int overallTimeout = 35) => new()
    {
        SecretHmacKey = HmacKey,
        AllowedResources = new Dictionary<string, KubernetesResourceOptions>
        {
            ["pods"] = new() { Group = "", Version = "v1", Resource = "pods", Kind = "Pod" }
        },
        Authentication = new KubeMcpAuthenticationOptions { Mode = AuthenticationMode.None },
        CredentialGate = gate,
        OverallMcpRequestTimeoutSeconds = overallTimeout
    };
}
