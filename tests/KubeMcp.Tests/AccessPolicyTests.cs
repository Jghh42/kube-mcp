using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using Microsoft.Extensions.Options;

namespace KubeMcp.Tests;

public sealed class ResourceAllowlistTests
{
    [Fact]
    public void ResolvesOnlyExplicitlyConfiguredResourceNames()
    {
        var allowlist = new ResourceAllowlist(Options.Create(OptionsWithResources(
            new Dictionary<string, KubernetesResourceOptions>
            {
                ["pods"] = Resource("", "v1", "pods", "Pod")
            })));

        var descriptor = allowlist.Resolve("PODS");

        Assert.Equal("pods", descriptor.QualifiedName);
        var exception = Assert.Throws<KubernetesReadException>(() => allowlist.Resolve("jobs"));
        Assert.Contains("not included in the configured resource allowlist", exception.Message);
    }

    [Fact]
    public void ResolvesExplicitCrdMapping()
    {
        var allowlist = new ResourceAllowlist(Options.Create(OptionsWithResources(
            new Dictionary<string, KubernetesResourceOptions>
            {
                ["clusters.postgresql.cnpg.io"] =
                    Resource("postgresql.cnpg.io", "v1", "clusters", "Cluster")
            })));

        var descriptor = allowlist.Resolve("clusters.postgresql.cnpg.io");

        Assert.Equal("postgresql.cnpg.io", descriptor.Group);
        Assert.Equal("v1", descriptor.Version);
        Assert.Equal("clusters", descriptor.Resource);
        Assert.Equal("Cluster", descriptor.Kind);
    }

    internal static KubeMcpOptions OptionsWithResources(
        Dictionary<string, KubernetesResourceOptions> resources,
        NamespacePolicyOptions? namespacePolicy = null) => new()
        {
            SecretHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            AllowedResources = resources,
            NamespacePolicy = namespacePolicy ?? new NamespacePolicyOptions(),
            Authentication = new KubeMcpAuthenticationOptions
            {
                Mode = AuthenticationMode.ApiKey,
                ApiKey = "stage-one-test-api-key-32-bytes-minimum"
            }
        };

    internal static KubernetesResourceOptions Resource(
        string group,
        string version,
        string resource,
        string kind) => new()
        {
            Group = group,
            Version = version,
            Resource = resource,
            Kind = kind
        };
}

public sealed class NamespaceAccessPolicyTests
{
    [Fact]
    public void BlacklistDeniesConfiguredNamespacesAndAllowsNewNamespaces()
    {
        var policy = Policy(new NamespacePolicyOptions
        {
            Mode = NamespacePolicyMode.Blacklist,
            DeniedNamespaces = ["kube-system", "private-system"]
        });

        var exception = Assert.Throws<KubernetesReadException>(
            () => policy.EnsureStaticallyAllowed("kube-system"));
        Assert.Contains("configured namespace blacklist", exception.Message);
        policy.EnsureStaticallyAllowed("new-application-namespace");
        Assert.False(policy.RequiresLabelCheck);
    }

    [Fact]
    public void LabelSelectorModeRequiresAnApiMatch()
    {
        var policy = Policy(new NamespacePolicyOptions
        {
            Mode = NamespacePolicyMode.LabelSelector,
            LabelSelector = "platform.example.com/group in (production,staging)"
        });

        policy.EnsureStaticallyAllowed("production-api");
        Assert.True(policy.RequiresLabelCheck);
        Assert.Equal(
            "platform.example.com/group in (production,staging)",
            policy.LabelSelector);
        policy.EnsureLabelCheckMatched("production-api", matched: true);
        var exception = Assert.Throws<KubernetesReadException>(
            () => policy.EnsureLabelCheckMatched("unlabelled", matched: false));
        Assert.Contains("does not match the configured namespace label selector", exception.Message);
    }

    private static NamespaceAccessPolicy Policy(NamespacePolicyOptions namespacePolicy) =>
        new(Options.Create(ResourceAllowlistTests.OptionsWithResources(
            new Dictionary<string, KubernetesResourceOptions>
            {
                ["pods"] = ResourceAllowlistTests.Resource("", "v1", "pods", "Pod")
            },
            namespacePolicy)));
}

public sealed class KubeMcpOptionsValidatorTests
{
    private readonly KubeMcpOptionsValidator validator =
        new(new TestHostEnvironment("Production"));

    [Fact]
    public void AcceptsValidBlacklistConfiguration()
    {
        var result = validator.Validate(null, ValidOptions());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void RejectsEmptyResourceAllowlist()
    {
        var options = ValidOptions().WithResources([]);

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("AllowedResources must contain at least one resource", result.FailureMessage);
    }

    [Fact]
    public void RejectsInvalidResourceMapping()
    {
        var options = ValidOptions().WithResources(new Dictionary<string, KubernetesResourceOptions>
        {
            ["unsafe"] = ResourceAllowlistTests.Resource("apps", "v1", "pods/status", "Pod")
        });

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("Resource must be a lowercase Kubernetes resource name", result.FailureMessage);
    }

    [Fact]
    public void RejectsNullResourceGroupButAcceptsEmptyCoreGroup()
    {
        var nullGroup = OptionsWithResource(new KubernetesResourceOptions
        {
            Group = null!,
            Version = "v1",
            Resource = "pods",
            Kind = "Pod"
        });
        var coreGroup = OptionsWithResource(
            ResourceAllowlistTests.Resource("", "v1", "pods", "Pod"));

        var nullResult = validator.Validate(null, nullGroup);
        var coreResult = validator.Validate(null, coreGroup);

        Assert.True(nullResult.Failed);
        Assert.Contains("Group must not be null", nullResult.FailureMessage);
        Assert.True(coreResult.Succeeded);
    }

    [Theory]
    [InlineData("v1")]
    [InlineData("v1beta1")]
    [InlineData("v1-beta-1")]
    public void AcceptsDns1035ApiVersionsIncludingInternalHyphens(string version)
    {
        var options = OptionsWithResource(
            ResourceAllowlistTests.Resource("example.test", version, "widgets", "Widget"));

        var result = validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void AcceptsApiVersionAtDns1035MaximumLength()
    {
        var version = $"v{new string('1', 62)}";
        var options = OptionsWithResource(
            ResourceAllowlistTests.Resource("example.test", version, "widgets", "Widget"));

        var result = validator.Validate(null, options);

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData("1v1")]
    [InlineData("-v1")]
    [InlineData("v1-")]
    [InlineData("v1_beta1")]
    [InlineData("V1")]
    public void RejectsApiVersionsOutsideDns1035Rules(string version)
    {
        var options = OptionsWithResource(
            ResourceAllowlistTests.Resource("example.test", version, "widgets", "Widget"));

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("Version must be a lowercase DNS-1035 label", result.FailureMessage);
    }

    [Fact]
    public void RejectsApiVersionLongerThanDns1035Maximum()
    {
        var version = $"v{new string('1', 63)}";
        var options = OptionsWithResource(
            ResourceAllowlistTests.Resource("example.test", version, "widgets", "Widget"));

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("Version must be a lowercase DNS-1035 label", result.FailureMessage);
    }

    [Fact]
    public void EnforcesDns1035ResourceLengthAndAllowsInternalHyphens()
    {
        var maximumResource = $"r-{new string('x', 61)}";
        var validResult = validator.Validate(
            null,
            OptionsWithResource(ResourceAllowlistTests.Resource("example.test", "v1", maximumResource, "Widget")));
        var invalidResult = validator.Validate(
            null,
            OptionsWithResource(ResourceAllowlistTests.Resource("example.test", "v1", $"r{new string('x', 63)}", "Widget")));

        Assert.True(validResult.Succeeded);
        Assert.True(invalidResult.Failed);
        Assert.Contains("Resource must be a lowercase Kubernetes resource name", invalidResult.FailureMessage);
    }

    [Fact]
    public void EnforcesMixedCaseDns1035KindLength()
    {
        var maximumKind = $"K-{new string('x', 61)}";
        var validResult = validator.Validate(
            null,
            OptionsWithResource(ResourceAllowlistTests.Resource("example.test", "v1", "widgets", maximumKind)));
        var invalidResult = validator.Validate(
            null,
            OptionsWithResource(ResourceAllowlistTests.Resource("example.test", "v1", "widgets", $"K{new string('x', 63)}")));

        Assert.True(validResult.Succeeded);
        Assert.True(invalidResult.Failed);
        Assert.Contains("Kind must be a mixed-case DNS-1035 label", invalidResult.FailureMessage);
    }

    [Fact]
    public void LabelSelectorModeRequiresSelector()
    {
        var options = ResourceAllowlistTests.OptionsWithResources(
            ValidOptions().AllowedResources,
            new NamespacePolicyOptions
            {
                Mode = NamespacePolicyMode.LabelSelector,
                LabelSelector = " "
            });

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("LabelSelector is required", result.FailureMessage);
    }

    [Fact]
    public void RejectsInvalidBlacklistedNamespace()
    {
        var options = ResourceAllowlistTests.OptionsWithResources(
            ValidOptions().AllowedResources,
            new NamespacePolicyOptions
            {
                Mode = NamespacePolicyMode.Blacklist,
                DeniedNamespaces = ["../kube-system"]
            });

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("contains invalid namespace", result.FailureMessage);
    }

    private static KubeMcpOptions OptionsWithResource(KubernetesResourceOptions resource) =>
        ValidOptions().WithResources(new Dictionary<string, KubernetesResourceOptions>
        {
            ["test-resource"] = resource
        });

    private static KubeMcpOptions ValidOptions() =>
        ResourceAllowlistTests.OptionsWithResources(
            new Dictionary<string, KubernetesResourceOptions>
            {
                ["pods"] = ResourceAllowlistTests.Resource("", "v1", "pods", "Pod")
            });
}

file static class OptionsTestExtensions
{
    public static KubeMcpOptions WithResources(
        this KubeMcpOptions options,
        Dictionary<string, KubernetesResourceOptions> resources) => new()
        {
            SecretHmacKey = options.SecretHmacKey,
            AllowedResources = resources,
            NamespacePolicy = options.NamespacePolicy,
            Authentication = options.Authentication,
            MaxListItems = options.MaxListItems,
            MaxResponseBytes = options.MaxResponseBytes,
            KubernetesRequestTimeoutSeconds = options.KubernetesRequestTimeoutSeconds,
        };
}
