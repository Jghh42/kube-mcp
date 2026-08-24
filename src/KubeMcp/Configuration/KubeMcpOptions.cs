using System.ComponentModel.DataAnnotations;

namespace KubeMcp.Configuration;

public sealed class KubeMcpOptions
{
    public const string SectionName = "KubeMcp";

    [Required]
    public string SecretHmacKey { get; init; } = string.Empty;

    public string? KubeConfigPath { get; init; }

    public ResourcePolicyOptions ResourcePolicy { get; init; } = new();

    public Dictionary<string, KubernetesResourceOptions> AllowedResources { get; init; } = [];

    public NamespacePolicyOptions NamespacePolicy { get; init; } = new();

    public KubeMcpAuthenticationOptions Authentication { get; init; } = new();

    [Range(1, 1000)]
    public int MaxListItems { get; init; } = 100;

    [Range(1024, 10 * 1024 * 1024)]
    public int MaxResponseBytes { get; init; } = 1024 * 1024;

    [Range(1, 120)]
    public int KubernetesRequestTimeoutSeconds { get; init; } = 15;

    [Range(1, 3600)]
    public int DiscoveryCacheSeconds { get; init; } = 300;
}

public sealed class ResourcePolicyOptions
{
    public ResourcePolicyMode Mode { get; init; } = ResourcePolicyMode.Allowlist;
}

public enum ResourcePolicyMode
{
    Allowlist,
    AllowAll
}

public sealed class KubernetesResourceOptions
{
    public string Group { get; init; } = string.Empty;

    public string Version { get; init; } = string.Empty;

    public string Resource { get; init; } = string.Empty;

    public string Kind { get; init; } = string.Empty;
}

public sealed class NamespacePolicyOptions
{
    public NamespacePolicyMode Mode { get; init; } = NamespacePolicyMode.Blacklist;

    public string[] DeniedNamespaces { get; init; } =
        ["kube-system", "kube-public", "kube-node-lease"];

    public string? LabelSelector { get; init; }
}

public enum NamespacePolicyMode
{
    Blacklist,
    LabelSelector
}

public sealed class KubeMcpAuthenticationOptions
{
    public AuthenticationMode Mode { get; init; } = AuthenticationMode.None;

    public string ApiKey { get; init; } = string.Empty;

    public OAuthOptions OAuth { get; init; } = new();
}

public sealed class OAuthOptions
{
    public string Authority { get; init; } = string.Empty;

    public string Audience { get; init; } = string.Empty;

    public string[] RequiredScopes { get; init; } = ["k-mcp:read"];

    public string[] RequiredRoles { get; init; } = [];

    public bool RequireHttpsMetadata { get; init; } = true;

    [Range(0, 300)]
    public int ClockSkewSeconds { get; init; } = 60;
}

public enum AuthenticationMode
{
    None,
    ApiKey,
    OAuthClientCredentials
}
