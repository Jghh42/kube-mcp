using System.ComponentModel.DataAnnotations;

namespace KubeMcp.Configuration;

public sealed class KubeMcpOptions
{
    public const string SectionName = "KubeMcp";

    [Required]
    public string SecretHmacKey { get; init; } = string.Empty;

    public string? KubeConfigPath { get; init; }

    public Dictionary<string, KubernetesResourceOptions> AllowedResources { get; init; } = [];

    public NamespacePolicyOptions NamespacePolicy { get; init; } = new();

    public KubeMcpAuthenticationOptions Authentication { get; init; } = new();

    public CredentialGateOptions CredentialGate { get; init; } = new();

    [Range(1, 1000)]
    public int MaxListItems { get; init; } = 100;

    [Range(1024, 10 * 1024 * 1024)]
    public int MaxResponseBytes { get; init; } = 1024 * 1024;

    /// <summary>
    /// Per-response upstream byte cap enforced before deserialization. Bounds peak
    /// memory for a single object or one LIST page. Must be at least
    /// <see cref="MaxResponseBytes"/> so a single object's safe output can fit.
    /// </summary>
    [Range(64 * 1024, 64 * 1024 * 1024)]
    public int MaxUpstreamBodyBytes { get; init; } = 4 * 1024 * 1024;

    /// <summary>Page size used when fetching non-Secret LISTs.</summary>
    [Range(1, 1000)]
    public int ListPageSize { get; init; } = 50;

    /// <summary>
    /// Maximum pages fetched for one LIST, bounding continuation-token chains
    /// even when an upstream server returns empty or undersized pages.
    /// </summary>
    [Range(1, 100)]
    public int MaxListPages { get; init; } = 20;

    /// <summary>
    /// Especially small page size for Secret LISTs to limit raw-secret memory
    /// lifetime and peak memory.
    /// </summary>
    [Range(1, 1000)]
    public int SecretListPageSize { get; init; } = 10;

    [Range(1, 120)]
    public int KubernetesRequestTimeoutSeconds { get; init; } = 15;

    /// <summary>
    /// End-to-end deadline for an HTTP MCP request, including authentication,
    /// protocol parsing/dispatch, Kubernetes work, and response serialization.
    /// </summary>
    [Range(1, 3600)]
    public int OverallMcpRequestTimeoutSeconds { get; init; } = 30;
}

public sealed record CredentialGateOptions
{
    public bool Enabled { get; init; }

    public string? Endpoint { get; init; }

    public string ApiKey { get; init; } = string.Empty;

    public string? RequestModel { get; init; }

    public string? ExpectedResponseModel { get; init; }

    public double? ProbabilityThreshold { get; init; }

    // Null selects the application-owned safe default. An explicitly empty
    // value is rejected when the gate is enabled.
    public string? Prompt { get; init; }

    [Range(256, 1024 * 1024)]
    public int ChunkSizeBytes { get; init; } = 4096;

    [Range(0, 1024 * 1024)]
    public int ScalarOverlapBytes { get; init; } = 256;

    [Range(1, 120)]
    public int TotalTimeoutSeconds { get; init; } = 15;

    [Range(1, 120)]
    public int AttemptTimeoutSeconds { get; init; } = 5;

    [Range(0, 2)]
    public int RetryCount { get; init; } = 2;

    [Range(1, 1_000_000)]
    public int MaxInputTokens { get; init; } = 4096;

    [Range(1024, 1024 * 1024)]
    public int MaxResponseBodyBytes { get; init; } = 64 * 1024;
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
    // Fail-closed default. The explicitly named Development settings override
    // this to None for local development only.
    public AuthenticationMode Mode { get; init; } = AuthenticationMode.ApiKey;

    public string ApiKey { get; init; } = string.Empty;
}

public enum AuthenticationMode
{
    None,
    ApiKey
}
