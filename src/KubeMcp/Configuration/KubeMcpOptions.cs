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

    [Range(1, 1000)]
    public int MaxListItems { get; init; } = 100;

    [Range(1024, 10 * 1024 * 1024)]
    public int MaxResponseBytes { get; init; } = 1024 * 1024;

    [Range(1, 120)]
    public int KubernetesRequestTimeoutSeconds { get; init; } = 15;
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
