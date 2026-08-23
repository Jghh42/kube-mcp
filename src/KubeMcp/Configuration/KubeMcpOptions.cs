using System.ComponentModel.DataAnnotations;

namespace KubeMcp.Configuration;

public sealed class KubeMcpOptions
{
    public const string SectionName = "KubeMcp";

    [Required]
    public string SecretHmacKey { get; init; } = string.Empty;

    public string? KubeConfigPath { get; init; }

    [Range(1, 1000)]
    public int MaxListItems { get; init; } = 100;

    [Range(1024, 10 * 1024 * 1024)]
    public int MaxResponseBytes { get; init; } = 1024 * 1024;

    [Range(1, 120)]
    public int KubernetesRequestTimeoutSeconds { get; init; } = 15;

    [Range(1, 3600)]
    public int DiscoveryCacheSeconds { get; init; } = 300;
}
