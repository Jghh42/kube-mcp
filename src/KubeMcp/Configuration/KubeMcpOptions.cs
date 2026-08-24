using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.HttpOverrides;

namespace KubeMcp.Configuration;

public sealed class KubeMcpOptions
{
    public const string SectionName = "KubeMcp";

    [Required]
    public string SecretHmacKey { get; init; } = string.Empty;

    public string? KubeConfigPath { get; init; }

    /// <summary>
    /// Optional representative namespace included in readiness SelfSubjectAccessReview
    /// checks for namespaced resources. Null retains a cluster-wide authorization check.
    /// </summary>
    public string? ReadinessNamespace { get; init; }

    public ResourcePolicyOptions ResourcePolicy { get; init; } = new();

    public Dictionary<string, KubernetesResourceOptions> AllowedResources { get; init; } = [];

    public NamespacePolicyOptions NamespacePolicy { get; init; } = new();

    public KubeMcpAuthenticationOptions Authentication { get; init; } = new();

    public KubeMcpForwardedHeadersOptions ForwardedHeaders { get; init; } = new();

    public McpAdmissionOptions McpAdmission { get; init; } = new();

    public McpConcurrencyOptions McpConcurrency { get; init; } = new();

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

    /// <summary>Bounded parallelism for AllowAll API group discovery.</summary>
    [Range(1, 16)]
    public int DiscoveryParallelism { get; init; } = 4;

    [Range(1, 120)]
    public int KubernetesRequestTimeoutSeconds { get; init; } = 15;

    /// <summary>
    /// End-to-end deadline for an HTTP MCP request, including authentication,
    /// protocol parsing/dispatch, Kubernetes work, and response serialization.
    /// </summary>
    [Range(1, 3600)]
    public int OverallMcpRequestTimeoutSeconds { get; init; } = 30;

    [Range(1, 3600)]
    public int DiscoveryCacheSeconds { get; init; } = 300;

    public KubeMcpTelemetryOptions Telemetry { get; init; } = new();
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
    // Fail-closed default. The explicitly named Development settings override
    // this to None for local development only.
    public AuthenticationMode Mode { get; init; } = AuthenticationMode.ApiKey;

    // Deliberate deployment-level opt-in that permits Mode=None in a
    // non-Development environment. Intended only for an isolated development
    // deployment; production must use ApiKey or OAuthClientCredentials.
    public bool AllowUnauthenticated { get; init; }

    public string ApiKey { get; init; } = string.Empty;

    public OAuthOptions OAuth { get; init; } = new();
}

public sealed class KubeMcpForwardedHeadersOptions
{
    // Explicitly trusted reverse-proxy IP addresses. Empty by default, in which
    // case only the loopback address is trusted. Never trust all proxies.
    public string[] KnownProxies { get; init; } = [];

    // Explicitly trusted reverse-proxy networks as CIDR strings, for example
    // "10.0.0.0/8". Empty by default, in which case only the loopback network is
    // trusted. Never trust all networks.
    public string[] KnownNetworks { get; init; } = [];

    // Which forwarded headers to honor from trusted proxies. Defaults to the
    // client IP, scheme, and host so audit records and host filtering see the
    // originating client and production hostname behind a reverse proxy.
    public ForwardedHeaders AllowedForwardedHeaders { get; init; } =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
}

public sealed class McpAdmissionOptions
{
    /// <summary>
    /// Maximum number of MCP requests admitted ahead of authentication. This
    /// must cover the post-authentication permits and complete inner queue.
    /// </summary>
    [Range(1, 128)]
    public int PermitLimit { get; init; } = 16;

    /// <summary>
    /// Bounded oldest-first admission queue. Overflow is rejected before
    /// authentication, request parsing, observability, or per-request audit work.
    /// </summary>
    [Range(0, 128)]
    public int QueueLimit { get; init; } = 16;
}

public sealed class McpConcurrencyOptions
{
    /// <summary>
    /// Maximum number of authenticated MCP requests executing concurrently in
    /// this process. All clients share this limit so Kubernetes response memory
    /// is globally bounded.
    /// </summary>
    [Range(1, 16)]
    public int PermitLimit { get; init; } = 2;

    /// <summary>
    /// Maximum number of MCP requests waiting for a permit. Zero fails fast;
    /// the deliberately small upper bound prevents queued requests becoming a
    /// second memory/backpressure problem.
    /// </summary>
    [Range(0, 4)]
    public int QueueLimit { get; init; } = 2;
}

public sealed class KubeMcpTelemetryOptions
{
    /// <summary>
    /// Enables OpenTelemetry tracing and metrics export. OTLP connection settings
    /// use the standard OTEL_EXPORTER_OTLP_* environment variables.
    /// </summary>
    public bool Enabled { get; init; }
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
