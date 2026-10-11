using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace KubeMcp.Configuration;

public sealed partial class KubeMcpOptionsValidator : IValidateOptions<KubeMcpOptions>
{
    private const int MinimumHmacKeyBytes = 32;
    private readonly IHostEnvironment environment;

    public KubeMcpOptionsValidator(IHostEnvironment environment)
    {
        this.environment = environment;
    }

    public ValidateOptionsResult Validate(string? name, KubeMcpOptions options)
    {
        var hmacValidation = ValidateHmacKey(options.SecretHmacKey);
        if (hmacValidation is not null)
        {
            return ValidateOptionsResult.Fail(hmacValidation);
        }

        if (options.AllowedResources is null || options.AllowedResources.Count == 0)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:AllowedResources must contain at least one resource.");
        }

        foreach (var (configuredName, resource) in options.AllowedResources ?? [])
        {
            var validation = ValidateResource(configuredName, resource);
            if (validation is not null)
            {
                return ValidateOptionsResult.Fail(validation);
            }
        }

        if (options.NamespacePolicy is null)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:NamespacePolicy is required.");
        }

        if (!Enum.IsDefined(options.NamespacePolicy.Mode))
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:NamespacePolicy:Mode must be Blacklist or LabelSelector.");
        }

        foreach (var deniedNamespace in options.NamespacePolicy.DeniedNamespaces ?? [])
        {
            if (!IsDnsLabel(deniedNamespace))
            {
                return ValidateOptionsResult.Fail(
                    $"{KubeMcpOptions.SectionName}:NamespacePolicy:DeniedNamespaces contains invalid namespace \"{deniedNamespace}\".");
            }
        }

        if (options.NamespacePolicy.Mode == NamespacePolicyMode.LabelSelector &&
            string.IsNullOrWhiteSpace(options.NamespacePolicy.LabelSelector))
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:NamespacePolicy:LabelSelector is required when Mode is LabelSelector.");
        }

        if (options.NamespacePolicy.LabelSelector?.Length > 1024)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:NamespacePolicy:LabelSelector must not exceed 1024 characters.");
        }

        if (options.MaxUpstreamBodyBytes < options.MaxResponseBytes)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:MaxUpstreamBodyBytes must be at least MaxResponseBytes so a single object's safe output can fit within the upstream body budget.");
        }

        if (options.SecretListPageSize > options.ListPageSize)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:SecretListPageSize must not exceed ListPageSize.");
        }

        if (options.OverallMcpRequestTimeoutSeconds is < 1 or > 3600)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:OverallMcpRequestTimeoutSeconds must be between 1 and 3600.");
        }

        var gateValidation = ValidateCredentialGate(options.CredentialGate);
        if (gateValidation is not null)
        {
            return ValidateOptionsResult.Fail(gateValidation);
        }

        var requiredWorkSeconds = options.KubernetesRequestTimeoutSeconds +
            (options.CredentialGate?.Enabled == true ? options.CredentialGate.TotalTimeoutSeconds : 0);
        if (options.OverallMcpRequestTimeoutSeconds <= requiredWorkSeconds)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:OverallMcpRequestTimeoutSeconds must be greater than KubernetesRequestTimeoutSeconds plus the enabled credential gate total timeout so the end-to-end deadline leaves time for MCP error serialization and audit publication.");
        }

        return ValidateAuthentication(options.Authentication);
    }

    private static string? ValidateHmacKey(string secretHmacKey)
    {
        if (string.IsNullOrWhiteSpace(secretHmacKey))
        {
            return $"{KubeMcpOptions.SectionName}:SecretHmacKey is required.";
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(secretHmacKey);
        }
        catch (FormatException)
        {
            return $"{KubeMcpOptions.SectionName}:SecretHmacKey must be a valid base64 value.";
        }

        try
        {
            return key.Length >= MinimumHmacKeyBytes
                ? null
                : $"{KubeMcpOptions.SectionName}:SecretHmacKey must contain at least {MinimumHmacKeyBytes} bytes.";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static string? ValidateCredentialGate(CredentialGateOptions? gate)
    {
        const string path = $"{KubeMcpOptions.SectionName}:CredentialGate";
        if (gate is null)
        {
            return $"{path} is required.";
        }

        if (gate.RetryCount is < 0 or > 2)
        {
            return $"{path}:RetryCount must be between 0 and 2.";
        }

        if (gate.ChunkSizeBytes is < 256 or > 1024 * 1024)
        {
            return $"{path}:ChunkSizeBytes must be between 256 and 1048576.";
        }

        // Leave enough state capacity for structural context and meaningful
        // forward progress on each oversized scalar segment.
        if (gate.ScalarOverlapBytes < 0 || gate.ScalarOverlapBytes > gate.ChunkSizeBytes / 4)
        {
            return $"{path}:ScalarOverlapBytes must be non-negative and no greater than one quarter of ChunkSizeBytes.";
        }

        if (gate.TotalTimeoutSeconds is < 1 or > 120)
        {
            return $"{path}:TotalTimeoutSeconds must be between 1 and 120.";
        }

        if (gate.AttemptTimeoutSeconds is < 1 or > 120 ||
            gate.AttemptTimeoutSeconds > gate.TotalTimeoutSeconds)
        {
            return $"{path}:AttemptTimeoutSeconds must be between 1 and TotalTimeoutSeconds.";
        }

        if (gate.MaxInputTokens is < 1 or > 1_000_000)
        {
            return $"{path}:MaxInputTokens must be between 1 and 1000000.";
        }

        if (gate.MaxResponseBodyBytes is < 1024 or > 1024 * 1024)
        {
            return $"{path}:MaxResponseBodyBytes must be between 1024 and 1048576.";
        }

        if (gate.ApiKey is null || Encoding.UTF8.GetByteCount(gate.ApiKey) > 8192)
        {
            return $"{path}:ApiKey must not exceed 8192 UTF-8 bytes.";
        }

        if (gate.Endpoint?.Length > 2048 || gate.RequestModel?.Length > 256 ||
            gate.ExpectedResponseModel?.Length > 256 || gate.Prompt?.Length > 16_384)
        {
            return $"{path}:Endpoint, model names, or Prompt exceeds its configured length bound.";
        }

        if (!gate.Enabled)
        {
            return null;
        }

        if (!Uri.TryCreate(gate.Endpoint, UriKind.Absolute, out var endpoint) ||
            (endpoint.Scheme != Uri.UriSchemeHttp && endpoint.Scheme != Uri.UriSchemeHttps) ||
            !endpoint.AbsolutePath.EndsWith("/systemone", StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment) ||
            !string.IsNullOrEmpty(endpoint.UserInfo))
        {
            return $"{path}:Endpoint must be a complete absolute HTTP or HTTPS URL ending in /systemone without userinfo, query, or fragment.";
        }

        if (string.IsNullOrWhiteSpace(gate.RequestModel))
        {
            return $"{path}:RequestModel is required when enabled.";
        }

        if (string.IsNullOrWhiteSpace(gate.ExpectedResponseModel))
        {
            return $"{path}:ExpectedResponseModel is required when enabled.";
        }

        if (gate.ProbabilityThreshold is null ||
            !double.IsFinite(gate.ProbabilityThreshold.Value) ||
            gate.ProbabilityThreshold.Value is < 0 or >= 0.5)
        {
            return $"{path}:ProbabilityThreshold must be finite, at least zero, and less than 0.5 when enabled.";
        }

        if (gate.Prompt is not null && string.IsNullOrWhiteSpace(gate.Prompt))
        {
            return $"{path}:Prompt must not be empty when enabled.";
        }

        return null;
    }

    private ValidateOptionsResult ValidateAuthentication(KubeMcpAuthenticationOptions authentication)
    {
        const string path = $"{KubeMcpOptions.SectionName}:Authentication";

        if (authentication is null)
        {
            return ValidateOptionsResult.Fail($"{path} is required.");
        }

        if (authentication.Mode == AuthenticationMode.None)
        {
            return environment.IsDevelopment()
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail(
                    $"{path}:Mode=None is not permitted outside the Development environment. " +
                    "Set Mode to ApiKey for every non-development deployment.");
        }

        if (authentication.Mode != AuthenticationMode.ApiKey)
        {
            return ValidateOptionsResult.Fail($"{path}:Mode is not supported.");
        }

        return Encoding.UTF8.GetByteCount(authentication.ApiKey) >= 32
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail($"{path}:ApiKey must contain at least 32 bytes in API key mode.");
    }

    private static string? ValidateResource(
        string configuredName,
        KubernetesResourceOptions? resource)
    {
        var path = $"{KubeMcpOptions.SectionName}:AllowedResources:{configuredName}";
        if (string.IsNullOrWhiteSpace(configuredName) ||
            configuredName.Length > 253 ||
            configuredName.Split('.').Any(part => !IsDnsLabel(part)))
        {
            return $"{path} has an invalid configured resource name.";
        }

        if (resource is null)
        {
            return $"{path} must contain a resource mapping.";
        }

        if (!IsDns1035Label(resource.Resource))
        {
            return $"{path}:Resource must be a lowercase Kubernetes resource name (DNS-1035 label).";
        }

        if (!IsDns1035Label(resource.Version))
        {
            return $"{path}:Version must be a lowercase DNS-1035 label such as v1 or v1beta1.";
        }

        if (resource.Group is null)
        {
            return $"{path}:Group must not be null; use an empty string for the core Kubernetes API group.";
        }

        if (resource.Group.Length > 0 &&
            (resource.Group.Length > 253 ||
             resource.Group.Split('.').Any(part => !IsDnsLabel(part))))
        {
            return $"{path}:Group must be empty or a lowercase DNS subdomain.";
        }

        if (string.IsNullOrWhiteSpace(resource.Kind) ||
            !IsDns1035Label(resource.Kind.ToLowerInvariant()))
        {
            return $"{path}:Kind must be a mixed-case DNS-1035 label (max 63 characters).";
        }

        return null;
    }

    private static bool IsDnsLabel(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 63 &&
        DnsLabelRegex().IsMatch(value);

    // A DNS-1035 label matches Kubernetes resource/version naming: lowercase
    // alphanumeric and internal hyphens, starting with a letter, ending with
    // an alphanumeric character, and at most 63 characters long.
    private static bool IsDns1035Label(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 63 &&
        Dns1035LabelRegex().IsMatch(value);

    [GeneratedRegex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")]
    private static partial Regex DnsLabelRegex();

    [GeneratedRegex("^[a-z]([-a-z0-9]*[a-z0-9])?$")]
    private static partial Regex Dns1035LabelRegex();
}
