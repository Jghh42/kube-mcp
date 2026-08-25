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

        if (options.OverallMcpRequestTimeoutSeconds <= options.KubernetesRequestTimeoutSeconds)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:OverallMcpRequestTimeoutSeconds must be greater than KubernetesRequestTimeoutSeconds so the end-to-end deadline leaves time for MCP error serialization and audit publication.");
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
