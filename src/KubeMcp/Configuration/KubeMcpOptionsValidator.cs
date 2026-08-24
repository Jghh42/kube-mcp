using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;

namespace KubeMcp.Configuration;

public sealed partial class KubeMcpOptionsValidator : IValidateOptions<KubeMcpOptions>
{
    private const int MinimumHmacKeyBytes = 32;

    public ValidateOptionsResult Validate(string? name, KubeMcpOptions options)
    {
        var hmacValidation = ValidateHmacKey(options.SecretHmacKey);
        if (hmacValidation is not null)
        {
            return ValidateOptionsResult.Fail(hmacValidation);
        }

        if (options.ResourcePolicy is null)
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:ResourcePolicy is required.");
        }

        if (!Enum.IsDefined(options.ResourcePolicy.Mode))
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:ResourcePolicy:Mode must be Allowlist or AllowAll.");
        }

        if (options.ResourcePolicy.Mode == ResourcePolicyMode.Allowlist &&
            (options.AllowedResources is null || options.AllowedResources.Count == 0))
        {
            return ValidateOptionsResult.Fail(
                $"{KubeMcpOptions.SectionName}:AllowedResources must contain at least one resource when ResourcePolicy:Mode is Allowlist.");
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

    private static ValidateOptionsResult ValidateAuthentication(KubeMcpAuthenticationOptions authentication)
    {
        const string path = $"{KubeMcpOptions.SectionName}:Authentication";

        if (authentication is null)
        {
            return ValidateOptionsResult.Fail($"{path} is required.");
        }

        if (authentication.Mode == AuthenticationMode.None)
        {
            return ValidateOptionsResult.Success;
        }

        if (authentication.Mode == AuthenticationMode.ApiKey)
        {
            return Encoding.UTF8.GetByteCount(authentication.ApiKey) >= 32
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail($"{path}:ApiKey must contain at least 32 bytes in API key mode.");
        }

        if (authentication.Mode != AuthenticationMode.OAuthClientCredentials)
        {
            return ValidateOptionsResult.Fail($"{path}:Mode is not supported.");
        }

        var oauth = authentication.OAuth;
        if (oauth is null)
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth is required in OAuth client credentials mode.");
        }

        if (!Uri.TryCreate(oauth.Authority, UriKind.Absolute, out var authority) ||
            (authority.Scheme != Uri.UriSchemeHttp && authority.Scheme != Uri.UriSchemeHttps) ||
            authority.Query.Length != 0 ||
            authority.Fragment.Length != 0)
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth:Authority must be an absolute HTTP(S) URL without a query or fragment.");
        }

        if (oauth.RequireHttpsMetadata && !string.Equals(authority.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth:Authority must use HTTPS when RequireHttpsMetadata is true.");
        }

        if (string.IsNullOrWhiteSpace(oauth.Audience))
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth:Audience is required in OAuth client credentials mode.");
        }

        if (oauth.ClockSkewSeconds is < 0 or > 300)
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth:ClockSkewSeconds must be between 0 and 300.");
        }

        if (oauth.RequiredScopes is null || oauth.RequiredRoles is null)
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth required scopes and roles must be arrays.");
        }

        if (oauth.RequiredScopes.Length == 0 && oauth.RequiredRoles.Length == 0)
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth must require at least one scope or role.");
        }

        if (oauth.RequiredScopes.Any(string.IsNullOrWhiteSpace) || oauth.RequiredRoles.Any(string.IsNullOrWhiteSpace))
        {
            return ValidateOptionsResult.Fail($"{path}:OAuth required scopes and roles cannot contain empty values.");
        }

        return ValidateOptionsResult.Success;
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

        if (!IsDnsLabel(resource.Resource))
        {
            return $"{path}:Resource must be a lowercase Kubernetes resource name.";
        }

        if (string.IsNullOrWhiteSpace(resource.Version) ||
            !ApiVersionRegex().IsMatch(resource.Version))
        {
            return $"{path}:Version is invalid.";
        }

        if (!string.IsNullOrEmpty(resource.Group) &&
            (resource.Group.Length > 253 ||
             resource.Group.Split('.').Any(part => !IsDnsLabel(part))))
        {
            return $"{path}:Group must be empty or a lowercase DNS subdomain.";
        }

        if (string.IsNullOrWhiteSpace(resource.Kind) ||
            !KindRegex().IsMatch(resource.Kind))
        {
            return $"{path}:Kind is invalid.";
        }

        return null;
    }

    private static bool IsDnsLabel(string value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= 63 &&
        DnsLabelRegex().IsMatch(value);

    [GeneratedRegex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")]
    private static partial Regex DnsLabelRegex();

    [GeneratedRegex("^[a-z][a-z0-9]*$")]
    private static partial Regex ApiVersionRegex();

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9]*$")]
    private static partial Regex KindRegex();
}
