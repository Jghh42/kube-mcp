using System.Text.RegularExpressions;

namespace KubeMcp.Kubernetes;

public static partial class KubernetesNameValidator
{
    public const int MaximumQualifiedNameLength = 253;

    public static void ValidateResourceIdentifierLength(string? resource)
    {
        if (resource is not null && resource.Length > MaximumQualifiedNameLength)
        {
            throw new KubernetesReadException(
                $"resource must not exceed {MaximumQualifiedNameLength} characters.",
                KubernetesErrorCategory.InvalidRequest);
        }
    }

    internal static string BoundedResourceForDiagnostics(string? resource) =>
        resource is not null && resource.Length <= MaximumQualifiedNameLength
            ? resource
            : "<invalid-resource>";

    public static void ValidateNamespace(string @namespace)
    {
        if (@namespace.Length > 63 || !DnsLabelRegex().IsMatch(@namespace))
        {
            throw new KubernetesReadException(
                "namespace must be a valid lowercase Kubernetes DNS label.",
                KubernetesErrorCategory.InvalidRequest);
        }
    }

    public static void ValidateResourceName(string name)
    {
        if (name.Length > MaximumQualifiedNameLength || name.Split('.').Any(label =>
                label.Length > 63 || !DnsLabelRegex().IsMatch(label)))
        {
            throw new KubernetesReadException(
                "name must be a valid lowercase Kubernetes DNS subdomain.",
                KubernetesErrorCategory.InvalidRequest);
        }
    }

    [GeneratedRegex("^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex DnsLabelRegex();
}
