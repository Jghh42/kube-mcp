using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Security;

namespace KubeMcp.Kubernetes;

public sealed class KubernetesListSummarizer(
    SecretSanitizer secretSanitizer,
    TimeProvider timeProvider)
{
    internal JsonObject Summarize(
        DynamicKubernetesObject item,
        KubernetesResourceDescriptor descriptor)
    {
        var result = new JsonObject
        {
            ["name"] = MetadataString(item, "name"),
            ["namespace"] = MetadataString(item, "namespace"),
            ["kind"] = string.IsNullOrWhiteSpace(item.Kind) ? descriptor.Kind : item.Kind
        };
        AddAgeWhenAvailable(result, MetadataString(item, "creationTimestamp"));
        return result;
    }

    internal JsonObject SummarizeSecret(JsonElement item)
    {
        var result = secretSanitizer.SanitizeListItem(item);
        AddAge(result, MetadataString(item, "creationTimestamp"));
        return result;
    }

    private void AddAgeWhenAvailable(JsonObject result, string? creationTimestamp)
    {
        if (TryFormatAge(creationTimestamp, out var age))
        {
            result["age"] = age;
        }
    }

    // Preserve the established Secret LIST shape, including a null age when
    // creation metadata is unavailable.
    private void AddAge(JsonObject result, string? creationTimestamp)
    {
        result["age"] = TryFormatAge(creationTimestamp, out var age) ? age : null;
    }

    private bool TryFormatAge(string? creationTimestamp, out string age)
    {
        if (!DateTimeOffset.TryParse(
                creationTimestamp,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var created))
        {
            age = string.Empty;
            return false;
        }

        age = FormatAge(timeProvider.GetUtcNow() - created);
        return true;
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        if (age.TotalSeconds < 60)
        {
            return $"{(long)age.TotalSeconds}s";
        }

        if (age.TotalMinutes < 60)
        {
            return $"{(long)age.TotalMinutes}m";
        }

        if (age.TotalHours < 24)
        {
            return $"{(long)age.TotalHours}h";
        }

        return $"{(long)age.TotalDays}d";
    }

    private static JsonElement? ObjectProperty(DynamicKubernetesObject item, string name) =>
        item.Properties.TryGetValue(name, out var value) ? value : null;

    private static JsonElement? ObjectProperty(JsonElement source, string name) =>
        source.ValueKind == JsonValueKind.Object && source.TryGetProperty(name, out var property)
            ? property
            : null;

    private static string? MetadataString(DynamicKubernetesObject item, string name) =>
        StringProperty(ObjectProperty(item, "metadata"), name);

    private static string? MetadataString(JsonElement item, string name) =>
        StringProperty(ObjectProperty(item, "metadata"), name);

    private static string? StringProperty(JsonElement? source, string name) =>
        source is { ValueKind: JsonValueKind.Object } value &&
        value.TryGetProperty(name, out var property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}
