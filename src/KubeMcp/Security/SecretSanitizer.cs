using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Kubernetes;

namespace KubeMcp.Security;

public sealed class SecretSanitizer(SecretFingerprinter fingerprinter)
{
    public JsonObject SanitizeGet(DynamicKubernetesObject secret)
    {
        var result = new JsonObject
        {
            ["apiVersion"] = secret.ApiVersion,
            ["kind"] = secret.Kind,
            ["metadata"] = SafeMetadata(secret),
            ["type"] = StringProperty(secret, "type") ?? "Opaque"
        };

        if (BooleanProperty(secret, "immutable") is { } immutable)
        {
            result["immutable"] = immutable;
        }

        var fingerprints = new SortedDictionary<string, string>(StringComparer.Ordinal);
        AddDataFingerprints(secret, fingerprints);
        AddStringDataFingerprints(secret, fingerprints);

        var data = new JsonObject();
        foreach (var (key, fingerprint) in fingerprints)
        {
            data[key] = fingerprint;
        }

        result["data"] = data;
        return result;
    }

    public JsonObject SanitizeListItem(DynamicKubernetesObject secret)
    {
        var keys = new SortedSet<string>(StringComparer.Ordinal);
        AddKeyNames(secret, "data", keys);
        AddKeyNames(secret, "stringData", keys);

        var keyArray = new JsonArray();
        foreach (var key in keys)
        {
            keyArray.Add(key);
        }

        return new JsonObject
        {
            ["name"] = MetadataString(secret, "name"),
            ["type"] = StringProperty(secret, "type") ?? "Opaque",
            ["keys"] = keyArray
        };
    }

    private void AddDataFingerprints(
        DynamicKubernetesObject secret,
        IDictionary<string, string> fingerprints)
    {
        if (!TryGetObjectProperty(secret, "data", out var data))
        {
            return;
        }

        foreach (var property in data.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                throw new KubernetesReadException("A Secret data value was not valid base64 data.");
            }

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(property.Value.GetString()!);
            }
            catch (FormatException)
            {
                throw new KubernetesReadException("A Secret data value was not valid base64 data.");
            }

            try
            {
                fingerprints[property.Name] = fingerprinter.Fingerprint(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    private void AddStringDataFingerprints(
        DynamicKubernetesObject secret,
        IDictionary<string, string> fingerprints)
    {
        if (!TryGetObjectProperty(secret, "stringData", out var stringData))
        {
            return;
        }

        foreach (var property in stringData.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                throw new KubernetesReadException("A Secret stringData value was not valid text.");
            }

            var bytes = Encoding.UTF8.GetBytes(property.Value.GetString()!);
            try
            {
                fingerprints[property.Name] = fingerprinter.Fingerprint(bytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    private static void AddKeyNames(
        DynamicKubernetesObject secret,
        string propertyName,
        ISet<string> keys)
    {
        if (!TryGetObjectProperty(secret, propertyName, out var data))
        {
            return;
        }

        foreach (var property in data.EnumerateObject())
        {
            keys.Add(property.Name);
        }
    }

    private static JsonObject SafeMetadata(DynamicKubernetesObject secret)
    {
        var metadata = new JsonObject();
        AddMetadataString(secret, metadata, "name");
        AddMetadataString(secret, metadata, "namespace");
        AddMetadataString(secret, metadata, "uid");
        AddMetadataString(secret, metadata, "resourceVersion");
        AddMetadataString(secret, metadata, "creationTimestamp");
        return metadata;
    }

    private static void AddMetadataString(
        DynamicKubernetesObject secret,
        JsonObject target,
        string propertyName)
    {
        if (MetadataString(secret, propertyName) is { } value)
        {
            target[propertyName] = value;
        }
    }

    private static string? MetadataString(DynamicKubernetesObject secret, string propertyName)
    {
        if (!TryGetObjectProperty(secret, "metadata", out var metadata) ||
            !metadata.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static string? StringProperty(DynamicKubernetesObject secret, string propertyName)
    {
        return secret.Properties.TryGetValue(propertyName, out var value) &&
               value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static bool? BooleanProperty(DynamicKubernetesObject secret, string propertyName)
    {
        if (!secret.Properties.TryGetValue(propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    private static bool TryGetObjectProperty(
        DynamicKubernetesObject secret,
        string propertyName,
        out JsonElement value)
    {
        if (secret.Properties.TryGetValue(propertyName, out value) &&
            value.ValueKind == JsonValueKind.Object)
        {
            return true;
        }

        value = default;
        return false;
    }
}
