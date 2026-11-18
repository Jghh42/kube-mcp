using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using Microsoft.Extensions.Options;

namespace KubeMcp.Security;

public sealed class SecretSanitizer(
    SecretFingerprinter fingerprinter,
    IOptions<KubeMcpOptions> options)
{
    private const string LastAppliedConfigurationAnnotation =
        "kubectl.kubernetes.io/last-applied-configuration";

    private readonly HashSet<string> plaintextEnvVars =
        new(options.Value.PlaintextEnvVars ?? [], StringComparer.Ordinal);
    private readonly HashSet<string> plaintextConfigMaps =
        new(options.Value.PlaintextConfigMaps ?? [], StringComparer.Ordinal);

    internal JsonObject SanitizeGet(JsonElement secret)
    {
        var result = new JsonObject
        {
            ["apiVersion"] = StringProperty(secret, "apiVersion"),
            ["kind"] = StringProperty(secret, "kind"),
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

    /// <summary>
    /// Sanitizes a detailed non-Secret GET in place. The last-applied annotation
    /// is dropped because it repeats the previous spec unsanitized. Every literal
    /// value in an <c>env</c> array, wherever it appears, and ConfigMap
    /// <c>data</c>/<c>binaryData</c> values are fingerprinted unless allowlisted.
    /// </summary>
    internal void SanitizeObjectGet(
        JsonObject item,
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string name)
    {
        if (item["metadata"] is JsonObject metadata &&
            metadata["annotations"] is JsonObject annotations)
        {
            annotations.Remove(LastAppliedConfigurationAnnotation);
        }

        if (descriptor.IsConfigMap && !plaintextConfigMaps.Contains($"{@namespace}/{name}"))
        {
            FingerprintConfigMapValues(item, "data", isBase64: false);
            FingerprintConfigMapValues(item, "binaryData", isBase64: true);
        }

        FingerprintEnvValues(item);
    }

    internal JsonObject SanitizeListItem(JsonElement secret)
    {
        var type = StringProperty(secret, "type");
        _ = BooleanProperty(secret, "immutable");
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
            ["type"] = type ?? "Opaque",
            ["keys"] = keyArray
        };
    }

    internal void ValidateListItem(JsonElement secret)
    {
        _ = StringProperty(secret, "type");
        _ = BooleanProperty(secret, "immutable");
        ValidateStringMap(secret, "data");
        ValidateStringMap(secret, "stringData");
    }

    private void AddDataFingerprints(
        JsonElement secret,
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
                bytes = property.Value.GetBytesFromBase64();
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
        JsonElement secret,
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

    private void FingerprintConfigMapValues(
        JsonObject configMap,
        string propertyName,
        bool isBase64)
    {
        var values = configMap[propertyName];
        if (values is null)
        {
            return;
        }

        if (values is not JsonObject entries)
        {
            throw InvalidConfigMapShapeException();
        }

        var fingerprints = new JsonObject();
        foreach (var (key, value) in entries)
        {
            if (value is not JsonValue text || !text.TryGetValue<string>(out var content))
            {
                throw InvalidConfigMapShapeException();
            }

            byte[] bytes;
            try
            {
                bytes = isBase64 ? Convert.FromBase64String(content) : Encoding.UTF8.GetBytes(content);
            }
            catch (FormatException)
            {
                throw InvalidConfigMapShapeException();
            }

            fingerprints[key] = fingerprinter.Fingerprint(bytes);
        }

        configMap[propertyName] = fingerprints;
    }

    // Walks the whole object so every pod template (including CronJob nesting,
    // init/ephemeral containers, and CRD fields that reuse EnvVar) is covered
    // without per-kind paths.
    private void FingerprintEnvValues(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject properties:
                foreach (var (propertyName, value) in properties)
                {
                    if (propertyName == "env" && value is JsonArray variables)
                    {
                        FingerprintEnvArray(variables);
                    }
                    else
                    {
                        FingerprintEnvValues(value);
                    }
                }

                break;
            case JsonArray elements:
                foreach (var element in elements)
                {
                    FingerprintEnvValues(element);
                }

                break;
        }
    }

    private void FingerprintEnvArray(JsonArray variables)
    {
        foreach (var variable in variables)
        {
            if (variable is not JsonObject entry || entry["value"] is not { } value)
            {
                continue;
            }

            if (entry["name"] is JsonValue name &&
                name.TryGetValue<string>(out var variableName) &&
                plaintextEnvVars.Contains(variableName))
            {
                continue;
            }

            // A non-string value is not a valid EnvVar; fingerprint its JSON
            // text rather than pass it through.
            var text = value is JsonValue scalar && scalar.TryGetValue<string>(out var content)
                ? content
                : value.ToJsonString();
            entry["value"] = fingerprinter.Fingerprint(Encoding.UTF8.GetBytes(text));
        }
    }

    private static void AddKeyNames(
        JsonElement secret,
        string propertyName,
        ISet<string> keys)
    {
        if (!TryGetObjectProperty(secret, propertyName, out var data))
        {
            return;
        }

        foreach (var property in data.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                throw InvalidSecretShapeException();
            }

            keys.Add(property.Name);
        }
    }

    private static void ValidateStringMap(JsonElement secret, string propertyName)
    {
        if (!TryGetObjectProperty(secret, propertyName, out var data))
        {
            return;
        }

        foreach (var property in data.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.String)
            {
                throw InvalidSecretShapeException();
            }
        }
    }

    private static JsonObject SafeMetadata(JsonElement secret)
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
        JsonElement secret,
        JsonObject target,
        string propertyName)
    {
        if (MetadataString(secret, propertyName) is { } value)
        {
            target[propertyName] = value;
        }
    }

    private static string? MetadataString(JsonElement secret, string propertyName)
    {
        if (!TryGetObjectProperty(secret, "metadata", out var metadata) ||
            !metadata.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        return value.GetString();
    }

    private static string? StringProperty(JsonElement secret, string propertyName)
    {
        if (!secret.TryGetProperty(propertyName, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw InvalidSecretShapeException();
        }

        return value.GetString();
    }

    private static bool? BooleanProperty(JsonElement secret, string propertyName)
    {
        if (!secret.TryGetProperty(propertyName, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw InvalidSecretShapeException()
        };
    }

    private static bool TryGetObjectProperty(
        JsonElement secret,
        string propertyName,
        out JsonElement value)
    {
        if (secret.ValueKind != JsonValueKind.Object)
        {
            throw InvalidSecretShapeException();
        }

        if (!secret.TryGetProperty(propertyName, out value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            value = default;
            return false;
        }

        if (value.ValueKind != JsonValueKind.Object)
        {
            throw InvalidSecretShapeException();
        }

        return true;
    }

    private static KubernetesReadException InvalidSecretShapeException() =>
        new("A Secret field had an invalid type.");

    private static KubernetesReadException InvalidConfigMapShapeException() =>
        new("A ConfigMap field had an invalid type.");
}
