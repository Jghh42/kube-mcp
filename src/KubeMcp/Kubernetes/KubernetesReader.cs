using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.Security;
using k8s;
using k8s.Models;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

public sealed class KubernetesReader : IKubernetesReader, IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IKubernetes client;
    private readonly SecretSanitizer secretSanitizer;
    private readonly KubeMcpOptions options;
    private readonly SemaphoreSlim discoveryLock = new(1, 1);
    private IReadOnlyList<KubernetesResourceDescriptor>? discoveredResources;
    private DateTimeOffset discoveryExpiresAt;

    public KubernetesReader(
        SecretSanitizer secretSanitizer,
        IOptions<KubeMcpOptions> options)
    {
        this.secretSanitizer = secretSanitizer;
        this.options = options.Value;

        var configuration = string.IsNullOrWhiteSpace(this.options.KubeConfigPath)
            ? KubernetesClientConfiguration.BuildDefaultConfig()
            : KubernetesClientConfiguration.BuildConfigFromConfigFile(this.options.KubeConfigPath);
        client = new k8s.Kubernetes(configuration);
    }

    public async Task<string> ReadAsync(
        string resource,
        string @namespace,
        string? name,
        CancellationToken cancellationToken)
    {
        resource = RequiredValue(resource, nameof(resource));
        @namespace = RequiredValue(@namespace, nameof(@namespace));
        name = name is null ? null : RequiredValue(name, nameof(name));
        KubernetesNameValidator.ValidateNamespace(@namespace);
        if (name is not null)
        {
            KubernetesNameValidator.ValidateResourceName(name);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.KubernetesRequestTimeoutSeconds));

        try
        {
            var descriptor = await ResolveResourceAsync(
                resource,
                listOperation: name is null,
                timeout.Token);

            JsonNode safeResult = name is null
                ? await ListAsync(descriptor, @namespace, timeout.Token)
                : await GetAsync(descriptor, @namespace, name, timeout.Token);

            var json = safeResult.ToJsonString(SerializerOptions);
            if (Encoding.UTF8.GetByteCount(json) > options.MaxResponseBytes)
            {
                throw new KubernetesReadException(
                    $"The Kubernetes response exceeded the configured {options.MaxResponseBytes}-byte limit.");
            }

            return json;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new KubernetesReadException("The Kubernetes request timed out.");
        }
    }

    private async Task<JsonNode> GetAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string name,
        CancellationToken cancellationToken)
    {
        using var genericClient = new GenericClient(
            client,
            descriptor.Group,
            descriptor.Version,
            descriptor.Resource,
            disposeClient: false);

        var item = await genericClient.ReadNamespacedAsync<DynamicKubernetesObject>(
            @namespace,
            name,
            cancellationToken);

        return descriptor.IsSecret
            ? secretSanitizer.SanitizeGet(item)
            : ToJsonObject(item);
    }

    private async Task<JsonNode> ListAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        CancellationToken cancellationToken)
    {
        using var genericClient = new GenericClient(
            client,
            descriptor.Group,
            descriptor.Version,
            descriptor.Resource,
            disposeClient: false);

        var list = await genericClient.ListNamespacedAsync<DynamicKubernetesObjectList>(
            @namespace,
            limit: options.MaxListItems,
            cancel: cancellationToken);

        var items = new JsonArray();
        foreach (var item in list.Items.Take(options.MaxListItems))
        {
            items.Add(descriptor.IsSecret
                ? secretSanitizer.SanitizeListItem(item)
                : CompactListItem(item, descriptor));
        }

        return new JsonObject
        {
            ["operation"] = "LIST",
            ["resource"] = descriptor.QualifiedName,
            ["namespace"] = @namespace,
            ["items"] = items,
            ["count"] = items.Count,
            ["limited"] = list.Items.Count > options.MaxListItems || HasContinueToken(list.Metadata)
        };
    }

    private async Task<KubernetesResourceDescriptor> ResolveResourceAsync(
        string requestedResource,
        bool listOperation,
        CancellationToken cancellationToken)
    {
        var resources = await GetDiscoveredResourcesAsync(cancellationToken);
        var requiredVerb = listOperation ? "list" : "get";
        var matches = resources
            .Where(resource => resource.Aliases.Contains(
                requestedResource,
                StringComparer.OrdinalIgnoreCase))
            .Where(resource => resource.Verbs.Contains(
                requiredVerb,
                StringComparer.OrdinalIgnoreCase))
            .ToArray();

        if (matches.Length == 0)
        {
            throw new KubernetesReadException(
                $"Namespaced resource \"{requestedResource}\" was not found in Kubernetes API discovery or does not support {requiredVerb.ToUpperInvariant()}.");
        }

        if (matches.Length > 1)
        {
            var names = string.Join(", ", matches.Select(match => match.QualifiedName).Order());
            throw new KubernetesReadException(
                $"Resource \"{requestedResource}\" is ambiguous; use one of: {names}.");
        }

        return matches[0];
    }

    private async Task<IReadOnlyList<KubernetesResourceDescriptor>> GetDiscoveredResourcesAsync(
        CancellationToken cancellationToken)
    {
        if (discoveredResources is not null && DateTimeOffset.UtcNow < discoveryExpiresAt)
        {
            return discoveredResources;
        }

        await discoveryLock.WaitAsync(cancellationToken);
        try
        {
            if (discoveredResources is not null && DateTimeOffset.UtcNow < discoveryExpiresAt)
            {
                return discoveredResources;
            }

            var discovered = new List<KubernetesResourceDescriptor>();
            var coreResources = await client.CoreV1.GetAPIResourcesAsync(cancellationToken);
            AddResources(discovered, string.Empty, "v1", coreResources.Resources);

            var apiGroups = await client.Apis.GetAPIVersionsAsync(cancellationToken);
            foreach (var group in apiGroups.Groups)
            {
                if (group.PreferredVersion is null)
                {
                    continue;
                }

                var groupResources = await client.CustomObjects.GetAPIResourcesAsync(
                    group.Name,
                    group.PreferredVersion.Version,
                    cancellationToken);
                AddResources(
                    discovered,
                    group.Name,
                    group.PreferredVersion.Version,
                    groupResources.Resources);
            }

            discoveredResources = discovered;
            discoveryExpiresAt = DateTimeOffset.UtcNow.AddSeconds(options.DiscoveryCacheSeconds);
            return discoveredResources;
        }
        finally
        {
            discoveryLock.Release();
        }
    }

    private static void AddResources(
        ICollection<KubernetesResourceDescriptor> destination,
        string group,
        string version,
        IEnumerable<V1APIResource> resources)
    {
        foreach (var resource in resources)
        {
            if (!resource.Namespaced || resource.Name.Contains('/'))
            {
                continue;
            }

            var qualifiedName = string.IsNullOrEmpty(group)
                ? resource.Name
                : $"{resource.Name}.{group}";
            var aliases = new List<string>
            {
                resource.Name,
                resource.SingularName,
                resource.Kind,
                qualifiedName
            };
            aliases.AddRange(resource.ShortNames ?? []);

            destination.Add(new KubernetesResourceDescriptor(
                group,
                version,
                resource.Name,
                resource.Kind,
                aliases.Where(alias => !string.IsNullOrWhiteSpace(alias)).Distinct().ToArray(),
                (resource.Verbs ?? []).ToArray()));
        }
    }

    private static JsonObject ToJsonObject(DynamicKubernetesObject item)
    {
        var result = new JsonObject
        {
            ["apiVersion"] = item.ApiVersion,
            ["kind"] = item.Kind
        };

        foreach (var (name, value) in item.Properties)
        {
            result[name] = JsonNode.Parse(value.GetRawText());
        }

        return result;
    }

    private static JsonObject CompactListItem(
        DynamicKubernetesObject item,
        KubernetesResourceDescriptor descriptor)
    {
        var apiVersion = string.IsNullOrWhiteSpace(item.ApiVersion)
            ? string.IsNullOrEmpty(descriptor.Group)
                ? descriptor.Version
                : $"{descriptor.Group}/{descriptor.Version}"
            : item.ApiVersion;
        var kind = string.IsNullOrWhiteSpace(item.Kind) ? descriptor.Kind : item.Kind;
        var result = new JsonObject
        {
            ["apiVersion"] = apiVersion,
            ["kind"] = kind
        };

        if (item.Properties.TryGetValue("metadata", out var metadata) &&
            metadata.ValueKind == JsonValueKind.Object)
        {
            var safeMetadata = new JsonObject();
            CopyProperty(metadata, safeMetadata, "name");
            CopyProperty(metadata, safeMetadata, "namespace");
            CopyProperty(metadata, safeMetadata, "creationTimestamp");
            CopyProperty(metadata, safeMetadata, "labels");
            result["metadata"] = safeMetadata;
        }

        if (item.Properties.TryGetValue("status", out var status))
        {
            result["status"] = JsonNode.Parse(status.GetRawText());
        }

        if (item.Properties.TryGetValue("type", out var type))
        {
            result["type"] = JsonNode.Parse(type.GetRawText());
        }

        return result;
    }

    private static void CopyProperty(JsonElement source, JsonObject target, string propertyName)
    {
        if (source.TryGetProperty(propertyName, out var value))
        {
            target[propertyName] = JsonNode.Parse(value.GetRawText());
        }
    }

    private static bool HasContinueToken(JsonElement metadata)
    {
        return metadata.ValueKind == JsonValueKind.Object &&
               metadata.TryGetProperty("continue", out var continueToken) &&
               continueToken.ValueKind == JsonValueKind.String &&
               !string.IsNullOrEmpty(continueToken.GetString());
    }

    private static string RequiredValue(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new KubernetesReadException($"{parameterName} is required.");
        }

        return value.Trim();
    }

    public void Dispose()
    {
        client.Dispose();
        discoveryLock.Dispose();
    }
}
