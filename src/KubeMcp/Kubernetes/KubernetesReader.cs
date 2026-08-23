using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.Security;
using k8s;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

public sealed class KubernetesReader : IKubernetesReader, IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IKubernetes client;
    private readonly SecretSanitizer secretSanitizer;
    private readonly KubernetesListSummarizer listSummarizer;
    private readonly ResourceAllowlist resourceAllowlist;
    private readonly NamespaceAccessPolicy namespacePolicy;
    private readonly KubeMcpOptions options;

    public KubernetesReader(
        SecretSanitizer secretSanitizer,
        KubernetesListSummarizer listSummarizer,
        ResourceAllowlist resourceAllowlist,
        NamespaceAccessPolicy namespacePolicy,
        IOptions<KubeMcpOptions> options)
    {
        this.secretSanitizer = secretSanitizer;
        this.listSummarizer = listSummarizer;
        this.resourceAllowlist = resourceAllowlist;
        this.namespacePolicy = namespacePolicy;
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

        var descriptor = resourceAllowlist.Resolve(resource);
        namespacePolicy.EnsureStaticallyAllowed(@namespace);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.KubernetesRequestTimeoutSeconds));

        try
        {
            await EnsureNamespaceAllowedAsync(@namespace, timeout.Token);

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
            items.Add(listSummarizer.Summarize(item, descriptor));
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

    private async Task EnsureNamespaceAllowedAsync(
        string @namespace,
        CancellationToken cancellationToken)
    {
        if (!namespacePolicy.RequiresLabelCheck)
        {
            return;
        }

        var matches = await client.CoreV1.ListNamespaceAsync(
            fieldSelector: $"metadata.name={@namespace}",
            labelSelector: namespacePolicy.LabelSelector,
            limit: 1,
            cancellationToken: cancellationToken);
        namespacePolicy.EnsureLabelCheckMatched(
            @namespace,
            matches.Items.Any(item => item.Metadata.Name == @namespace));
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
    }
}
