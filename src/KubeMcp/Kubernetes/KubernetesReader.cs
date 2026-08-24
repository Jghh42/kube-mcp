using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace KubeMcp.Kubernetes;

public sealed class KubernetesReader : IKubernetesReader, IDisposable
{
    private const int ListFrameOverheadBytes = 256;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IKubernetesApi api;
    private readonly SecretSanitizer secretSanitizer;
    private readonly KubernetesListSummarizer listSummarizer;
    private readonly ResourceAllowlist resourceAllowlist;
    private readonly NamespaceAccessPolicy namespacePolicy;
    private readonly KubeMcpOptions options;
    private readonly TimeProvider timeProvider;
    private readonly ILogger<KubernetesReader> logger;
    private readonly SemaphoreSlim discoveryLock = new(1, 1);
    private DiscoveryCache? discoveryCache;

    public KubernetesReader(
        SecretSanitizer secretSanitizer,
        KubernetesListSummarizer listSummarizer,
        ResourceAllowlist resourceAllowlist,
        NamespaceAccessPolicy namespacePolicy,
        IOptions<KubeMcpOptions> options,
        IKubernetesClientFactory? clientFactory = null,
        TimeProvider? timeProvider = null,
        ILogger<KubernetesReader>? logger = null)
    {
        this.secretSanitizer = secretSanitizer;
        this.listSummarizer = listSummarizer;
        this.resourceAllowlist = resourceAllowlist;
        this.namespacePolicy = namespacePolicy;
        this.options = options.Value;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.logger = logger ?? NullLogger<KubernetesReader>.Instance;

        var factory = clientFactory ?? new KubernetesClientFactory(this.options);
        api = factory.Create();
    }

    public async Task<KubernetesReadResult> ReadAsync(
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

        // Resolve the resource descriptor synchronously from the allowlist (no
        // network). In AllowAll mode the descriptor is resolved later via discovery.
        KubernetesResourceDescriptor? descriptor = resourceAllowlist.AllowsAll
            ? null
            : resourceAllowlist.Resolve(resource);

        // Static namespace denial (blacklist) happens before any Kubernetes call.
        namespacePolicy.EnsureStaticallyAllowed(@namespace);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.KubernetesRequestTimeoutSeconds));

        try
        {
            // Label-selector namespace check happens before discovery and before the
            // requested GET/LIST, and is the only Kubernetes call that may precede them.
            await EnsureNamespaceAllowedAsync(@namespace, timeout.Token).ConfigureAwait(false);
            descriptor ??= await ResolveDiscoveredResourceAsync(
                resource,
                requiredVerb: name is null ? "list" : "get",
                timeout.Token).ConfigureAwait(false);

            JsonNode safeResult = name is null
                ? await ListAsync(descriptor, resource, @namespace, timeout.Token).ConfigureAwait(false)
                : await GetAsync(descriptor, @namespace, name, timeout.Token).ConfigureAwait(false);

            var json = safeResult.ToJsonString(SerializerOptions);
            if (Encoding.UTF8.GetByteCount(json) > options.MaxResponseBytes)
            {
                throw new KubernetesReadException(
                    $"The Kubernetes response exceeded the configured {options.MaxResponseBytes}-byte limit.",
                    KubernetesErrorCategory.ResponseTooLarge);
            }

            return new KubernetesReadResult(
                json,
                name is null ? safeResult["count"]?.GetValue<int>() ?? 0 : 1,
                descriptor.IsSecret);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new KubernetesReadException(
                "The Kubernetes request timed out.",
                KubernetesErrorCategory.Timeout);
        }
        catch (KubernetesApiException ex)
        {
            throw Translate(ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not KubernetesReadException)
        {
            // Unexpected boundary failure: map to a safe internal category without
            // surfacing the exception body (which could carry upstream details).
            logger.LogWarning(
                "Unexpected Kubernetes boundary failure: {ExceptionType}",
                ex.GetType().Name);
            throw new KubernetesReadException(
                "The Kubernetes API request failed.",
                KubernetesErrorCategory.Internal);
        }
    }

    private async Task<JsonNode> GetAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string name,
        CancellationToken cancellationToken)
    {
        var body = await api.GetNamespacedAsync(
            descriptor, @namespace, name, options.MaxUpstreamBodyBytes, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        DynamicKubernetesObject item;
        try
        {
            item = JsonSerializer.Deserialize<DynamicKubernetesObject>(body.Span, SerializerOptions) ??
                   throw new KubernetesApiException(
                       KubernetesErrorCategory.MalformedResponse,
                       KubernetesApi.SafeMessage(KubernetesErrorCategory.MalformedResponse));
        }
        catch (JsonException)
        {
            throw new KubernetesApiException(
                KubernetesErrorCategory.MalformedResponse,
                KubernetesApi.SafeMessage(KubernetesErrorCategory.MalformedResponse));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!descriptor.IsSecret)
        {
            return ToJsonObject(item);
        }

        try
        {
            return secretSanitizer.SanitizeGet(item);
        }
        catch (KubernetesReadException)
        {
            // Invalid Secret data is malformed upstream content. Replace the
            // sanitizer detail with the same fixed boundary category/message.
            throw MalformedResponseException();
        }
    }

    private async Task<JsonNode> ListAsync(
        KubernetesResourceDescriptor descriptor,
        string requestedResource,
        string @namespace,
        CancellationToken cancellationToken)
    {
        var configuredPageSize = descriptor.IsSecret ? options.SecretListPageSize : options.ListPageSize;
        var maxItems = options.MaxListItems;
        var pageSize = Math.Min(configuredPageSize, maxItems);
        var items = new JsonArray();
        var itemCapHit = false;
        var budgetHit = false;
        var pageCapHit = false;
        var pagesFetched = 0;
        var seenContinueTokens = new HashSet<string>(StringComparer.Ordinal);
        string? continueToken = null;

        do
        {
            // Stop before fetching another page when the configured item count is reached;
            // this branch is only reached when a continue token indicates more data exists.
            if (items.Count >= maxItems)
            {
                itemCapHit = true;
                break;
            }

            // Kubernetes continuation tokens are replayed with the original query
            // shape, including a stable limit. Any final-page excess is discarded
            // locally when the item cap is reached.
            var body = await api.ListNamespacedAsync(
                descriptor, @namespace, pageSize, continueToken, options.MaxUpstreamBodyBytes, cancellationToken)
                .ConfigureAwait(false);
            pagesFetched++;
            cancellationToken.ThrowIfCancellationRequested();

            using var document = ParseListBody(body);
            cancellationToken.ThrowIfCancellationRequested();
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("items", out var itemsElement) ||
                itemsElement.ValueKind != JsonValueKind.Array)
            {
                throw new KubernetesApiException(
                    KubernetesErrorCategory.MalformedResponse,
                    KubernetesApi.SafeMessage(KubernetesErrorCategory.MalformedResponse));
            }

            string? nextContinue = ReadContinueToken(document.RootElement);
            if (!string.IsNullOrEmpty(nextContinue) && !seenContinueTokens.Add(nextContinue))
            {
                throw MalformedResponseException();
            }

            // Summarize each item and drop the raw object promptly so raw Secret
            // values do not outlive the page. Stop as soon as the item or safe
            // response budget is reached.
            foreach (var itemElement in itemsElement.EnumerateArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (items.Count >= maxItems)
                {
                    itemCapHit = true;
                    break;
                }

                var item = ParseListItem(itemElement);
                var summary = listSummarizer.Summarize(item, descriptor);
                items.Add(summary);

                if (Encoding.UTF8.GetByteCount(items.ToJsonString(SerializerOptions)) + ListFrameOverheadBytes >
                    options.MaxResponseBytes)
                {
                    items.RemoveAt(items.Count - 1);
                    budgetHit = true;
                    break;
                }
            }

            continueToken = nextContinue;
            if (itemCapHit || budgetHit)
            {
                break;
            }

            if (string.IsNullOrEmpty(continueToken))
            {
                break;
            }

            if (pagesFetched >= options.MaxListPages)
            {
                pageCapHit = true;
                break;
            }
        }
        while (true);

        var limited = itemCapHit || budgetHit || pageCapHit || !string.IsNullOrEmpty(continueToken);

        var response = new JsonObject
        {
            ["operation"] = "LIST",
            ["resource"] = requestedResource,
            ["canonicalResource"] = descriptor.QualifiedName,
            ["namespace"] = @namespace,
            ["items"] = items,
            ["count"] = items.Count,
            ["limited"] = limited
        };

        // Final guard so the serialized safe output never exceeds the budget even
        // when the per-item estimate under-counted the response framing.
        if (Encoding.UTF8.GetByteCount(response.ToJsonString(SerializerOptions)) > options.MaxResponseBytes)
        {
            limited = true;
            while (items.Count > 0 &&
                   Encoding.UTF8.GetByteCount(response.ToJsonString(SerializerOptions)) > options.MaxResponseBytes)
            {
                items.RemoveAt(items.Count - 1);
            }

            response["count"] = items.Count;
            response["limited"] = true;
        }

        return response;
    }

    private static JsonDocument ParseListBody(ReadOnlyMemory<byte> body)
    {
        try
        {
            return JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            throw MalformedResponseException();
        }
    }

    private static DynamicKubernetesObject ParseListItem(JsonElement item)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw MalformedResponseException();
        }

        try
        {
            return item.Deserialize<DynamicKubernetesObject>(SerializerOptions) ??
                   throw MalformedResponseException();
        }
        catch (JsonException)
        {
            throw MalformedResponseException();
        }
    }

    private static KubernetesApiException MalformedResponseException() =>
        new(
            KubernetesErrorCategory.MalformedResponse,
            KubernetesApi.SafeMessage(KubernetesErrorCategory.MalformedResponse));

    private static string? ReadContinueToken(JsonElement root)
    {
        if (!root.TryGetProperty("metadata", out var metadata) ||
            metadata.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (metadata.ValueKind != JsonValueKind.Object)
        {
            throw MalformedResponseException();
        }

        if (!metadata.TryGetProperty("continue", out var continueToken) ||
            continueToken.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (continueToken.ValueKind != JsonValueKind.String)
        {
            throw MalformedResponseException();
        }

        return continueToken.GetString();
    }

    private async Task EnsureNamespaceAllowedAsync(
        string @namespace,
        CancellationToken cancellationToken)
    {
        if (!namespacePolicy.RequiresLabelCheck)
        {
            return;
        }

        var matched = await api.NamespaceMatchesLabelSelectorAsync(
            @namespace,
            namespacePolicy.LabelSelector!,
            options.MaxUpstreamBodyBytes,
            cancellationToken).ConfigureAwait(false);
        namespacePolicy.EnsureLabelCheckMatched(@namespace, matched);
    }

    private async Task<KubernetesResourceDescriptor> ResolveDiscoveredResourceAsync(
        string requestedResource,
        string requiredVerb,
        CancellationToken cancellationToken)
    {
        var discovery = await GetDiscoveryAsync(cancellationToken).ConfigureAwait(false);
        var matches = discovery.Resources
            .Where(resource => resource.Aliases.Contains(
                requestedResource,
                StringComparer.OrdinalIgnoreCase))
            .Where(resource => resource.Verbs.Contains(
                requiredVerb,
                StringComparer.OrdinalIgnoreCase));

        if (!discovery.IsComplete)
        {
            // Missing groups can hide an alias collision. During partial discovery,
            // only a grouped resource's canonical qualified name is safe to resolve;
            // this makes a discovery failure reduce access rather than turning a
            // formerly ambiguous short alias into an allowed request.
            matches = matches.Where(resource =>
                resource.Descriptor.Group.Length > 0 &&
                resource.Descriptor.QualifiedName.Equals(
                    requestedResource,
                    StringComparison.OrdinalIgnoreCase));
        }

        var resolvedMatches = matches.ToArray();

        if (resolvedMatches.Length == 0)
        {
            throw new KubernetesReadException(
                $"Resource \"{requestedResource}\" was not found among namespaced Kubernetes resources supporting {requiredVerb.ToUpperInvariant()}.",
                KubernetesErrorCategory.NotFound);
        }

        if (resolvedMatches.Length > 1)
        {
            var names = string.Join(", ", resolvedMatches
                .Select(match => match.Descriptor.QualifiedName)
                .Order());
            throw new KubernetesReadException(
                $"Resource \"{requestedResource}\" is ambiguous; use one of: {names}.",
                KubernetesErrorCategory.InvalidRequest);
        }

        return resolvedMatches[0].Descriptor;
    }

    private async Task<DiscoveryCache> GetDiscoveryAsync(CancellationToken cancellationToken)
    {
        var cached = Volatile.Read(ref discoveryCache);
        if (cached is not null && timeProvider.GetUtcNow() < cached.ExpiresAt)
        {
            return cached;
        }

        await discoveryLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cached = Volatile.Read(ref discoveryCache);
            if (cached is not null && timeProvider.GetUtcNow() < cached.ExpiresAt)
            {
                return cached;
            }

            var (resources, coreAvailable, complete, failureCategory) =
                await DiscoverResourcesAsync(cancellationToken).ConfigureAwait(false);
            if (coreAvailable)
            {
                var cacheSeconds = complete
                    ? options.DiscoveryCacheSeconds
                    : Math.Min(options.DiscoveryCacheSeconds, 15);
                var refreshed = new DiscoveryCache(
                    resources,
                    complete,
                    timeProvider.GetUtcNow().AddSeconds(cacheSeconds));
                Volatile.Write(ref discoveryCache, refreshed);
                return refreshed;
            }

            // Total discovery failure: never expand access. Serve the last-known-good
            // stale cache if one exists, and use a short retry window so concurrent
            // requests do not serialize into repeated failing refreshes.
            if (cached is not null)
            {
                logger.LogWarning(
                    "Kubernetes discovery refresh failed; serving the last-known-good cached discovery.");
                var stale = cached with
                {
                    ExpiresAt = timeProvider.GetUtcNow().AddSeconds(
                        Math.Min(options.DiscoveryCacheSeconds, 15))
                };
                Volatile.Write(ref discoveryCache, stale);
                return stale;
            }

            var category = failureCategory ?? KubernetesErrorCategory.ServerError;
            throw new KubernetesReadException(
                KubernetesApi.SafeMessage(category),
                category);
        }
        finally
        {
            discoveryLock.Release();
        }
    }

    private async Task<(
        List<DiscoveredResource> Resources,
        bool CoreAvailable,
        bool Complete,
        KubernetesErrorCategory? FailureCategory)> DiscoverResourcesAsync(
        CancellationToken cancellationToken)
    {
        var discovered = new List<DiscoveredResource>();

        IReadOnlyList<ApiResourceInfo> coreResources;
        try
        {
            coreResources = await api.GetCoreResourcesAsync(
                options.MaxUpstreamBodyBytes,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                "Kubernetes core API discovery failed with {ExceptionType}; discovery is unavailable.",
                ex.GetType().Name);
            var category = ex is KubernetesApiException apiException
                ? apiException.Category
                : KubernetesErrorCategory.Internal;
            return (
                discovered,
                CoreAvailable: false,
                Complete: false,
                FailureCategory: category);
        }

        AddDiscoveredResources(discovered, string.Empty, "v1", coreResources);

        IReadOnlyList<ApiGroupInfo> groups;
        try
        {
            groups = await api.GetApiGroupsAsync(
                options.MaxUpstreamBodyBytes,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                "Kubernetes API group index discovery failed with {ExceptionType}; only core resources are available.",
                ex.GetType().Name);
            return (
                discovered,
                CoreAvailable: true,
                Complete: false,
                FailureCategory: null);
        }

        var bag = new ConcurrentBag<DiscoveredResource>();
        var partialFailure = 0;
        try
        {
            await Parallel.ForEachAsync(groups, new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(1, options.DiscoveryParallelism),
                CancellationToken = cancellationToken
            }, async (group, token) =>
            {
                try
                {
                    var groupResources = await api.GetGroupResourcesAsync(
                        group.Name,
                        group.PreferredVersion,
                        options.MaxUpstreamBodyBytes,
                        token).ConfigureAwait(false);
                    var local = new List<DiscoveredResource>();
                    AddDiscoveredResources(local, group.Name, group.PreferredVersion, groupResources);
                    foreach (var discoveredResource in local)
                    {
                        bag.Add(discoveredResource);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // A single unavailable aggregated API group reduces access to that
                    // group only; it must never abort discovery for unrelated groups.
                    Interlocked.Exchange(ref partialFailure, 1);
                    logger.LogWarning(
                        "Kubernetes API discovery for group {Group}/{Version} failed with {ExceptionType}; the group is unavailable.",
                        group.Name,
                        group.PreferredVersion,
                        ex.GetType().Name);
                }
            }).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }

        discovered.AddRange(bag);
        return (
            discovered,
            CoreAvailable: true,
            Complete: Volatile.Read(ref partialFailure) == 0,
            FailureCategory: null);
    }

    private static void AddDiscoveredResources(
        ICollection<DiscoveredResource> destination,
        string group,
        string version,
        IEnumerable<ApiResourceInfo> resources)
    {
        foreach (var resource in resources)
        {
            if (!resource.Namespaced || resource.Name.Contains('/'))
            {
                continue;
            }

            var descriptor = new KubernetesResourceDescriptor(
                group,
                version,
                resource.Name,
                resource.Kind);
            var aliases = new List<string>
            {
                resource.Name,
                resource.SingularName,
                resource.Kind,
                descriptor.QualifiedName
            };
            aliases.AddRange(resource.ShortNames ?? []);

            destination.Add(new DiscoveredResource(
                descriptor,
                aliases.Where(alias => !string.IsNullOrWhiteSpace(alias)).Distinct().ToArray(),
                (resource.Verbs ?? []).ToArray()));
        }
    }

    private static KubernetesReadException Translate(KubernetesApiException exception) =>
        new(KubernetesApi.SafeMessage(exception.Category), exception.Category);

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

    private static string RequiredValue(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new KubernetesReadException(
                $"{parameterName} is required.",
                KubernetesErrorCategory.InvalidRequest);
        }

        return value.Trim();
    }

    public void Dispose()
    {
        api.Dispose();
        discoveryLock.Dispose();
    }

    private sealed record DiscoveryCache(
        IReadOnlyList<DiscoveredResource> Resources,
        bool IsComplete,
        DateTimeOffset ExpiresAt);

    private sealed record DiscoveredResource(
        KubernetesResourceDescriptor Descriptor,
        IReadOnlyList<string> Aliases,
        IReadOnlyList<string> Verbs);
}
