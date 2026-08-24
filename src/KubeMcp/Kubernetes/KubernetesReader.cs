using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
    internal const int MaximumCachedDiscoveryResources = 2048;
    private const int MaximumAliasesPerDiscoveredResource = 16;

    private const string ListPrefix = "{\"operation\":\"LIST\",\"resource\":";
    private const string ListCanonicalResource = ",\"canonicalResource\":";
    private const string ListNamespace = ",\"namespace\":";
    private const string ListItems = ",\"items\":[";
    private const string ListCount = "],\"count\":";
    private const string ListLimited = ",\"limited\":";
    private const string ListSuffix = "}";

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false
    };
    private static readonly int ListFixedFramingBytes = Encoding.UTF8.GetByteCount(
        ListPrefix +
        ListCanonicalResource +
        ListNamespace +
        ListItems +
        ListCount +
        ListLimited +
        ListSuffix);

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
        // Reject an oversized caller value before trimming or copying it into
        // allowlist/discovery lookups and dynamic error text.
        KubernetesNameValidator.ValidateResourceIdentifierLength(resource);
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
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            throw new KubernetesReadException(
                "The Kubernetes request timed out.",
                KubernetesErrorCategory.Timeout);
        }
        catch (OperationCanceledException ex)
        {
            logger.LogWarning(
                "Unexpected Kubernetes cancellation: {ExceptionType}",
                ex.GetType().Name);
            throw new KubernetesReadException(
                "The Kubernetes API request failed.",
                KubernetesErrorCategory.Internal);
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

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var document = ParseBody(body);
            ValidateObjectIdentity(document.RootElement, descriptor, @namespace, name);
            cancellationToken.ThrowIfCancellationRequested();

            if (descriptor.IsSecret)
            {
                try
                {
                    // Sanitize directly from the document so raw Secret fields are
                    // not cloned into a second JsonElement backing buffer.
                    return secretSanitizer.SanitizeGet(document.RootElement);
                }
                catch (Exception ex) when (ex is KubernetesReadException or InvalidOperationException)
                {
                    // Invalid Secret data is malformed upstream content. Replace the
                    // sanitizer detail with the same fixed boundary category/message.
                    throw MalformedResponseException();
                }
            }

            DynamicKubernetesObject item;
            try
            {
                item = document.RootElement.Deserialize<DynamicKubernetesObject>(SerializerOptions) ??
                       throw MalformedResponseException();
            }
            catch (JsonException)
            {
                throw MalformedResponseException();
            }

            cancellationToken.ThrowIfCancellationRequested();
            return ToJsonObject(item);
        }
        finally
        {
            if (descriptor.IsSecret)
            {
                ZeroRawBody(body);
            }
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
        var itemsContentBytes = 0L;
        var requestedResourceBytes = SerializedStringByteCount(requestedResource);
        var canonicalResourceBytes = SerializedStringByteCount(descriptor.QualifiedName);
        var namespaceBytes = SerializedStringByteCount(@namespace);
        var seenContinueTokens = new HashSet<string>(
            Math.Min(options.MaxListPages, 100),
            StringComparer.Ordinal);
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
            string? nextContinue;

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                EnsureContinueTokenBounded(body.Span);
                using (var document = ParseBody(body))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var itemsElement = ValidateListIdentity(
                        document.RootElement,
                        descriptor);

                    nextContinue = ReadContinueToken(document.RootElement);
                    if (!string.IsNullOrEmpty(nextContinue) && !seenContinueTokens.Add(nextContinue))
                    {
                        throw MalformedResponseException();
                    }

                    // Validate every object in an already-fetched page, including
                    // entries omitted by a local output cap. Serialize each emitted
                    // safe summary once for exact O(n) compact UTF-8 accounting.
                    var sourceItemIndex = 0;
                    var sourceItemCount = itemsElement.GetArrayLength();
                    foreach (var itemElement in itemsElement.EnumerateArray())
                    {
                        sourceItemIndex++;
                        cancellationToken.ThrowIfCancellationRequested();
                        ValidateListObjectIdentity(
                            itemElement,
                            descriptor,
                            @namespace);

                        if (items.Count >= maxItems)
                        {
                            itemCapHit = true;
                        }

                        if (itemCapHit || budgetHit)
                        {
                            if (descriptor.IsSecret)
                            {
                                ValidateSecretListItem(itemElement);
                            }

                            continue;
                        }

                        JsonObject summary;
                        if (descriptor.IsSecret)
                        {
                            try
                            {
                                summary = listSummarizer.SummarizeSecret(itemElement);
                            }
                            catch (Exception ex) when (ex is KubernetesReadException or InvalidOperationException)
                            {
                                throw MalformedResponseException();
                            }
                        }
                        else
                        {
                            var item = ParseListItem(itemElement);
                            try
                            {
                                summary = listSummarizer.Summarize(item, descriptor);
                            }
                            catch (InvalidOperationException)
                            {
                                throw MalformedResponseException();
                            }
                        }

                        var summaryBytes = JsonSerializer.SerializeToUtf8Bytes(
                            summary,
                            SerializerOptions).LongLength;
                        var prospectiveItemsBytes = itemsContentBytes +
                            (items.Count == 0 ? 0 : 1) +
                            summaryBytes;
                        var prospectiveCount = items.Count + 1;
                        var completeResponseBytes = ListResponseByteCount(
                            requestedResourceBytes,
                            canonicalResourceBytes,
                            namespaceBytes,
                            prospectiveItemsBytes,
                            prospectiveCount,
                            limited: false);

                        if (completeResponseBytes > options.MaxResponseBytes)
                        {
                            var moreDataExists = sourceItemIndex < sourceItemCount ||
                                !string.IsNullOrEmpty(nextContinue);
                            var limitedResponseBytes = completeResponseBytes - 1;
                            if (moreDataExists && limitedResponseBytes <= options.MaxResponseBytes)
                            {
                                // The shorter `true` marker is now semantically
                                // accurate because this page or a continuation has
                                // known omitted data.
                                items.Add(summary);
                                itemsContentBytes = prospectiveItemsBytes;
                            }

                            budgetHit = true;
                            continue;
                        }

                        items.Add(summary);
                        itemsContentBytes = prospectiveItemsBytes;
                    }
                }
            }
            finally
            {
                if (descriptor.IsSecret)
                {
                    // JsonDocument can reference the input memory, so clear only
                    // after it and all per-item JsonElements have been disposed.
                    ZeroRawBody(body);
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

        // ReadAsync performs one final serialization guard for both GET and LIST,
        // verifying this incremental accounting without a trimming loop.
        return response;
    }

    private void ValidateSecretListItem(JsonElement item)
    {
        try
        {
            secretSanitizer.ValidateListItem(item);
        }
        catch (Exception ex) when (ex is KubernetesReadException or InvalidOperationException)
        {
            throw MalformedResponseException();
        }
    }

    private static long SerializedStringByteCount(string value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, SerializerOptions).LongLength;

    private static long ListResponseByteCount(
        long requestedResourceBytes,
        long canonicalResourceBytes,
        long namespaceBytes,
        long itemsContentBytes,
        int itemCount,
        bool limited) =>
        ListFixedFramingBytes +
        requestedResourceBytes +
        canonicalResourceBytes +
        namespaceBytes +
        itemsContentBytes +
        itemCount.ToString(CultureInfo.InvariantCulture).Length +
        (limited ? 4 : 5);

    private static JsonElement ValidateListIdentity(
        JsonElement root,
        KubernetesResourceDescriptor descriptor)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !RequiredIdentityString(root, "apiVersion").Equals(
                descriptor.ApiVersion,
                StringComparison.Ordinal) ||
            !RequiredIdentityString(root, "kind").Equals(
                descriptor.Kind + "List",
                StringComparison.Ordinal))
        {
            throw MalformedResponseException();
        }

        _ = RequiredIdentityObject(root, "metadata");
        var items = RequiredIdentityProperty(root, "items");
        if (items.ValueKind != JsonValueKind.Array)
        {
            throw MalformedResponseException();
        }

        return items;
    }

    private static void ValidateObjectIdentity(
        JsonElement item,
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string? expectedName)
    {
        if (item.ValueKind != JsonValueKind.Object ||
            !RequiredIdentityString(item, "apiVersion").Equals(
                descriptor.ApiVersion,
                StringComparison.Ordinal) ||
            !RequiredIdentityString(item, "kind").Equals(
                descriptor.Kind,
                StringComparison.Ordinal))
        {
            throw MalformedResponseException();
        }

        ValidateMetadataIdentity(
            RequiredIdentityObject(item, "metadata"),
            @namespace,
            expectedName);
    }

    private static void ValidateListObjectIdentity(
        JsonElement item,
        KubernetesResourceDescriptor descriptor,
        string @namespace)
    {
        if (item.ValueKind != JsonValueKind.Object)
        {
            throw MalformedResponseException();
        }

        // Kubernetes commonly omits TypeMeta (apiVersion/kind) from objects
        // embedded in typed LIST responses. The enclosing list TypeMeta is
        // required above; if an item does include either field, validate it
        // strictly so contradictory or case-confused identities are rejected.
        ValidateOptionalIdentityString(item, "apiVersion", descriptor.ApiVersion);
        ValidateOptionalIdentityString(item, "kind", descriptor.Kind);
        ValidateMetadataIdentity(
            RequiredIdentityObject(item, "metadata"),
            @namespace,
            expectedName: null);
    }

    private static void ValidateOptionalIdentityString(
        JsonElement parent,
        string propertyName,
        string expectedValue)
    {
        if (!TryGetExactProperty(parent, propertyName, out var value))
        {
            return;
        }

        if (value.ValueKind != JsonValueKind.String ||
            !string.Equals(value.GetString(), expectedValue, StringComparison.Ordinal))
        {
            throw MalformedResponseException();
        }
    }

    private static void ValidateMetadataIdentity(
        JsonElement metadata,
        string @namespace,
        string? expectedName)
    {
        var actualName = RequiredIdentityString(metadata, "name");
        var actualNamespace = RequiredIdentityString(metadata, "namespace");
        if ((expectedName is not null && !actualName.Equals(expectedName, StringComparison.Ordinal)) ||
            !actualNamespace.Equals(@namespace, StringComparison.Ordinal))
        {
            throw MalformedResponseException();
        }
    }

    private static JsonElement RequiredIdentityObject(
        JsonElement parent,
        string propertyName)
    {
        var result = RequiredIdentityProperty(parent, propertyName);
        if (result.ValueKind != JsonValueKind.Object)
        {
            throw MalformedResponseException();
        }

        return result;
    }

    private static string RequiredIdentityString(JsonElement parent, string propertyName)
    {
        var value = RequiredIdentityProperty(parent, propertyName);
        if (value.ValueKind != JsonValueKind.String)
        {
            throw MalformedResponseException();
        }

        string? result;
        try
        {
            result = value.GetString();
        }
        catch (InvalidOperationException)
        {
            throw MalformedResponseException();
        }

        if (string.IsNullOrWhiteSpace(result))
        {
            throw MalformedResponseException();
        }

        return result;
    }

    private static JsonElement RequiredIdentityProperty(
        JsonElement parent,
        string propertyName)
    {
        if (!TryGetExactProperty(parent, propertyName, out var value))
        {
            throw MalformedResponseException();
        }

        return value;
    }

    private static bool TryGetExactProperty(
        JsonElement parent,
        string propertyName,
        out JsonElement value)
    {
        value = default;
        var found = false;
        foreach (var property in parent.EnumerateObject())
        {
            if (!property.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (found || !property.NameEquals(propertyName))
            {
                throw MalformedResponseException();
            }

            found = true;
            value = property.Value;
        }

        return found;
    }

    private static void ZeroRawBody(ReadOnlyMemory<byte> body)
    {
        try
        {
            if (MemoryMarshal.TryGetArray(body, out var segment) && segment.Array is not null)
            {
                CryptographicOperations.ZeroMemory(segment.AsSpan());
            }
        }
        catch
        {
            // The API boundary permits arbitrary ReadOnlyMemory implementations.
            // Clearing is best effort and must not replace the safe result or the
            // original boundary error when a custom memory manager misbehaves.
        }
    }

    private static void EnsureContinueTokenBounded(ReadOnlySpan<byte> body)
    {
        try
        {
            var reader = new Utf8JsonReader(body, isFinalBlock: true, state: default);
            var readMetadataValue = false;
            var readContinueValue = false;
            var metadataObjectDepth = -1;
            while (reader.Read())
            {
                if (readMetadataValue)
                {
                    if (reader.TokenType == JsonTokenType.StartObject)
                    {
                        metadataObjectDepth = reader.CurrentDepth;
                    }

                    readMetadataValue = false;
                    continue;
                }

                if (readContinueValue)
                {
                    if (reader.TokenType == JsonTokenType.String &&
                        KubernetesApi.JsonStringExceedsUtf8ByteLimit(
                            ref reader,
                            KubernetesApi.MaximumContinueTokenBytes))
                    {
                        throw MalformedResponseException();
                    }

                    readContinueValue = false;
                    continue;
                }

                if (metadataObjectDepth >= 0 &&
                    reader.TokenType == JsonTokenType.EndObject &&
                    reader.CurrentDepth == metadataObjectDepth)
                {
                    metadataObjectDepth = -1;
                    continue;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    continue;
                }

                if (metadataObjectDepth < 0 &&
                    reader.CurrentDepth == 1 &&
                    reader.ValueTextEquals("metadata"u8))
                {
                    readMetadataValue = true;
                }
                else if (metadataObjectDepth >= 0 &&
                         reader.CurrentDepth == metadataObjectDepth + 1 &&
                         reader.ValueTextEquals("continue"u8))
                {
                    readContinueValue = true;
                }
            }
        }
        catch (JsonException)
        {
            throw MalformedResponseException();
        }
    }

    private static JsonDocument ParseBody(ReadOnlyMemory<byte> body)
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
        var metadata = RequiredIdentityObject(root, "metadata");
        if (!TryGetExactProperty(metadata, "continue", out var continueToken) ||
            continueToken.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (continueToken.ValueKind != JsonValueKind.String)
        {
            throw MalformedResponseException();
        }

        string? value;
        try
        {
            value = continueToken.GetString();
        }
        catch (InvalidOperationException)
        {
            throw MalformedResponseException();
        }

        if (value is not null &&
            Encoding.UTF8.GetByteCount(value) > KubernetesApi.MaximumContinueTokenBytes)
        {
            throw MalformedResponseException();
        }

        return value;
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

        ApiDiscoveryResult<ApiResourceInfo> coreResources;
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

        var discoveryComplete = coreResources.IsComplete;
        discoveryComplete &= AddDiscoveredResources(
            discovered,
            string.Empty,
            "v1",
            coreResources.Items,
            MaximumCachedDiscoveryResources);

        ApiDiscoveryResult<ApiGroupInfo> groups;
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
        var partialFailure = discoveryComplete && groups.IsComplete ? 0 : 1;
        var cachedResourceCount = discovered.Count;
        try
        {
            await Parallel.ForEachAsync(groups.Items, new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(1, options.DiscoveryParallelism),
                CancellationToken = cancellationToken
            }, async (group, token) =>
            {
                try
                {
                    if (Volatile.Read(ref cachedResourceCount) >= MaximumCachedDiscoveryResources)
                    {
                        Interlocked.Exchange(ref partialFailure, 1);
                        return;
                    }

                    var groupResources = await api.GetGroupResourcesAsync(
                        group.Name,
                        group.PreferredVersion,
                        options.MaxUpstreamBodyBytes,
                        token).ConfigureAwait(false);
                    if (!groupResources.IsComplete)
                    {
                        Interlocked.Exchange(ref partialFailure, 1);
                    }

                    var local = new List<DiscoveredResource>();
                    if (!AddDiscoveredResources(
                            local,
                            group.Name,
                            group.PreferredVersion,
                            groupResources.Items,
                            KubernetesApi.MaximumResourcesPerDiscoveryDocument))
                    {
                        Interlocked.Exchange(ref partialFailure, 1);
                    }

                    foreach (var discoveredResource in local)
                    {
                        var position = Interlocked.Increment(ref cachedResourceCount);
                        if (position > MaximumCachedDiscoveryResources)
                        {
                            Interlocked.Exchange(ref partialFailure, 1);
                            break;
                        }

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

    private static bool AddDiscoveredResources(
        ICollection<DiscoveredResource> destination,
        string group,
        string version,
        IEnumerable<ApiResourceInfo> resources,
        int maximumResources)
    {
        var complete = true;
        foreach (var resource in resources)
        {
            if (!resource.Namespaced || resource.Name.Contains('/'))
            {
                continue;
            }

            if (destination.Count >= maximumResources)
            {
                complete = false;
                break;
            }

            var descriptor = new KubernetesResourceDescriptor(
                group,
                version,
                resource.Name,
                resource.Kind);
            if (!IsBoundedDiscoveryValue(resource.Name) ||
                !IsBoundedDiscoveryValue(resource.Kind) ||
                !IsBoundedDiscoveryValue(descriptor.QualifiedName))
            {
                complete = false;
                continue;
            }

            var aliases = new List<string>(MaximumAliasesPerDiscoveredResource);
            var aliasCandidates = new[]
            {
                resource.Name,
                resource.SingularName,
                resource.Kind,
                descriptor.QualifiedName
            }.Concat(resource.ShortNames ?? []);
            foreach (var alias in aliasCandidates)
            {
                if (string.IsNullOrWhiteSpace(alias))
                {
                    continue;
                }

                if (!IsBoundedDiscoveryValue(alias))
                {
                    complete = false;
                    continue;
                }

                if (aliases.Contains(alias, StringComparer.Ordinal))
                {
                    continue;
                }

                if (aliases.Count >= MaximumAliasesPerDiscoveredResource)
                {
                    complete = false;
                    break;
                }

                aliases.Add(alias);
            }

            var verbs = (resource.Verbs ?? [])
                .Where(verb => verb.Equals("get", StringComparison.OrdinalIgnoreCase) ||
                               verb.Equals("list", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            destination.Add(new DiscoveredResource(descriptor, aliases, verbs));
        }

        return complete;
    }

    private static bool IsBoundedDiscoveryValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= KubernetesNameValidator.MaximumQualifiedNameLength;

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
