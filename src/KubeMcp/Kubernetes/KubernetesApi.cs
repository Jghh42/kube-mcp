using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using k8s;

namespace KubeMcp.Kubernetes;

/// <summary>
/// Default <see cref="IKubernetesApi"/> implementation. It reuses the official
/// client's authenticated HTTP pipeline but reads every response as a bounded
/// byte stream before parsing it.
/// </summary>
internal sealed class KubernetesApi : IKubernetesApi
{
    private const string JsonMediaType = "application/json";

    internal const int MaximumContinueTokenBytes = 8 * 1024;
    internal const int MaximumDiscoveryGroups = 256;
    internal const int MaximumResourcesPerDiscoveryDocument = 1024;
    private const int MaximumDiscoveryShortNames = 12;
    private const int MaximumDiscoveryVerbs = 32;
    private const int MaximumDiscoveryStringBytes = 512;

    private readonly k8s.Kubernetes client;
    private readonly bool ownsClient;
    private readonly string? tlsServerName;

    public KubernetesApi(
        k8s.Kubernetes client,
        bool ownsClient,
        string? tlsServerName = null)
    {
        this.client = client;
        this.ownsClient = ownsClient;
        this.tlsServerName = tlsServerName;
    }

    public Task<ReadOnlyMemory<byte>> GetNamespacedAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string name,
        int maxBodyBytes,
        CancellationToken cancellationToken) =>
        GetRawAsync(
            BuildGetUri(client.BaseUri, descriptor, @namespace, name),
            maxBodyBytes,
            cancellationToken,
            clearTemporaryBuffers: descriptor.IsSecret);

    public Task<ReadOnlyMemory<byte>> ListNamespacedAsync(
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        int pageSize,
        string? continueToken,
        int maxBodyBytes,
        CancellationToken cancellationToken) =>
        GetRawAsync(
            BuildListUri(client.BaseUri, descriptor, @namespace, pageSize, continueToken),
            maxBodyBytes,
            cancellationToken,
            clearTemporaryBuffers: descriptor.IsSecret);

    public async Task<ApiDiscoveryResult<ApiResourceInfo>> GetCoreResourcesAsync(
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var body = await GetRawAsync(
            AppendPath(client.BaseUri, "/api/v1"),
            maxBodyBytes,
            cancellationToken).ConfigureAwait(false);
        return ParseApiResources(body, cancellationToken);
    }

    public async Task<ApiDiscoveryResult<ApiGroupInfo>> GetApiGroupsAsync(
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var body = await GetRawAsync(
            AppendPath(client.BaseUri, "/apis"),
            maxBodyBytes,
            cancellationToken).ConfigureAwait(false);
        return ParseApiGroups(body, cancellationToken);
    }

    public async Task<ApiDiscoveryResult<ApiResourceInfo>> GetGroupResourcesAsync(
        string group,
        string version,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var path = $"/apis/{Uri.EscapeDataString(group)}/{Uri.EscapeDataString(version)}";
        var body = await GetRawAsync(
            AppendPath(client.BaseUri, path),
            maxBodyBytes,
            cancellationToken).ConfigureAwait(false);
        return ParseApiResources(body, cancellationToken);
    }

    public async Task<bool> IsResourceAccessAllowedAsync(
        KubernetesResourceDescriptor descriptor,
        string verb,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var uri = AppendPath(
            client.BaseUri,
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews");
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            apiVersion = "authorization.k8s.io/v1",
            kind = "SelfSubjectAccessReview",
            spec = new
            {
                resourceAttributes = new
                {
                    group = descriptor.Group,
                    resource = descriptor.Resource,
                    verb
                }
            }
        });
        using var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue(JsonMediaType);
        var body = await PostRawAsync(
            uri,
            content,
            maxBodyBytes,
            cancellationToken).ConfigureAwait(false);
        return ParseResourceAccessReview(body, cancellationToken);
    }

    public async Task<bool> NamespaceMatchesLabelSelectorAsync(
        string @namespace,
        string labelSelector,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var uri = BuildNamespaceListUri(client.BaseUri, @namespace, labelSelector);
        var body = await GetRawAsync(uri, maxBodyBytes, cancellationToken).ConfigureAwait(false);
        return ParseNamespaceMatch(body, @namespace, cancellationToken);
    }

    private async Task<ReadOnlyMemory<byte>> GetRawAsync(
        Uri uri,
        int maxBodyBytes,
        CancellationToken cancellationToken,
        bool clearTemporaryBuffers = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        return await SendRawAsync(
            request,
            maxBodyBytes,
            cancellationToken,
            clearTemporaryBuffers).ConfigureAwait(false);
    }

    private async Task<ReadOnlyMemory<byte>> PostRawAsync(
        Uri uri,
        HttpContent content,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = content
        };
        return await SendRawAsync(request, maxBodyBytes, cancellationToken).ConfigureAwait(false);
    }

    private async Task<ReadOnlyMemory<byte>> SendRawAsync(
        HttpRequestMessage request,
        int maxBodyBytes,
        CancellationToken cancellationToken,
        bool clearTemporaryBuffers = false)
    {
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonMediaType));
        var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);

        try
        {
            EnsureSuccess(response);
            return await ReadCappedAsync(
                response,
                maxBodyBytes,
                cancellationToken,
                clearTemporaryBuffers).ConfigureAwait(false);
        }
        catch (KubernetesApiException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            throw NetworkException();
        }
        finally
        {
            // Disposal is best effort. In particular, a faulty response/content
            // implementation must not prevent a successfully read sensitive body
            // from reaching the reader that owns its post-sanitization zeroing.
            try
            {
                response.Dispose();
            }
            catch
            {
                // Request/result handling takes precedence over disposal failures.
            }
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        try
        {
            // The generated Kubernetes client invokes this hook for every request.
            // Raw bounded requests must do the same so bearer/exec tokens are
            // applied and refreshed correctly.
            if (client.Credentials is not null)
            {
                await client.Credentials
                    .ProcessHttpRequestAsync(request, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!string.IsNullOrWhiteSpace(tlsServerName))
            {
                request.Headers.Host = tlsServerName;
            }

            return await client.HttpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            throw NetworkException();
        }
    }

    private static void EnsureSuccess(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var statusCode = (int)response.StatusCode;
        var category = MapErrorCategory(statusCode);

        // Do not read the upstream error body. Only the status-derived safe
        // category crosses the adapter boundary.
        throw new KubernetesApiException(category, SafeMessage(category), statusCode);
    }

    private static KubernetesApiException NetworkException() =>
        new(
            KubernetesErrorCategory.NetworkError,
            SafeMessage(KubernetesErrorCategory.NetworkError));

    internal static KubernetesErrorCategory MapErrorCategory(int statusCode) => statusCode switch
    {
        401 or 403 => KubernetesErrorCategory.AccessDenied,
        404 => KubernetesErrorCategory.NotFound,
        408 => KubernetesErrorCategory.Timeout,
        429 => KubernetesErrorCategory.RateLimited,
        504 => KubernetesErrorCategory.Timeout,
        >= 500 => KubernetesErrorCategory.ServerError,
        >= 400 => KubernetesErrorCategory.InvalidRequest,
        _ => KubernetesErrorCategory.Internal,
    };

    internal static string SafeMessage(KubernetesErrorCategory category) =>
        KubernetesErrorDetails.Get(category).Message;

    internal static Uri BuildGetUri(
        Uri baseUri,
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        string name)
    {
        var resourcePath = ResourcePath(descriptor, @namespace);
        return AppendPath(baseUri, $"{resourcePath}/{Uri.EscapeDataString(name)}");
    }

    internal static Uri BuildListUri(
        Uri baseUri,
        KubernetesResourceDescriptor descriptor,
        string @namespace,
        int pageSize,
        string? continueToken)
    {
        var query = $"?limit={pageSize}";
        if (!string.IsNullOrEmpty(continueToken))
        {
            if (Encoding.UTF8.GetByteCount(continueToken) > MaximumContinueTokenBytes)
            {
                throw MalformedResponseException();
            }

            query += "&continue=" + Uri.EscapeDataString(continueToken);
        }

        return AppendPath(baseUri, ResourcePath(descriptor, @namespace) + query);
    }

    internal static Uri BuildNamespaceListUri(
        Uri baseUri,
        string @namespace,
        string labelSelector)
    {
        var fieldSelector = Uri.EscapeDataString($"metadata.name={@namespace}");
        var escapedLabelSelector = Uri.EscapeDataString(labelSelector);
        return AppendPath(
            baseUri,
            $"/api/v1/namespaces?fieldSelector={fieldSelector}&labelSelector={escapedLabelSelector}&limit=1");
    }

    private static Uri AppendPath(Uri baseUri, string pathAndQuery)
    {
        var basePath = baseUri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        return new Uri($"{basePath}/{pathAndQuery.TrimStart('/')}", UriKind.Absolute);
    }

    private static string ResourcePath(
        KubernetesResourceDescriptor descriptor,
        string @namespace)
    {
        var groupPath = descriptor.Group.Length == 0
            ? $"/api/{Uri.EscapeDataString(descriptor.Version)}"
            : $"/apis/{Uri.EscapeDataString(descriptor.Group)}/{Uri.EscapeDataString(descriptor.Version)}";
        return $"{groupPath}/namespaces/{Uri.EscapeDataString(@namespace)}/{Uri.EscapeDataString(descriptor.Resource)}";
    }

    /// <summary>
    /// Rejects a declared oversized body before opening its stream, then reads
    /// at most one byte beyond the cap to detect an undeclared oversized body.
    /// </summary>
    internal static async Task<ReadOnlyMemory<byte>> ReadCappedAsync(
        HttpResponseMessage response,
        int maxBodyBytes,
        CancellationToken cancellationToken,
        bool clearTemporaryBuffers = false)
    {
        if (response.Content is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        if (response.Content.Headers.ContentLength is { } contentLength &&
            contentLength > maxBodyBytes)
        {
            throw ResponseTooLargeException();
        }

        var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return await ReadCappedAsync(
                stream,
                maxBodyBytes,
                cancellationToken,
                clearTemporaryBuffers).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                stream.Dispose();
            }
            catch
            {
                // A disposal failure cannot replace the bounded read result/error.
            }
        }
    }

    internal static async Task<ReadOnlyMemory<byte>> ReadCappedAsync(
        Stream stream,
        int maxBodyBytes,
        CancellationToken cancellationToken,
        bool clearTemporaryBuffers = false)
    {
        // Use one fixed backing array rather than a growing MemoryStream. Besides
        // keeping allocation within the configured cap, this ensures a sensitive
        // response never leaves abandoned expansion buffers that cannot be zeroed.
        var output = new byte[maxBodyBytes];
        var sentinel = new byte[1];
        var completed = false;

        try
        {
            var total = 0;
            while (total < output.Length)
            {
                var read = await stream
                    .ReadAsync(output.AsMemory(total), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    completed = true;
                    return new ReadOnlyMemory<byte>(output, 0, total);
                }

                total += read;
            }

            var extra = await stream
                .ReadAsync(sentinel, cancellationToken)
                .ConfigureAwait(false);
            if (extra != 0)
            {
                throw ResponseTooLargeException();
            }

            completed = true;
            return new ReadOnlyMemory<byte>(output, 0, total);
        }
        finally
        {
            if (clearTemporaryBuffers)
            {
                CryptographicOperations.ZeroMemory(sentinel);
                if (!completed)
                {
                    CryptographicOperations.ZeroMemory(output);
                }
            }
        }
    }

    private static KubernetesApiException ResponseTooLargeException() =>
        new(
            KubernetesErrorCategory.ResponseTooLarge,
            SafeMessage(KubernetesErrorCategory.ResponseTooLarge));

    private static ApiDiscoveryResult<ApiResourceInfo> ParseApiResources(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        EnsureDiscoveryDocumentBounded(body.Span, "resources"u8, cancellationToken);
        var reader = new Utf8JsonReader(body.Span, isFinalBlock: true, state: default);
        MoveToRootArray(ref reader, "resources"u8);
        var result = new List<ApiResourceInfo>();
        var complete = true;
        var resourcesSeen = 0;

        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                return new ApiDiscoveryResult<ApiResourceInfo>(result, complete);
            }

            if (resourcesSeen >= MaximumResourcesPerDiscoveryDocument)
            {
                return new ApiDiscoveryResult<ApiResourceInfo>(result, IsComplete: false);
            }

            resourcesSeen++;
            var resource = ReadApiResource(ref reader, out var resourceComplete);
            complete &= resourceComplete;
            if (resource is not null)
            {
                result.Add(resource);
            }
        }

        throw MalformedResponseException();
    }

    private static ApiDiscoveryResult<ApiGroupInfo> ParseApiGroups(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        EnsureDiscoveryDocumentBounded(body.Span, "groups"u8, cancellationToken);
        var reader = new Utf8JsonReader(body.Span, isFinalBlock: true, state: default);
        MoveToRootArray(ref reader, "groups"u8);
        var result = new List<ApiGroupInfo>();
        var complete = true;
        var groupsSeen = 0;

        while (reader.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                return new ApiDiscoveryResult<ApiGroupInfo>(result, complete);
            }

            if (groupsSeen >= MaximumDiscoveryGroups)
            {
                return new ApiDiscoveryResult<ApiGroupInfo>(result, IsComplete: false);
            }

            groupsSeen++;
            var group = ReadApiGroup(ref reader, out var groupComplete);
            complete &= groupComplete;
            if (group is not null)
            {
                result.Add(group);
            }
        }

        throw MalformedResponseException();
    }

    private static ApiResourceInfo? ReadApiResource(
        ref Utf8JsonReader reader,
        out bool complete)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw MalformedResponseException();
        }

        string? name = null;
        string? singularName = null;
        string? kind = null;
        bool? namespaced = null;
        IReadOnlyList<string>? shortNames = null;
        IReadOnlyList<string>? verbs = null;
        var shortNamesSeen = false;
        var verbsSeen = false;
        complete = true;

        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw MalformedResponseException();
            }

            var isName = reader.ValueTextEquals("name"u8);
            var isSingularName = reader.ValueTextEquals("singularName"u8);
            var isKind = reader.ValueTextEquals("kind"u8);
            var isNamespaced = reader.ValueTextEquals("namespaced"u8);
            var isShortNames = reader.ValueTextEquals("shortNames"u8);
            var isVerbs = reader.ValueTextEquals("verbs"u8);
            if (!reader.Read())
            {
                throw MalformedResponseException();
            }

            if (isName)
            {
                if (name is not null)
                {
                    throw MalformedResponseException();
                }

                name = ReadRequiredString(ref reader);
            }
            else if (isSingularName)
            {
                if (singularName is not null)
                {
                    throw MalformedResponseException();
                }

                singularName = ReadOptionalString(ref reader) ?? string.Empty;
            }
            else if (isKind)
            {
                if (kind is not null)
                {
                    throw MalformedResponseException();
                }

                kind = ReadRequiredString(ref reader);
            }
            else if (isNamespaced)
            {
                if (namespaced is not null ||
                    reader.TokenType is not (JsonTokenType.True or JsonTokenType.False))
                {
                    throw MalformedResponseException();
                }

                namespaced = reader.GetBoolean();
            }
            else if (isShortNames)
            {
                if (shortNamesSeen)
                {
                    throw MalformedResponseException();
                }

                shortNamesSeen = true;
                shortNames = ReadBoundedStringArray(
                    ref reader,
                    MaximumDiscoveryShortNames,
                    out var arrayComplete);
                complete &= arrayComplete;
            }
            else if (isVerbs)
            {
                if (verbsSeen)
                {
                    throw MalformedResponseException();
                }

                verbsSeen = true;
                verbs = ReadBoundedStringArray(
                    ref reader,
                    MaximumDiscoveryVerbs,
                    out var arrayComplete);
                complete &= arrayComplete;
            }
            else
            {
                reader.Skip();
            }
        }

        if (name is null || kind is null || namespaced is null)
        {
            throw MalformedResponseException();
        }

        singularName ??= string.Empty;
        if (!IsBoundedDiscoveryValue(name) ||
            !IsBoundedDiscoveryValue(kind) ||
            (singularName.Length > 0 && !IsBoundedDiscoveryValue(singularName)))
        {
            complete = false;
            return null;
        }

        return new ApiResourceInfo(
            name,
            singularName,
            kind,
            namespaced.Value,
            shortNames,
            verbs);
    }

    private static ApiGroupInfo? ReadApiGroup(
        ref Utf8JsonReader reader,
        out bool complete)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw MalformedResponseException();
        }

        string? name = null;
        string? preferredVersion = null;
        var preferredVersionSeen = false;
        complete = true;

        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw MalformedResponseException();
            }

            var isName = reader.ValueTextEquals("name"u8);
            var isPreferredVersion = reader.ValueTextEquals("preferredVersion"u8);
            if (!reader.Read())
            {
                throw MalformedResponseException();
            }

            if (isName)
            {
                if (name is not null)
                {
                    throw MalformedResponseException();
                }

                name = ReadRequiredString(ref reader);
            }
            else if (isPreferredVersion)
            {
                if (preferredVersionSeen)
                {
                    throw MalformedResponseException();
                }

                preferredVersionSeen = true;
                preferredVersion = ReadPreferredVersion(ref reader);
            }
            else
            {
                reader.Skip();
            }
        }

        if (name is null)
        {
            throw MalformedResponseException();
        }

        if (!preferredVersionSeen || preferredVersion is null ||
            !IsBoundedDiscoveryValue(name) ||
            !IsBoundedDiscoveryValue(preferredVersion))
        {
            complete = false;
            return null;
        }

        return new ApiGroupInfo(name, preferredVersion);
    }

    private static string? ReadPreferredVersion(ref Utf8JsonReader reader)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw MalformedResponseException();
        }

        string? version = null;
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw MalformedResponseException();
            }

            var isVersion = reader.ValueTextEquals("version"u8);
            if (!reader.Read())
            {
                throw MalformedResponseException();
            }

            if (isVersion)
            {
                if (version is not null)
                {
                    throw MalformedResponseException();
                }

                version = ReadRequiredString(ref reader);
            }
            else
            {
                reader.Skip();
            }
        }

        return version;
    }

    private static IReadOnlyList<string>? ReadBoundedStringArray(
        ref Utf8JsonReader reader,
        int maximumItems,
        out bool complete)
    {
        complete = true;
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw MalformedResponseException();
        }

        var result = new List<string>();
        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if (reader.TokenType != JsonTokenType.String)
            {
                throw MalformedResponseException();
            }

            if (result.Count >= maximumItems)
            {
                complete = false;
                continue;
            }

            var value = ReadJsonString(ref reader);
            if (!IsBoundedDiscoveryValue(value))
            {
                complete = false;
                continue;
            }

            result.Add(value);
        }

        return result;
    }

    private static string ReadRequiredString(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw MalformedResponseException();
        }

        return ReadJsonString(ref reader);
    }

    private static string? ReadOptionalString(ref Utf8JsonReader reader) =>
        reader.TokenType switch
        {
            JsonTokenType.Null => null,
            JsonTokenType.String => ReadJsonString(ref reader),
            _ => throw MalformedResponseException()
        };

    private static string ReadJsonString(ref Utf8JsonReader reader)
    {
        try
        {
            return reader.GetString()!;
        }
        catch (InvalidOperationException)
        {
            throw MalformedResponseException();
        }
    }

    private static bool ParseResourceAccessReview(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var document = ParseJson(body);
        cancellationToken.ThrowIfCancellationRequested();
        if (!document.RootElement.TryGetProperty("status", out var status))
        {
            throw MalformedResponseException();
        }

        EnsureObject(status);
        return RequiredBoolean(status, "allowed");
    }

    private static bool ParseNamespaceMatch(
        ReadOnlyMemory<byte> body,
        string @namespace,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var document = ParseJson(body);
        cancellationToken.ThrowIfCancellationRequested();
        var items = RequiredArray(document.RootElement, "items");
        foreach (var item in items.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureObject(item);
            if (!item.TryGetProperty("metadata", out var metadata))
            {
                throw MalformedResponseException();
            }

            EnsureObject(metadata);
            if (string.Equals(
                    RequiredString(metadata, "name"),
                    @namespace,
                    StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static void EnsureDiscoveryDocumentBounded(
        ReadOnlySpan<byte> body,
        ReadOnlySpan<byte> rootArrayProperty,
        CancellationToken cancellationToken)
    {
        try
        {
            var reader = new Utf8JsonReader(body, isFinalBlock: true, state: default);
            var rootArrayCount = 0;
            var tokensRead = 0;
            while (reader.Read())
            {
                if ((++tokensRead & 1023) == 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                if (reader.TokenType == JsonTokenType.String &&
                    JsonStringExceedsUtf8ByteLimit(
                        ref reader,
                        MaximumDiscoveryStringBytes))
                {
                    throw MalformedResponseException();
                }

                if (reader.TokenType == JsonTokenType.PropertyName &&
                    reader.CurrentDepth == 1 &&
                    reader.ValueTextEquals(rootArrayProperty) &&
                    ++rootArrayCount > 1)
                {
                    throw MalformedResponseException();
                }
            }

            if (rootArrayCount != 1)
            {
                throw MalformedResponseException();
            }
        }
        catch (JsonException)
        {
            throw MalformedResponseException();
        }
    }

    /// <summary>
    /// Measures an escaped JSON string without materializing it as a managed
    /// string. JSON escapes are longer than their decoded UTF-8 representation,
    /// so only values whose raw representation exceeds the cap need a bounded
    /// unescape pass.
    /// </summary>
    internal static bool JsonStringExceedsUtf8ByteLimit(
        ref Utf8JsonReader reader,
        int maximumBytes)
    {
        if (reader.TokenType is not (JsonTokenType.String or JsonTokenType.PropertyName))
        {
            throw new InvalidOperationException("The JSON token is not a string.");
        }

        if (!reader.ValueIsEscaped || reader.ValueSpan.Length <= maximumBytes)
        {
            return reader.ValueSpan.Length > maximumBytes;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(checked(maximumBytes + 1));
        try
        {
            try
            {
                return reader.CopyString(buffer.AsSpan(0, maximumBytes + 1)) > maximumBytes;
            }
            catch (ArgumentException)
            {
                // CopyString reports an undersized destination without allocating
                // the decoded value. The extra byte distinguishes an exact-cap
                // token from an oversized one.
                return true;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, maximumBytes + 1));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void MoveToRootArray(
        ref Utf8JsonReader reader,
        ReadOnlySpan<byte> propertyName)
    {
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw MalformedResponseException();
        }

        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw MalformedResponseException();
            }

            var isRequiredArray = reader.ValueTextEquals(propertyName);
            if (!reader.Read())
            {
                throw MalformedResponseException();
            }

            if (isRequiredArray)
            {
                if (reader.TokenType != JsonTokenType.StartArray)
                {
                    throw MalformedResponseException();
                }

                return;
            }

            reader.Skip();
        }

        throw MalformedResponseException();
    }

    private static JsonDocument ParseJson(ReadOnlyMemory<byte> body)
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

    private static JsonElement RequiredArray(JsonElement parent, string propertyName)
    {
        EnsureObject(parent);
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Array)
        {
            throw MalformedResponseException();
        }

        return value;
    }

    private static string RequiredString(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw MalformedResponseException();
        }

        return value.GetString()!;
    }

    private static bool RequiredBoolean(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw MalformedResponseException();
        }

        return value.GetBoolean();
    }

    private static bool IsBoundedDiscoveryValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= KubernetesNameValidator.MaximumQualifiedNameLength;

    private static void EnsureObject(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw MalformedResponseException();
        }
    }

    private static KubernetesApiException MalformedResponseException() =>
        new(
            KubernetesErrorCategory.MalformedResponse,
            SafeMessage(KubernetesErrorCategory.MalformedResponse));

    public void Dispose()
    {
        if (ownsClient)
        {
            client.Dispose();
        }
    }
}
