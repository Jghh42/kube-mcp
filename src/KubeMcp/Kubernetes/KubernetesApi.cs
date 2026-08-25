using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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
    private static readonly JsonSerializerOptions AccessReviewSerializerOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    internal const int MaximumContinueTokenBytes = 8 * 1024;

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

    public async Task<bool> IsResourceAccessAllowedAsync(
        KubernetesResourceDescriptor descriptor,
        string verb,
        string? @namespace,
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
                    verb,
                    @namespace
                }
            }
        }, AccessReviewSerializerOptions);
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
