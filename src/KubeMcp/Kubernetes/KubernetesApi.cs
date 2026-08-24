using System.Net.Http.Headers;
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
            cancellationToken);

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
            cancellationToken);

    public async Task<IReadOnlyList<ApiResourceInfo>> GetCoreResourcesAsync(
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var body = await GetRawAsync(
            AppendPath(client.BaseUri, "/api/v1"),
            maxBodyBytes,
            cancellationToken).ConfigureAwait(false);
        return ParseApiResources(body, cancellationToken);
    }

    public async Task<IReadOnlyList<ApiGroupInfo>> GetApiGroupsAsync(
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var body = await GetRawAsync(
            AppendPath(client.BaseUri, "/apis"),
            maxBodyBytes,
            cancellationToken).ConfigureAwait(false);
        return ParseApiGroups(body, cancellationToken);
    }

    public async Task<IReadOnlyList<ApiResourceInfo>> GetGroupResourcesAsync(
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
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        return await SendRawAsync(request, maxBodyBytes, cancellationToken).ConfigureAwait(false);
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
        CancellationToken cancellationToken)
    {
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(JsonMediaType));
        using var response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        EnsureSuccess(response);

        try
        {
            return await ReadCappedAsync(response, maxBodyBytes, cancellationToken).ConfigureAwait(false);
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
        CancellationToken cancellationToken)
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

        using var stream = await response.Content
            .ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        return await ReadCappedAsync(stream, maxBodyBytes, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<ReadOnlyMemory<byte>> ReadCappedAsync(
        Stream stream,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[Math.Min(8192, checked(maxBodyBytes + 1))];
        using var output = new MemoryStream();
        var total = 0;

        while (true)
        {
            var remainingWithSentinel = maxBodyBytes - total + 1;
            var read = await stream
                .ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remainingWithSentinel)), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (read > maxBodyBytes - total)
            {
                throw ResponseTooLargeException();
            }

            output.Write(buffer, 0, read);
            total += read;
        }

        return new ReadOnlyMemory<byte>(output.GetBuffer(), 0, checked((int)output.Length));
    }

    private static KubernetesApiException ResponseTooLargeException() =>
        new(
            KubernetesErrorCategory.ResponseTooLarge,
            SafeMessage(KubernetesErrorCategory.ResponseTooLarge));

    private static IReadOnlyList<ApiResourceInfo> ParseApiResources(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var document = ParseJson(body);
        cancellationToken.ThrowIfCancellationRequested();
        var resources = RequiredArray(document.RootElement, "resources");
        var result = new List<ApiResourceInfo>();

        foreach (var resource in resources.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureObject(resource);
            result.Add(new ApiResourceInfo(
                RequiredString(resource, "name"),
                OptionalString(resource, "singularName") ?? string.Empty,
                RequiredString(resource, "kind"),
                RequiredBoolean(resource, "namespaced"),
                OptionalStringArray(resource, "shortNames"),
                OptionalStringArray(resource, "verbs")));
        }

        return result;
    }

    private static IReadOnlyList<ApiGroupInfo> ParseApiGroups(
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var document = ParseJson(body);
        cancellationToken.ThrowIfCancellationRequested();
        var groups = RequiredArray(document.RootElement, "groups");
        var result = new List<ApiGroupInfo>();

        foreach (var group in groups.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureObject(group);
            var name = RequiredString(group, "name");
            if (!group.TryGetProperty("preferredVersion", out var preferredVersion) ||
                preferredVersion.ValueKind == JsonValueKind.Null)
            {
                continue;
            }

            EnsureObject(preferredVersion);
            var version = RequiredString(preferredVersion, "version");
            if (!string.IsNullOrWhiteSpace(version))
            {
                result.Add(new ApiGroupInfo(name, version));
            }
        }

        return result;
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

    private static string? OptionalString(JsonElement parent, string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw MalformedResponseException();
        }

        return value.GetString();
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

    private static IReadOnlyList<string>? OptionalStringArray(
        JsonElement parent,
        string propertyName)
    {
        if (!parent.TryGetProperty(propertyName, out var value) ||
            value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw MalformedResponseException();
        }

        var result = new List<string>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw MalformedResponseException();
            }

            result.Add(item.GetString()!);
        }

        return result;
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
