using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using KubeMcp.Kubernetes;
using k8s;

namespace KubeMcp.Tests;

public sealed class KubernetesApiTests
{
    private static readonly Uri BaseUri = new("https://kube.example.internal:6443/");

    private static KubernetesResourceDescriptor Descriptor(string group, string version, string resource, string kind) =>
        new(group, version, resource, kind);

    [Theory]
    [InlineData(400, KubernetesErrorCategory.InvalidRequest)]
    [InlineData(401, KubernetesErrorCategory.AccessDenied)]
    [InlineData(403, KubernetesErrorCategory.AccessDenied)]
    [InlineData(404, KubernetesErrorCategory.NotFound)]
    [InlineData(408, KubernetesErrorCategory.Timeout)]
    [InlineData(409, KubernetesErrorCategory.InvalidRequest)]
    [InlineData(422, KubernetesErrorCategory.InvalidRequest)]
    [InlineData(429, KubernetesErrorCategory.RateLimited)]
    [InlineData(500, KubernetesErrorCategory.ServerError)]
    [InlineData(502, KubernetesErrorCategory.ServerError)]
    [InlineData(503, KubernetesErrorCategory.ServerError)]
    [InlineData(504, KubernetesErrorCategory.Timeout)]
    public void MapsHttpStatusCodesToSafeCategories(int statusCode, KubernetesErrorCategory expected)
    {
        Assert.Equal(expected, KubernetesApi.MapErrorCategory(statusCode));
    }

    [Fact]
    public void SafeMessagesNeverEmbedStructuredUpstreamData()
    {
        foreach (var category in Enum.GetValues<KubernetesErrorCategory>())
        {
            if (category == KubernetesErrorCategory.None)
            {
                continue;
            }

            var message = KubernetesApi.SafeMessage(category);
            Assert.False(string.IsNullOrWhiteSpace(message));
            // Safe messages are fixed, human-readable strings; they must never carry
            // upstream JSON, status payloads, or exception bodies.
            Assert.DoesNotContain("{", message);
            Assert.DoesNotContain("}", message);
            Assert.DoesNotContain("\"", message);
        }
    }

    [Fact]
    public async Task ReadCappedReturnsBodyAtExactLimit()
    {
        var payload = new byte[100];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)('a' + (i % 26));
        }

        using var stream = new MemoryStream(payload);
        var body = await KubernetesApi.ReadCappedAsync(stream, maxBodyBytes: 100, CancellationToken.None);

        Assert.Equal(100, body.Length);
    }

    [Fact]
    public async Task ReadCappedThrowsResponseTooLargeBeyondLimit()
    {
        var payload = new byte[101];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)('a' + (i % 26));
        }

        using var stream = new MemoryStream(payload);
        var exception = await Assert.ThrowsAsync<KubernetesApiException>(() =>
            KubernetesApi.ReadCappedAsync(stream, maxBodyBytes: 100, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.ResponseTooLarge, exception.Category);
        Assert.DoesNotContain("aaaa", exception.Message); // no body fragment
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public async Task ReadCappedStopsBeforeBufferingOversizedBody()
    {
        using var stream = new RepeatingByteStream(10 * 1024);

        await Assert.ThrowsAsync<KubernetesApiException>(() =>
            KubernetesApi.ReadCappedAsync(stream, maxBodyBytes: 256, CancellationToken.None));

        Assert.InRange(stream.BytesRead, 257, 257);
    }

    [Fact]
    public async Task SensitiveCappedReadClearsPartialBodyOnError()
    {
        using var stream = new RepeatingByteStream(10 * 1024);

        await Assert.ThrowsAsync<KubernetesApiException>(() =>
            KubernetesApi.ReadCappedAsync(
                stream,
                maxBodyBytes: 256,
                CancellationToken.None,
                clearTemporaryBuffers: true));

        Assert.False(stream.FirstReadBuffer.IsEmpty);
        Assert.All(stream.FirstReadBuffer.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public void BuildGetUriUsesCorePathForEmptyGroup()
    {
        var uri = KubernetesApi.BuildGetUri(BaseUri, Descriptor("", "v1", "pods", "Pod"), "production", "web-1");

        Assert.Equal("https://kube.example.internal:6443/api/v1/namespaces/production/pods/web-1", uri.ToString());
    }

    [Fact]
    public void BuildGetUriPreservesKubeconfigServerPathPrefix()
    {
        var uri = KubernetesApi.BuildGetUri(
            new Uri("https://rancher.example/k8s/clusters/c-1/"),
            Descriptor("", "v1", "pods", "Pod"),
            "production",
            "web-1");

        Assert.Equal(
            "https://rancher.example/k8s/clusters/c-1/api/v1/namespaces/production/pods/web-1",
            uri.AbsoluteUri);
    }

    [Fact]
    public void BuildGetUriUsesApisPathForGroupedResources()
    {
        var uri = KubernetesApi.BuildGetUri(
            BaseUri,
            Descriptor("postgresql.cnpg.io", "v1", "clusters", "Cluster"),
            "db",
            "pg-1");

        Assert.Equal(
            "https://kube.example.internal:6443/apis/postgresql.cnpg.io/v1/namespaces/db/clusters/pg-1",
            uri.ToString());
    }

    [Fact]
    public void BuildListUriAppliesPageSizeAndEscapesContinueToken()
    {
        var uri = KubernetesApi.BuildListUri(
            BaseUri,
            Descriptor("apps", "v1", "deployments", "Deployment"),
            "kube-mcp",
            pageSize: 25,
            continueToken: "abc 123/+=");

        Assert.Equal(
            "https://kube.example.internal:6443/apis/apps/v1/namespaces/kube-mcp/deployments?limit=25&continue=abc%20123%2F%2B%3D",
            uri.AbsoluteUri);
    }

    [Fact]
    public void BuildListUriRejectsOversizedContinueTokenBeforeEscaping()
    {
        var exception = Assert.Throws<KubernetesApiException>(() => KubernetesApi.BuildListUri(
            BaseUri,
            Descriptor("", "v1", "pods", "Pod"),
            "production",
            pageSize: 25,
            continueToken: new string('t', KubernetesApi.MaximumContinueTokenBytes + 1)));

        Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
    }

    [Fact]
    public async Task GetNamespacedReturnsCappedBodyAndDoesNotReadUpstreamErrorBody()
    {
        var secretLeak = "UPSTREAM-SECRET-BODY-MUST-NOT-LEAK";
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent(secretLeak)
        });
        using var api = new KubernetesApi(k, ownsClient: true);

        var exception = await Assert.ThrowsAsync<KubernetesApiException>(() =>
            api.GetNamespacedAsync(Descriptor("", "v1", "pods", "Pod"), "ns", "p1", maxBodyBytes: 4096, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.NotFound, exception.Category);
        Assert.Equal(404, exception.StatusCode);
        Assert.DoesNotContain(secretLeak, exception.Message);
    }

    [Fact]
    public async Task GetNamespacedEnforcesUpstreamBodyCapBeforeReturning()
    {
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new RepeatingByteStream(10 * 1024))
        });
        using var api = new KubernetesApi(k, ownsClient: true);

        await Assert.ThrowsAsync<KubernetesApiException>(() =>
            api.GetNamespacedAsync(Descriptor("", "v1", "configmaps", "ConfigMap"), "ns", "big", maxBodyBytes: 512, CancellationToken.None));
    }

    [Fact]
    public async Task ListNamespacedReturnsPageBody()
    {
        var body = "{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"continue\":\"token-2\"},\"items\":[]}";
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body)
        });
        using var api = new KubernetesApi(k, ownsClient: true);

        var result = await api.ListNamespacedAsync(
            Descriptor("", "v1", "pods", "Pod"), "ns", pageSize: 10, continueToken: null, maxBodyBytes: 4096, CancellationToken.None);

        Assert.Contains("token-2", Encoding.UTF8.GetString(result.Span));
    }

    [Fact]
    public async Task NamespaceLabelCheckUsesBoundedFilteredList()
    {
        var setup = CreateClientAndHandler(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"items\":[{\"metadata\":{\"name\":\"prod\"}}]}")
        });
        using var k = setup.Client;
        using var api = new KubernetesApi(k, ownsClient: true);

        var matches = await api.NamespaceMatchesLabelSelectorAsync(
            "prod",
            "environment=production",
            4096,
            CancellationToken.None);

        Assert.True(matches);
        var uri = Assert.Single(setup.Handler.Requests);
        Assert.Equal("/api/v1/namespaces", uri.AbsolutePath);
        Assert.Contains("fieldSelector=metadata.name%3Dprod", uri.Query);
        Assert.Contains("labelSelector=environment%3Dproduction", uri.Query);
        Assert.Contains("limit=1", uri.Query);
    }

    [Fact]
    public async Task RawRequestsApplyConfiguredKubernetesCredentials()
    {
        var setup = CreateClientAndHandler(
            () => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}")
            },
            accessToken: "rotating-token");
        using var k = setup.Client;
        using var api = new KubernetesApi(k, ownsClient: true);

        await api.GetNamespacedAsync(
            Descriptor("", "v1", "pods", "Pod"),
            "ns",
            "p1",
            maxBodyBytes: 4096,
            CancellationToken.None);

        Assert.Equal("Bearer rotating-token", Assert.Single(setup.Handler.AuthorizationHeaders));
    }

    [Fact]
    public async Task NetworkFailureMapsToSafeCategoryWithoutRetainingTransportException()
    {
        using var k = CreateClient(() => throw new HttpRequestException("network-detail"));
        using var api = new KubernetesApi(k, ownsClient: true);

        var exception = await Assert.ThrowsAsync<KubernetesApiException>(() =>
            api.GetNamespacedAsync(
                Descriptor("", "v1", "pods", "Pod"),
                "ns",
                "p1",
                maxBodyBytes: 4096,
                CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.NetworkError, exception.Category);
        Assert.DoesNotContain("network-detail", exception.ToString());
        Assert.Null(exception.InnerException);
    }

    private static k8s.Kubernetes CreateClient(Func<HttpResponseMessage> responder) =>
        CreateClientAndHandler(responder).Client;

    private static (k8s.Kubernetes Client, StubHandler Handler) CreateClientAndHandler(
        Func<HttpResponseMessage> responder,
        string? accessToken = null)
    {
        var configuration = new KubernetesClientConfiguration
        {
            Host = "https://kube.example.internal:6443",
            SkipTlsVerify = true,
            AccessToken = accessToken
        };

        var handler = new StubHandler(responder);
        return (new k8s.Kubernetes(configuration, new DelegatingHandler[] { handler }), handler);
    }

    private sealed class RepeatingByteStream : Stream
    {
        private readonly long length;
        private long remaining;

        public RepeatingByteStream(long length)
        {
            this.length = length;
            remaining = length;
        }

        public int BytesRead { get; private set; }
        public Memory<byte> FirstReadBuffer { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position
        {
            get => length - remaining;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = (int)Math.Min(count, remaining);
            buffer.AsSpan(offset, read).Fill((byte)'x');
            remaining -= read;
            BytesRead += read;
            return read;
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (FirstReadBuffer.IsEmpty)
            {
                FirstReadBuffer = buffer;
            }

            var read = (int)Math.Min(buffer.Length, remaining);
            buffer.Span[..read].Fill((byte)'x');
            remaining -= read;
            BytesRead += read;
            return ValueTask.FromResult(read);
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class StubHandler : DelegatingHandler
    {
        private readonly Func<HttpResponseMessage> respond;

        public StubHandler(Func<HttpResponseMessage> respond) => this.respond = respond;

        public List<Uri> Requests { get; } = [];

        public List<HttpMethod> Methods { get; } = [];

        public List<string> Bodies { get; } = [];

        public List<string?> AuthorizationHeaders { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            Methods.Add(request.Method);
            Bodies.Add(request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken));
            AuthorizationHeaders.Add(request.Headers.Authorization?.ToString());
            var response = respond();
            response.Content!.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return response;
        }
    }
}
