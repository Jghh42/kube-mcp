using System.Net;
using System.Net.Http.Headers;
using System.Text;
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
        var payload = Encoding.UTF8.GetBytes(new string('x', 10 * 1024));
        using var stream = new MemoryStream(payload);
        await Assert.ThrowsAsync<KubernetesApiException>(() =>
            KubernetesApi.ReadCappedAsync(stream, maxBodyBytes: 256, CancellationToken.None));
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
        var oversized = new string('x', 10 * 1024);
        var body = "{\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"big\"},\"data\":{\"k\":\"" + oversized + "\"}}";
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body)
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
    public async Task CoreDiscoveryParsesCappedApiResourceList()
    {
        const string body = """
            {
              "groupVersion": "v1",
              "resources": [
                {
                  "name": "pods",
                  "singularName": "pod",
                  "namespaced": true,
                  "kind": "Pod",
                  "verbs": ["get", "list"],
                  "shortNames": ["po"]
                }
              ]
            }
            """;
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body)
        });
        using var api = new KubernetesApi(k, ownsClient: true);

        var resources = await api.GetCoreResourcesAsync(4096, CancellationToken.None);

        var resource = Assert.Single(resources);
        Assert.Equal("pods", resource.Name);
        Assert.Equal("pod", resource.SingularName);
        Assert.Equal("Pod", resource.Kind);
        Assert.True(resource.Namespaced);
        Assert.Equal(["po"], resource.ShortNames);
        Assert.Equal(["get", "list"], resource.Verbs);
    }

    [Fact]
    public async Task ApiGroupDiscoveryParsesPreferredVersions()
    {
        const string body = """
            {
              "groups": [
                {
                  "name": "apps",
                  "preferredVersion": {
                    "groupVersion": "apps/v1",
                    "version": "v1"
                  }
                }
              ]
            }
            """;
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body)
        });
        using var api = new KubernetesApi(k, ownsClient: true);

        var groups = await api.GetApiGroupsAsync(4096, CancellationToken.None);

        Assert.Equal(new ApiGroupInfo("apps", "v1"), Assert.Single(groups));
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
    public async Task DiscoveryIsAlsoCappedBeforeParsing()
    {
        var body = "{\"resources\":[]}" + new string(' ', 4096);
        using var k = CreateClient(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body)
        });
        using var api = new KubernetesApi(k, ownsClient: true);

        var exception = await Assert.ThrowsAsync<KubernetesApiException>(() =>
            api.GetCoreResourcesAsync(maxBodyBytes: 128, CancellationToken.None));

        Assert.Equal(KubernetesErrorCategory.ResponseTooLarge, exception.Category);
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

    private sealed class StubHandler : DelegatingHandler
    {
        private readonly Func<HttpResponseMessage> respond;

        public StubHandler(Func<HttpResponseMessage> respond) => this.respond = respond;

        public List<Uri> Requests { get; } = [];

        public List<string?> AuthorizationHeaders { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            AuthorizationHeaders.Add(request.Headers.Authorization?.ToString());
            var response = respond();
            response.Content!.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            return Task.FromResult(response);
        }
    }
}
