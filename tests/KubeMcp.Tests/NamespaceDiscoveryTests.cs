using System.Text;
using System.Text.Json;
using KubeMcp.Audit;
using KubeMcp.Configuration;
using KubeMcp.Kubernetes;
using KubeMcp.Mcp;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Timeouts;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol;

namespace KubeMcp.Tests;

public sealed class NamespaceDiscoveryReaderTests
{
    [Fact]
    public async Task BlacklistFiltersEveryPageWithoutMarkingFilteredResultsLimited()
    {
        var options = ReaderTestOptions.Options(
            namespacePolicy: new NamespacePolicyOptions
            {
                Mode = NamespacePolicyMode.Blacklist,
                DeniedNamespaces = ["kube-system"]
            },
            maxListItems: 5,
            listPageSize: 2);
        using var host = new ReaderHost(options);
        host.Api.NamespaceListHandler = (_, token, selector, _, _) =>
        {
            Assert.Null(selector);
            return Task.FromResult(token is null
                ? KubernetesJson.ListBody(
                    [KubernetesJson.NamespaceItem("kube-system")],
                    "page-2",
                    "v1",
                    "NamespaceList")
                : KubernetesJson.ListBody(
                    [KubernetesJson.NamespaceItem("new-application")],
                    null,
                    "v1",
                    "NamespaceList"));
        };

        var result = await host.Reader.ListNamespacesAsync(CancellationToken.None);

        using var json = JsonDocument.Parse(result.Json);
        var root = json.RootElement;
        Assert.Equal(
            ["count", "items", "limited", "operation", "resource"],
            root.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.Equal("LIST", root.GetProperty("operation").GetString());
        Assert.Equal("namespaces", root.GetProperty("resource").GetString());
        Assert.Equal(1, root.GetProperty("count").GetInt32());
        Assert.False(root.GetProperty("limited").GetBoolean());
        var item = Assert.Single(root.GetProperty("items").EnumerateArray());
        Assert.Equal(
            ["age", "name"],
            item.EnumerateObject().Select(property => property.Name).Order().ToArray());
        Assert.Equal("new-application", item.GetProperty("name").GetString());
        Assert.Equal("0s", item.GetProperty("age").GetString());
        Assert.DoesNotContain("sensitive", result.Json);
        Assert.DoesNotContain("status", result.Json);
        Assert.Equal(2, host.Api.Calls.Count);
    }

    [Fact]
    public async Task LabelSelectorIsSentOnEveryContinuationPage()
    {
        var options = ReaderTestOptions.Options(
            namespacePolicy: new NamespacePolicyOptions
            {
                Mode = NamespacePolicyMode.LabelSelector,
                LabelSelector = "environment=production"
            },
            listPageSize: 1);
        using var host = new ReaderHost(options);
        var selectors = new List<string?>();
        host.Api.NamespaceListHandler = (_, token, selector, _, _) =>
        {
            selectors.Add(selector);
            return Task.FromResult(KubernetesJson.ListBody(
                [KubernetesJson.NamespaceItem(token is null ? "prod-a" : "prod-b")],
                token is null ? "next" : null,
                "v1",
                "NamespaceList"));
        };

        var result = await host.Reader.ListNamespacesAsync(CancellationToken.None);

        Assert.Equal(["environment=production", "environment=production"], selectors);
        Assert.Equal(2, result.ObjectCount);
        Assert.DoesNotContain(host.Api.Calls, call => call.StartsWith("NSCHECK", StringComparison.Ordinal));
    }

    [Fact]
    public async Task DiscoveryDoesNotResolveAllowedResources()
    {
        var options = ReaderTestOptions.Options(resources: new()
        {
            ["only-unrelated-widgets"] = ReaderTestOptions.R("example.test", "v1", "widgets", "Widget")
        });
        using var host = new ReaderHost(options);
        host.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody([KubernetesJson.NamespaceItem("production")], null, "v1", "NamespaceList"));

        var result = await host.Reader.ListNamespacesAsync(CancellationToken.None);

        Assert.Equal(1, result.ObjectCount);
        Assert.Single(host.Api.Calls);
    }

    [Fact]
    public async Task MalformedFilteredAndOutputOmittedObjectsAreRejected()
    {
        var blacklist = ReaderTestOptions.Options(
            namespacePolicy: new NamespacePolicyOptions
            {
                Mode = NamespacePolicyMode.Blacklist,
                DeniedNamespaces = ["kube-system"]
            });
        using (var host = new ReaderHost(blacklist))
        {
            host.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
                KubernetesJson.ListBody(
                    [KubernetesJson.NamespaceItem("kube-system", apiVersion: "apps/v1")],
                    null,
                    "v1",
                    "NamespaceList"));

            var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
                host.Reader.ListNamespacesAsync(CancellationToken.None));
            Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        }

        using (var host = new ReaderHost(ReaderTestOptions.Options(maxListItems: 1)))
        {
            host.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
                KubernetesJson.ListBody(
                    [
                        KubernetesJson.NamespaceItem("production"),
                        KubernetesJson.NamespaceItem("bad_name")
                    ],
                    null,
                    "v1",
                    "NamespaceList"));

            var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
                host.Reader.ListNamespacesAsync(CancellationToken.None));
            Assert.Equal(KubernetesErrorCategory.MalformedResponse, exception.Category);
        }
    }

    [Fact]
    public async Task ExistingItemPageAndSafeOutputBoundsApply()
    {
        using (var itemHost = new ReaderHost(ReaderTestOptions.Options(maxListItems: 1)))
        {
            itemHost.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
                KubernetesJson.ListBody(
                    [KubernetesJson.NamespaceItem("one"), KubernetesJson.NamespaceItem("two")],
                    null,
                    "v1",
                    "NamespaceList"));
            using var json = JsonDocument.Parse(
                (await itemHost.Reader.ListNamespacesAsync(CancellationToken.None)).Json);
            Assert.Equal(1, json.RootElement.GetProperty("count").GetInt32());
            Assert.True(json.RootElement.GetProperty("limited").GetBoolean());
        }

        using (var pageHost = new ReaderHost(ReaderTestOptions.Options(maxListPages: 1)))
        {
            pageHost.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
                KubernetesJson.ListBody([], "more", "v1", "NamespaceList"));
            using var json = JsonDocument.Parse(
                (await pageHost.Reader.ListNamespacesAsync(CancellationToken.None)).Json);
            Assert.True(json.RootElement.GetProperty("limited").GetBoolean());
            Assert.Single(pageHost.Api.Calls);
        }

        var body = KubernetesJson.ListBody(
            [KubernetesJson.NamespaceItem("production")], null, "v1", "NamespaceList");
        using var baseline = new ReaderHost(ReaderTestOptions.Options());
        baseline.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(body);
        var complete = await baseline.Reader.ListNamespacesAsync(CancellationToken.None);
        var exactBytes = Encoding.UTF8.GetByteCount(complete.Json);

        using var exact = new ReaderHost(ReaderTestOptions.Options(maxResponseBytes: exactBytes));
        exact.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(body);
        Assert.Equal(1, (await exact.Reader.ListNamespacesAsync(CancellationToken.None)).ObjectCount);

        using var shortHost = new ReaderHost(ReaderTestOptions.Options(maxResponseBytes: exactBytes - 1));
        shortHost.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(body);
        using var shortJson = JsonDocument.Parse(
            (await shortHost.Reader.ListNamespacesAsync(CancellationToken.None)).Json);
        Assert.Equal(0, shortJson.RootElement.GetProperty("count").GetInt32());
        Assert.True(shortJson.RootElement.GetProperty("limited").GetBoolean());
    }

    [Fact]
    public async Task SafeOutputAccountingRetainsItemWhenOnlyLimitedTrueFitsAndMoreDataExists()
    {
        const string expected =
            "{\"operation\":\"LIST\",\"resource\":\"namespaces\",\"items\":[{\"name\":\"production\",\"age\":\"0s\"}],\"count\":1,\"limited\":true}";
        var maxResponseBytes = Encoding.UTF8.GetByteCount(expected);
        using var host = new ReaderHost(
            ReaderTestOptions.Options(maxResponseBytes: maxResponseBytes));
        host.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody(
                [
                    KubernetesJson.NamespaceItem("production"),
                    KubernetesJson.NamespaceItem("staging")
                ],
                null,
                "v1",
                "NamespaceList"));

        var result = await host.Reader.ListNamespacesAsync(CancellationToken.None);

        Assert.Equal(expected, result.Json);
        Assert.Equal(maxResponseBytes, Encoding.UTF8.GetByteCount(result.Json));
        Assert.Equal(1, result.ObjectCount);
    }

    [Fact]
    public async Task SafeOutputAccountingDoesNotUseDeniedTrailingItemToJustifyExactFit()
    {
        const string retainedItemWithLimitedTrue =
            "{\"operation\":\"LIST\",\"resource\":\"namespaces\",\"items\":[{\"name\":\"production\",\"age\":\"0s\"}],\"count\":1,\"limited\":true}";
        const string expected =
            "{\"operation\":\"LIST\",\"resource\":\"namespaces\",\"items\":[],\"count\":0,\"limited\":true}";
        var options = ReaderTestOptions.Options(
            namespacePolicy: new NamespacePolicyOptions
            {
                Mode = NamespacePolicyMode.Blacklist,
                DeniedNamespaces = ["private-system"]
            },
            maxResponseBytes: Encoding.UTF8.GetByteCount(retainedItemWithLimitedTrue));
        using var host = new ReaderHost(options);
        host.Api.NamespaceListHandler = (_, _, _, _, _) => Task.FromResult(
            KubernetesJson.ListBody(
                [
                    KubernetesJson.NamespaceItem("production"),
                    KubernetesJson.NamespaceItem("private-system")
                ],
                null,
                "v1",
                "NamespaceList"));

        var result = await host.Reader.ListNamespacesAsync(CancellationToken.None);

        Assert.Equal(expected, result.Json);
        Assert.Equal(0, result.ObjectCount);
        Assert.DoesNotContain("production", result.Json);
        Assert.True(Encoding.UTF8.GetByteCount(result.Json) <= options.MaxResponseBytes);
    }

    [Fact]
    public async Task UpstreamErrorsTimeoutsAndCallerCancellationKeepExistingClassification()
    {
        using (var errorHost = new ReaderHost(ReaderTestOptions.Options()))
        {
            errorHost.Api.NamespaceListHandler = (_, _, _, _, _) =>
                Task.FromException<string>(new KubernetesApiException(
                    KubernetesErrorCategory.AccessDenied,
                    "sensitive"));
            var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
                errorHost.Reader.ListNamespacesAsync(CancellationToken.None));
            Assert.Equal(KubernetesErrorCategory.AccessDenied, exception.Category);
            Assert.DoesNotContain("sensitive", exception.Message);
        }

        using (var timeoutHost = new ReaderHost(
            ReaderTestOptions.Options(kubernetesRequestTimeoutSeconds: 1)))
        {
            timeoutHost.Api.NamespaceListHandler = async (_, _, _, _, token) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                return string.Empty;
            };
            var exception = await Assert.ThrowsAsync<KubernetesReadException>(() =>
                timeoutHost.Reader.ListNamespacesAsync(CancellationToken.None));
            Assert.Equal(KubernetesErrorCategory.Timeout, exception.Category);
        }

        using var cancellationHost = new ReaderHost(ReaderTestOptions.Options());
        cancellationHost.Api.NamespaceListHandler = async (_, _, _, _, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return string.Empty;
        };
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            cancellationHost.Reader.ListNamespacesAsync(cancellation.Token));
    }
}

public sealed class KubernetesListNamespacesToolTests
{
    [Fact]
    public async Task AuditsOneAggregateEventWithoutNamespaceNames()
    {
        var audit = new CapturingAudit();
        var tool = new KubernetesListNamespacesTool(
            new NamespaceReader(new KubernetesReadResult("{\"items\":[]}", 2)),
            audit,
            NullLogger<KubernetesListNamespacesTool>.Instance);

        Assert.Equal("{\"items\":[]}", await tool.ListAsync());
        var entry = Assert.Single(audit.Events);
        Assert.Equal("LIST", entry.Operation);
        Assert.Equal("namespaces", entry.Resource);
        Assert.Equal("-", entry.Namespace);
        Assert.Equal("-", entry.Name);
        Assert.Equal(2, entry.ObjectCount);
        Assert.Equal("success", entry.Category);
    }

    [Fact]
    public async Task MapsReaderFailureToFixedErrorAndAuditCategory()
    {
        var audit = new CapturingAudit();
        var tool = new KubernetesListNamespacesTool(
            new NamespaceReader(new KubernetesReadException(
                "namespace-name-must-not-leak",
                KubernetesErrorCategory.MalformedResponse)),
            audit,
            NullLogger<KubernetesListNamespacesTool>.Instance);

        var exception = await Assert.ThrowsAsync<McpException>(() => tool.ListAsync());

        Assert.Equal("The Kubernetes API returned a malformed response.", exception.Message);
        var entry = Assert.Single(audit.Events);
        Assert.Equal("upstream_malformed_response", entry.Category);
        Assert.Null(entry.ObjectCount);
    }

    [Fact]
    public async Task DistinguishesCallerCancellationFromServerDeadlineInAudit()
    {
        using var callerCancellation = new CancellationTokenSource();
        callerCancellation.Cancel();
        var callerAudit = new CapturingAudit();
        var callerTool = new KubernetesListNamespacesTool(
            new NamespaceReader(new OperationCanceledException(callerCancellation.Token)),
            callerAudit,
            NullLogger<KubernetesListNamespacesTool>.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            callerTool.ListAsync(callerCancellation.Token));

        var callerEntry = Assert.Single(callerAudit.Events);
        Assert.Equal("cancelled", callerEntry.Result);
        Assert.Equal(AuditCategories.ClientCancelled, callerEntry.Category);

        using var serverDeadline = new CancellationTokenSource();
        serverDeadline.Cancel();
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpRequestTimeoutFeature>(new TimeoutFeature(serverDeadline.Token));
        var serverAudit = new CapturingAudit();
        var serverTool = new KubernetesListNamespacesTool(
            new NamespaceReader(new OperationCanceledException(serverDeadline.Token)),
            serverAudit,
            NullLogger<KubernetesListNamespacesTool>.Instance,
            new HttpContextAccessor { HttpContext = context });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            serverTool.ListAsync(serverDeadline.Token));

        var serverEntry = Assert.Single(serverAudit.Events);
        Assert.Equal("timeout", serverEntry.Result);
        Assert.Equal(AuditCategories.ServerTimeout, serverEntry.Category);
    }

    private sealed class NamespaceReader : IKubernetesReader
    {
        private readonly KubernetesReadResult? result;
        private readonly Exception? exception;

        public NamespaceReader(KubernetesReadResult result) => this.result = result;
        public NamespaceReader(Exception exception) => this.exception = exception;

        public Task<KubernetesReadResult> ReadAsync(
            string resource, string @namespace, string? name, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<KubernetesReadResult> ListNamespacesAsync(CancellationToken cancellationToken) =>
            exception is null
                ? Task.FromResult(result!)
                : Task.FromException<KubernetesReadResult>(exception);
    }

    private sealed class CapturingAudit : IAuditLogger
    {
        public List<KubernetesAuditEvent> Events { get; } = [];
        public void LogKubernetesAccess(KubernetesAuditEvent auditEvent) => Events.Add(auditEvent);
        public void LogMcpAccessDenied(McpAccessDeniedAuditEvent auditEvent) { }
    }

    private sealed class TimeoutFeature(CancellationToken token) : IHttpRequestTimeoutFeature
    {
        public CancellationToken RequestTimeoutToken => token;
        public void DisableTimeout() { }
    }
}
