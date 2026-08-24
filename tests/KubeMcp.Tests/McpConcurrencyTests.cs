using System.Net;
using System.Net.Http.Headers;
using System.Threading.Channels;
using KubeMcp.Audit;
using KubeMcp.Kubernetes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ModelContextProtocol.Client;

namespace KubeMcp.Tests;

public sealed class McpConcurrencyTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-five-test-api-key-32-bytes-minimum";

    [Fact]
    public async Task AuthenticatedRequestsQueueWithinBoundAndRejectOverflow()
    {
        var reader = new GatedKubernetesReader();
        var auditSink = new CapturingAuditSink();
        await using var factory = CreateFactory(reader, auditSink, queueLimit: 1);
        var statusCapture = new StatusCaptureHandler();
        using var httpClient = factory.CreateDefaultClient(statusCapture);
        httpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", ApiKey);

        await using var transport1 = CreateTransport(httpClient, "concurrency-1");
        await using var mcpClient1 = await McpClient.CreateAsync(transport1);
        await using var transport2 = CreateTransport(httpClient, "concurrency-2");
        await using var mcpClient2 = await McpClient.CreateAsync(transport2);
        await using var transport3 = CreateTransport(httpClient, "concurrency-3");
        await using var mcpClient3 = await McpClient.CreateAsync(transport3);

        var first = CallToolAsync(mcpClient1);
        Assert.Equal(1, await reader.NextStartedAsync());

        var competing = new[]
        {
            CallToolAsync(mcpClient2),
            CallToolAsync(mcpClient3)
        };

        // With one active permit and one queue entry, exactly one additional
        // request must fail while the active request remains deliberately gated.
        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            await statusCapture.Rejection.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal(1, reader.StartedCount);

        reader.ReleaseOne();
        Assert.Equal(2, await reader.NextStartedAsync());
        reader.ReleaseOne();

        var outcomes = await Task.WhenAll(
            new[] { first }.Concat(competing).Select(ObserveAsync));
        Assert.Equal(2, outcomes.Count(static succeeded => succeeded));
        Assert.Equal(1, outcomes.Count(static succeeded => !succeeded));
        Assert.Equal(2, reader.StartedCount);

        var rejectionAudit = await auditSink.WaitForAsync(AuditCategories.RateLimited);
        Assert.Equal(AuditEventType.McpAccessDenied, rejectionAudit.EventType);
        Assert.Equal((int)HttpStatusCode.TooManyRequests, rejectionAudit.StatusCode);
        Assert.Equal("static-api-key", rejectionAudit.ClientIdentity);
        Assert.Null(rejectionAudit.Resource);
        Assert.Null(rejectionAudit.Namespace);
    }

    [Fact]
    public async Task SaturatedMcpLimiterFailsFastButDoesNotLimitHealthEndpoints()
    {
        var reader = new GatedKubernetesReader();
        var auditSink = new CapturingAuditSink();
        await using var factory = CreateFactory(reader, auditSink, queueLimit: 0);
        var statusCapture = new StatusCaptureHandler();
        using var httpClient = factory.CreateDefaultClient(statusCapture);
        httpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", ApiKey);
        await using var transport1 = CreateTransport(httpClient, "concurrency-health-1");
        await using var mcpClient1 = await McpClient.CreateAsync(transport1);
        await using var transport2 = CreateTransport(httpClient, "concurrency-health-2");
        await using var mcpClient2 = await McpClient.CreateAsync(transport2);

        var active = CallToolAsync(mcpClient1);
        Assert.Equal(1, await reader.NextStartedAsync());
        var overflow = CallToolAsync(mcpClient2);

        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            await statusCapture.Rejection.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        using var liveness = await httpClient.GetAsync("/healthz")
            .WaitAsync(TimeSpan.FromSeconds(2));

        Assert.False(await ObserveAsync(overflow));
        Assert.Equal(HttpStatusCode.OK, liveness.StatusCode);
        Assert.Equal("Healthy", await liveness.Content.ReadAsStringAsync());
        Assert.Equal(1, reader.StartedCount);

        reader.ReleaseOne();
        Assert.True(await ObserveAsync(active));
    }

    private static WebApplicationFactory<Program> CreateFactory(
        IKubernetesReader reader,
        IAuditSink auditSink,
        int queueLimit) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "ApiKey");
            builder.UseSetting("KubeMcp:Authentication:ApiKey", ApiKey);
            builder.UseSetting("KubeMcp:McpConcurrency:PermitLimit", "1");
            builder.UseSetting("KubeMcp:McpConcurrency:QueueLimit", queueLimit.ToString());
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IKubernetesReader>();
                services.AddSingleton(reader);
                services.AddSingleton(auditSink);
            });
        });

    private static HttpClientTransport CreateTransport(HttpClient httpClient, string name) =>
        new(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(httpClient.BaseAddress!, "/mcp"),
                Name = name
            },
            httpClient,
            loggerFactory: null,
            ownsHttpClient: false);

    private static Task CallToolAsync(McpClient client) =>
        client.CallToolAsync(
            "k8s_get",
            new Dictionary<string, object?>
            {
                ["resource"] = "pods",
                ["namespace"] = "default"
            },
            cancellationToken: CancellationToken.None).AsTask();

    private static async Task<bool> ObserveAsync(Task task)
    {
        try
        {
            await task;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private sealed class GatedKubernetesReader : IKubernetesReader
    {
        private readonly Channel<int> started = Channel.CreateUnbounded<int>();
        private readonly Channel<bool> releases = Channel.CreateUnbounded<bool>();
        private int startedCount;

        public int StartedCount => Volatile.Read(ref startedCount);

        public async Task<KubernetesReadResult> ReadAsync(
            string resource,
            string @namespace,
            string? name,
            CancellationToken cancellationToken)
        {
            var count = Interlocked.Increment(ref startedCount);
            started.Writer.TryWrite(count);
            await releases.Reader.ReadAsync(cancellationToken);
            return new KubernetesReadResult("{}", 1);
        }

        public async Task<int> NextStartedAsync() =>
            await started.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        public void ReleaseOne() => releases.Writer.TryWrite(true);
    }

    private sealed class StatusCaptureHandler : DelegatingHandler
    {
        public TaskCompletionSource<HttpStatusCode> Rejection { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Rejection.TrySetResult(response.StatusCode);
            }

            return response;
        }
    }

    private sealed class CapturingAuditSink : IAuditSink
    {
        private readonly object sync = new();
        private readonly List<AuditRecord> records = [];

        public ValueTask WriteAsync(AuditRecord record, CancellationToken cancellationToken)
        {
            lock (sync)
            {
                records.Add(record);
            }

            return ValueTask.CompletedTask;
        }

        public async Task<AuditRecord> WaitForAsync(string category)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                lock (sync)
                {
                    var found = records.FirstOrDefault(record => record.Category == category);
                    if (found is not null)
                    {
                        return found;
                    }
                }

                await Task.Delay(10);
            }

            throw new TimeoutException($"Audit category {category} was not delivered.");
        }
    }
}
