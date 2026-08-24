using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using KubeMcp.Audit;
using KubeMcp.Authentication;
using KubeMcp.Configuration;
using KubeMcp.Mcp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace KubeMcp.Tests;

public sealed class McpAdmissionTests
{
    private const string TestHmacKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    private const string ApiKey = "stage-five-test-api-key-32-bytes-minimum";

    [Fact]
    public async Task InvalidCredentialFloodHasBoundedAuthenticationAdmission()
    {
        var authentication = new GatedAuthenticationWork();
        var publisher = new CapturingPublisher();
        await using var factory = CreateFactory(services =>
        {
            services.RemoveAll<IAuthenticationHandlerProvider>();
            services.AddScoped<IAuthenticationHandlerProvider>(serviceProvider =>
                new GatedAuthenticationHandlerProvider(
                    serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>(),
                    authentication));
            services.RemoveAll<IAuditEventPublisher>();
            services.AddSingleton<IAuditEventPublisher>(publisher);
        }, new Dictionary<string, string?>
        {
            ["KubeMcp:McpAdmission:PermitLimit"] = "2",
            ["KubeMcp:McpAdmission:QueueLimit"] = "1",
            ["KubeMcp:McpConcurrency:PermitLimit"] = "1",
            ["KubeMcp:McpConcurrency:QueueLimit"] = "0"
        });
        using var client = factory.CreateClient();

        var requests = Enumerable.Range(0, 4)
            .Select(_ => client.PostAsync("/mcp", new StringContent("{}", null, "application/json")))
            .ToArray();
        await authentication.NextEnteredAsync();
        await authentication.NextEnteredAsync();

        Assert.Equal(2, authentication.ActiveCount);
        Assert.Equal(2, authentication.MaximumActiveCount);

        var overflowTask = await Task.WhenAny(requests).WaitAsync(TimeSpan.FromSeconds(5));
        using (var overflow = await overflowTask)
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, overflow.StatusCode);
        }

        authentication.ReleaseOne();
        await authentication.NextEnteredAsync();
        Assert.True(authentication.MaximumActiveCount <= 2);
        authentication.ReleaseOne();
        authentication.ReleaseOne();

        var remaining = requests.Where(request => request != overflowTask).ToArray();
        var responses = await Task.WhenAll(remaining).WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            Assert.All(responses, response => Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode));
            Assert.Equal(3, authentication.AuthenticationCount);
            Assert.Equal(3, publisher.Records.Count(record =>
                record.Category == AuditCategories.AuthenticationDenied));
            Assert.DoesNotContain(publisher.Records, record =>
                record.Category == AuditCategories.RateLimited);
        }
        finally
        {
            foreach (var response in responses)
            {
                response.Dispose();
            }
        }
    }

    [Fact]
    public async Task AdmissionQueueServesAuthenticatedCandidatesOldestFirst()
    {
        using var gate = new McpPreAuthenticationAdmissionGate(Options.Create(
            new KubeMcpOptions
            {
                McpAdmission = new McpAdmissionOptions
                {
                    PermitLimit = 1,
                    QueueLimit = 2
                }
            }));
        var active = await gate.AcquireAsync(CancellationToken.None);
        var oldest = gate.AcquireAsync(CancellationToken.None).AsTask();
        var newest = gate.AcquireAsync(CancellationToken.None).AsTask();

        active.Dispose();
        var oldestLease = await oldest.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(oldestLease.IsAcquired);
        Assert.False(newest.IsCompleted);

        oldestLease.Dispose();
        using var newestLease = await newest.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(newestLease.IsAcquired);
    }

    [Fact]
    public async Task OversizedMcpBodyReturns413BeforeAuthenticationParsingOrAudit()
    {
        var publisher = new CapturingPublisher();
        await using var factory = CreateFactory(services =>
        {
            services.RemoveAll<IAuditEventPublisher>();
            services.AddSingleton<IAuditEventPublisher>(publisher);
        });
        using var client = factory.CreateClient();
        using var content = new StringContent(
            new string('x', 64 * 1024 + 1),
            null,
            "application/json");

        using var response = await client.PostAsync("/mcp", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Empty(publisher.Records);
    }

    [Fact]
    public async Task McpBodyLimitPreservesStricterServerLimit()
    {
        var nextCalled = false;
        var context = new DefaultHttpContext();
        context.Request.ContentLength = 1025;
        var feature = new TestMaxRequestBodySizeFeature
        {
            MaxRequestBodySize = 1024
        };
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        var middleware = new McpRequestBodyLimitMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.Equal(1024, feature.MaxRequestBodySize);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task UnknownLengthBodyUsesServerFeatureAndMapsItsOverflowTo413()
    {
        var context = new DefaultHttpContext();
        var feature = new TestMaxRequestBodySizeFeature();
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        var middleware = new McpRequestBodyLimitMiddleware(_ =>
        {
            Assert.Equal(McpRequestBodyLimitMiddleware.MaximumBodyBytes, feature.MaxRequestBodySize);
            throw new BadHttpRequestException(
                "request body too large",
                StatusCodes.Status413PayloadTooLarge);
        });

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
    }

    private static WebApplicationFactory<Program> CreateFactory(
        Action<IServiceCollection> configureServices,
        IReadOnlyDictionary<string, string?>? settings = null) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("KubeMcp:SecretHmacKey", TestHmacKey);
            builder.UseSetting("KubeMcp:Authentication:Mode", "ApiKey");
            builder.UseSetting("KubeMcp:Authentication:ApiKey", ApiKey);
            foreach (var setting in settings ?? new Dictionary<string, string?>())
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureServices(configureServices);
        });

    private sealed class TestMaxRequestBodySizeFeature : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly { get; init; }

        public long? MaxRequestBodySize { get; set; }
    }

    private sealed class CapturingPublisher : IAuditEventPublisher
    {
        private readonly ConcurrentQueue<AuditRecord> records = new();

        public IReadOnlyCollection<AuditRecord> Records => records.ToArray();

        public bool TryPublish(AuditRecord record)
        {
            records.Enqueue(record);
            return true;
        }
    }

    private sealed class GatedAuthenticationWork
    {
        private readonly Channel<int> entered = Channel.CreateUnbounded<int>();
        private readonly Channel<bool> releases = Channel.CreateUnbounded<bool>();
        private int activeCount;
        private int authenticationCount;
        private int maximumActiveCount;

        public int ActiveCount => Volatile.Read(ref activeCount);

        public int AuthenticationCount => Volatile.Read(ref authenticationCount);

        public int MaximumActiveCount => Volatile.Read(ref maximumActiveCount);

        public async Task<AuthenticateResult> AuthenticateAsync(CancellationToken cancellationToken)
        {
            var invocation = Interlocked.Increment(ref authenticationCount);
            var active = Interlocked.Increment(ref activeCount);
            UpdateMaximum(active);
            entered.Writer.TryWrite(invocation);

            try
            {
                await releases.Reader.ReadAsync(cancellationToken);
                return AuthenticateResult.Fail("deliberate invalid credential");
            }
            finally
            {
                Interlocked.Decrement(ref activeCount);
            }
        }

        public Task<int> NextEnteredAsync() =>
            entered.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        public void ReleaseOne() => releases.Writer.TryWrite(true);

        private void UpdateMaximum(int candidate)
        {
            while (true)
            {
                var observed = Volatile.Read(ref maximumActiveCount);
                if (candidate <= observed ||
                    Interlocked.CompareExchange(ref maximumActiveCount, candidate, observed) == observed)
                {
                    return;
                }
            }
        }
    }

    private sealed class GatedAuthenticationHandlerProvider(
        IAuthenticationSchemeProvider schemeProvider,
        GatedAuthenticationWork work) : IAuthenticationHandlerProvider
    {
        private GatedAuthenticationHandler? handler;

        public async Task<IAuthenticationHandler?> GetHandlerAsync(
            HttpContext context,
            string authenticationScheme)
        {
            if (handler is not null)
            {
                return handler;
            }

            var scheme = await schemeProvider.GetSchemeAsync(authenticationScheme);
            if (scheme is null)
            {
                return null;
            }

            handler = new GatedAuthenticationHandler(work);
            await handler.InitializeAsync(scheme, context);
            return handler;
        }
    }

    private sealed class GatedAuthenticationHandler(GatedAuthenticationWork work)
        : IAuthenticationHandler
    {
        private HttpContext context = null!;

        public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
        {
            this.context = context;
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync() =>
            work.AuthenticateAsync(context.RequestAborted);

        public Task ChallengeAsync(AuthenticationProperties? properties)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        public Task ForbidAsync(AuthenticationProperties? properties)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
    }
}
