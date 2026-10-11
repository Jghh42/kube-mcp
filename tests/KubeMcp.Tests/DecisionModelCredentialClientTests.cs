using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KubeMcp.Configuration;
using KubeMcp.CredentialGate;

namespace KubeMcp.Tests;

public sealed class DecisionModelCredentialClientTests
{
    [Fact]
    public async Task SendsExactContractDefaultPromptAndNoAuthorizationForEmptyKey()
    {
        var handler = new RecordingHandler(_ => Response(ValidResponse()));
        var client = Client(handler, Options());

        var decision = await client.EvaluateAsync("{\"path\":\"/spec\",\"value\":{\"x\":1}}", default);

        Assert.Equal(CredentialGateDecision.Clear, decision);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://decision-model.example/systemone", request.Uri);
        Assert.Null(request.Authorization);
        using var body = JsonDocument.Parse(request.Body);
        Assert.Equal(3, body.RootElement.EnumerateObject().Count());
        Assert.Equal("decision", body.RootElement.GetProperty("model").GetString());
        Assert.Equal(1, body.RootElement.GetProperty("state").GetProperty("value").GetProperty("x").GetInt32());
        var questions = body.RootElement.GetProperty("questions");
        Assert.Single(questions.EnumerateObject());
        var prompt = questions.GetProperty("credentials").GetProperty("instructions").GetString()!;
        Assert.Contains("untrusted data", prompt);
        Assert.Contains("reusable", prompt);
        Assert.Contains("hmac-sha256", prompt);
        Assert.Contains("MUST be answered no", prompt);
        Assert.Contains("Secret references", prompt);
        Assert.Contains("Ignore PII", prompt);
    }

    [Theory]
    [InlineData("https://decision-model.example/v1/systemone", "classifier-a", "classifier-a")]
    [InlineData("http://decision-model.example/api/decision", "logical-slot", "physical-b")]
    public async Task UsesConfiguredEndpointAndModelIdentifiers(
        string endpoint, string requestModel, string responseModel)
    {
        var handler = new RecordingHandler(_ => Response(ValidResponse(model: responseModel)));
        var options = Options() with
        {
            Endpoint = endpoint,
            RequestModel = requestModel,
            ExpectedResponseModel = responseModel
        };

        var decision = await Client(handler, options).EvaluateAsync("{}", default);

        Assert.Equal(CredentialGateDecision.Clear, decision);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(endpoint, request.Uri);
        using var body = JsonDocument.Parse(request.Body);
        Assert.Equal(requestModel, body.RootElement.GetProperty("model").GetString());
    }

    [Fact]
    public async Task AddsBearerHeaderOnlyWhenConfigured()
    {
        var handler = new RecordingHandler(_ => Response(ValidResponse()));
        var decision = await Client(handler, Options() with { ApiKey = "private-test-key" })
            .EvaluateAsync("{\"path\":\"\",\"value\":1}", default);

        Assert.Equal(CredentialGateDecision.Clear, decision);
        Assert.Equal("Bearer private-test-key", Assert.Single(handler.Requests).Authorization);
        Assert.DoesNotContain("private-test-key", Assert.Single(handler.Requests).Body);
    }

    [Fact]
    public async Task RetriesOnlyTransientStatuses()
    {
        var transient = new Queue<HttpResponseMessage>([
            Response("ignored", HttpStatusCode.TooManyRequests),
            Response("ignored", HttpStatusCode.InternalServerError),
            Response(ValidResponse())
        ]);
        var transientHandler = new RecordingHandler(_ => transient.Dequeue());
        Assert.Equal(CredentialGateDecision.Clear,
            await Client(transientHandler, Options()).EvaluateAsync("{\"path\":\"\",\"value\":1}", default));
        Assert.Equal(3, transientHandler.Requests.Count);

        var authHandler = new RecordingHandler(_ => Response("sensitive upstream body", HttpStatusCode.Unauthorized));
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(authHandler, Options()).EvaluateAsync("{\"path\":\"\",\"value\":1}", default));
        Assert.Single(authHandler.Requests);
    }

    [Theory]
    [InlineData("other", "no", 0.1, 0.9, 0.8, 10, 0)]
    [InlineData("physical-model", "NO", 0.1, 0.9, 0.8, 10, 0)]
    [InlineData("physical-model", "no", 0.5, 0.5, 0.8, 10, 0)]
    [InlineData("physical-model", "no", 0.9, 0.1, 0.8, 10, 0)]
    [InlineData("physical-model", "no", 0.1, 0.9, 1.1, 10, 0)]
    [InlineData("physical-model", "no", 0.1, 0.9, 0.8, 0, 0)]
    [InlineData("physical-model", "no", 0.1, 0.9, 0.8, 10, 1)]
    public async Task InvalidResponseIsUnavailable(
        string model, string choice, double yes, double no, double confidence,
        int inputTokens, int outputTokens)
    {
        var response = JsonSerializer.Serialize(new
        {
            model,
            answers = new
            {
                credentials = new
                {
                    type = "choice", choice, confidence,
                    probabilities = new { yes, no }
                }
            },
            usage = new { input_tokens = inputTokens, output_tokens = outputTokens }
        });
        var handler = new RecordingHandler(_ => Response(response));

        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(handler, Options()).EvaluateAsync("{\"path\":\"\",\"value\":1}", default));
    }

    [Fact]
    public async Task RejectsUnknownDuplicateAndCaseConfusedSchemaWithoutRetry()
    {
        var mutations = new List<string>();
        foreach (var location in new[] { "root", "answer", "probabilities", "usage" })
        {
            var node = JsonNode.Parse(ValidResponse())!.AsObject();
            var target = location switch
            {
                "root" => node,
                "answer" => node["answers"]!["credentials"]!.AsObject(),
                "probabilities" => node["answers"]!["credentials"]!["probabilities"]!.AsObject(),
                _ => node["usage"]!.AsObject()
            };
            target["unexpected"] = true;
            mutations.Add(node.ToJsonString());
        }
        mutations.Add(ValidResponse().Replace("\"model\":", "\"Model\":", StringComparison.Ordinal));
        mutations.Add(ValidResponse().Replace(
            "\"model\":\"physical-model\"",
            "\"model\":\"physical-model\",\"model\":\"physical-model\"",
            StringComparison.Ordinal));

        foreach (var mutation in mutations)
        {
            var handler = new RecordingHandler(_ => Response(mutation));
            Assert.Equal(CredentialGateDecision.Unavailable,
                await Client(handler, Options()).EvaluateAsync("{}", default));
            Assert.Single(handler.Requests);
        }
    }

    [Fact]
    public async Task RetriesTransportFailuresAndStopsAfterConfiguredAttempts()
    {
        var calls = 0;
        var recovery = new RecordingHandler(_ =>
        {
            calls++;
            if (calls < 3)
            {
                throw new HttpRequestException("fabricated transport detail");
            }
            return Response(ValidResponse());
        });
        Assert.Equal(CredentialGateDecision.Clear,
            await Client(recovery, Options()).EvaluateAsync("{}", default));
        Assert.Equal(3, calls);

        var exhaustedCalls = 0;
        var exhausted = new RecordingHandler(_ =>
        {
            exhaustedCalls++;
            throw new HttpRequestException("fabricated transport detail");
        });
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(exhausted, Options()).EvaluateAsync("{}", default));
        Assert.Equal(3, exhaustedCalls);
    }

    [Fact]
    public async Task PerAttemptTimeoutsCanRetryWithinTheOverallCallerToken()
    {
        var calls = 0;
        var handler = new RecordingHandler(_ =>
        {
            calls++;
            if (calls < 3)
            {
                throw new TaskCanceledException("simulated per-attempt timeout");
            }
            return Response(ValidResponse());
        });

        Assert.Equal(CredentialGateDecision.Clear,
            await Client(handler, Options() with { AttemptTimeoutSeconds = 1 })
                .EvaluateAsync("{}", default));
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task ExpiredRealAttemptTimerCannotClearWhenHandlerIgnoresCancellation()
    {
        var handler = new CancellationIgnoringHandler(
            TimeSpan.FromMilliseconds(1100), Response(ValidResponse()));

        var decision = await new DecisionModelCredentialClient(
            new HttpClient(handler),
            Options() with { AttemptTimeoutSeconds = 1, RetryCount = 0 })
            .EvaluateAsync("{}", default);

        Assert.Equal(CredentialGateDecision.Unavailable, decision);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task RetriesBodyReadIoFailuresButNotOversizedValidationFailures()
    {
        var responses = new Queue<HttpResponseMessage>([
            new(HttpStatusCode.OK) { Content = new StreamContent(new ThrowingReadStream()) },
            Response(ValidResponse())
        ]);
        var ioHandler = new RecordingHandler(_ => responses.Dequeue());
        Assert.Equal(CredentialGateDecision.Clear,
            await Client(ioHandler, Options()).EvaluateAsync("{}", default));
        Assert.Equal(2, ioHandler.Requests.Count);

        var oversizedHandler = new RecordingHandler(_ => Response(new string('x', 2000)));
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(oversizedHandler, Options() with { MaxResponseBodyBytes = 1024 })
                .EvaluateAsync("{}", default));
        Assert.Single(oversizedHandler.Requests);
    }

    [Fact]
    public async Task DoesNotRetryStatusesOutside500Through599()
    {
        var handler = new RecordingHandler(_ => Response("ignored", (HttpStatusCode)600));
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(handler, Options()).EvaluateAsync("{}", default));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task CallerCancellationDuringRetryDelayPropagates()
    {
        var handler = new RecordingHandler(_ => Response("ignored", HttpStatusCode.InternalServerError));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Client(handler, Options()).EvaluateAsync("{}", cancellation.Token));
        Assert.Single(handler.Requests);

        var readHandler = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new BlockingReadStream())
        });
        using var readCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Client(readHandler, Options()).EvaluateAsync("{}", readCancellation.Token));
        Assert.Single(readHandler.Requests);
    }

    [Fact]
    public async Task DetectionAndThresholdAreFailClosed()
    {
        var yes = new RecordingHandler(_ => Response(ValidResponse("yes", 0.8, 0.2)));
        Assert.Equal(CredentialGateDecision.Detected,
            await Client(yes, Options()).EvaluateAsync("{\"path\":\"\",\"value\":1}", default));

        var aboveThreshold = new RecordingHandler(_ => Response(ValidResponse("no", 0.21, 0.79)));
        Assert.Equal(CredentialGateDecision.Detected,
            await Client(aboveThreshold, Options()).EvaluateAsync("{\"path\":\"\",\"value\":1}", default));
    }

    [Fact]
    public async Task MalformedAndOversizedBodiesAreUnavailable()
    {
        var malformed = new RecordingHandler(_ => Response("not-json"));
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(malformed, Options()).EvaluateAsync("{\"path\":\"\",\"value\":1}", default));

        var oversized = new RecordingHandler(_ => Response(new string('x', 2000)));
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(oversized, Options() with { MaxResponseBodyBytes = 1024 })
                .EvaluateAsync("{\"path\":\"\",\"value\":1}", default));

        var unknownLength = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new NonSeekableMemoryStream(Encoding.UTF8.GetBytes(new string('x', 2000))))
        });
        Assert.Equal(CredentialGateDecision.Unavailable,
            await Client(unknownLength, Options() with { MaxResponseBodyBytes = 1024 })
                .EvaluateAsync("{}", default));
    }

    private static DecisionModelCredentialClient Client(RecordingHandler handler, CredentialGateOptions options) =>
        new(new HttpClient(handler), options);

    private static CredentialGateOptions Options() => new()
    {
        Enabled = true,
        Endpoint = "https://decision-model.example/systemone",
        RequestModel = "decision",
        ExpectedResponseModel = "physical-model",
        ProbabilityThreshold = 0.20,
        RetryCount = 2,
        MaxInputTokens = 100
    };

    private static string ValidResponse(
        string choice = "no", double yes = 0.1, double no = 0.9, string model = "physical-model") =>
        JsonSerializer.Serialize(new
        {
            model,
            answers = new
            {
                credentials = new
                {
                    type = "choice", choice, confidence = Math.Max(yes, no),
                    probabilities = new { yes, no }
                }
            },
            usage = new { input_tokens = 10, output_tokens = 0 }
        });

    private static HttpResponseMessage Response(
        string body,
        HttpStatusCode status = HttpStatusCode.OK) => new(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };

    private sealed class NonSeekableMemoryStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }

    private sealed class ThrowingReadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException("fabricated body transport failure"));

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new IOException("fabricated body transport failure");
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class BlockingReadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class CancellationIgnoringHandler(
        TimeSpan delay,
        HttpResponseMessage response) : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            await Task.Delay(delay);
            return response;
        }
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> response) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Uri, string? Authorization, string Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add((request.Method, request.RequestUri!.ToString(),
                request.Headers.Authorization?.ToString(),
                await request.Content!.ReadAsStringAsync(cancellationToken)));
            return response(request);
        }
    }
}
