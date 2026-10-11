using System.Text.Json;
using KubeMcp.Configuration;
using KubeMcp.CredentialGate;

namespace KubeMcp.Tests;

public sealed class ClefCredentialGateTests
{
    [Fact]
    public async Task RequiresEveryChunkToClear()
    {
        var client = new StubClient([
            CredentialGateDecision.Clear,
            CredentialGateDecision.Detected,
            CredentialGateDecision.Clear
        ]);
        var gate = new ClefCredentialGate(client, Options(chunkSize: 256));
        var json = JsonSerializer.Serialize(new string('a', 800));

        Assert.Equal(CredentialGateDecision.Detected, await gate.EvaluateAsync(json, default));
        Assert.Equal(2, client.CallCount);
    }

    [Fact]
    public async Task AnyClientOrChunkingFailureIsUnavailable()
    {
        var unavailable = new ClefCredentialGate(
            new StubClient([CredentialGateDecision.Unavailable]), Options());
        Assert.Equal(CredentialGateDecision.Unavailable,
            await unavailable.EvaluateAsync("{}", default));

        var malformed = new ClefCredentialGate(
            new StubClient([CredentialGateDecision.Clear]), Options());
        Assert.Equal(CredentialGateDecision.Unavailable,
            await malformed.EvaluateAsync("raw-secret-not-json", default));
    }

    [Fact]
    public async Task GateOwnedTimeoutBlocksButCallerCancellationPropagates()
    {
        var gate = new ClefCredentialGate(new CancellingClient(), Options());
        Assert.Equal(CredentialGateDecision.Unavailable, await gate.EvaluateAsync("{}", default));

        using var caller = new CancellationTokenSource();
        caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gate.EvaluateAsync("{}", caller.Token));
    }

    [Fact]
    public async Task CancellationIgnoringClientCannotRaceAClientCancellationIntoClear()
    {
        var gate = new ClefCredentialGate(
            new DelayedIgnoringClient(TimeSpan.FromMilliseconds(40)), Options());
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(10));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            gate.EvaluateAsync("{}", cancellation.Token));
    }

    [Fact]
    public async Task TotalBudgetCoversAllChunksEvenWhenClientIgnoresCancellation()
    {
        var client = new DelayedIgnoringClient(TimeSpan.FromMilliseconds(600));
        var gate = new ClefCredentialGate(client, Options(chunkSize: 256) with
        {
            TotalTimeoutSeconds = 1,
            AttemptTimeoutSeconds = 1
        });

        var result = await gate.EvaluateAsync(JsonSerializer.Serialize(new string('x', 800)), default);

        Assert.Equal(CredentialGateDecision.Unavailable, result);
        Assert.Equal(2, client.CallCount);
    }

    private static CredentialGateOptions Options(int chunkSize = 4096) => new()
    {
        Enabled = true,
        ChunkSizeBytes = chunkSize,
        ScalarOverlapBytes = 32,
        TotalTimeoutSeconds = 15
    };

    private sealed class StubClient(IEnumerable<CredentialGateDecision> decisions) : ICredentialDecisionClient
    {
        private readonly Queue<CredentialGateDecision> decisions = new(decisions);
        public int CallCount { get; private set; }

        public Task<CredentialGateDecision> EvaluateAsync(string stateJson, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(decisions.Dequeue());
        }
    }

    private sealed class DelayedIgnoringClient(TimeSpan delay) : ICredentialDecisionClient
    {
        public int CallCount { get; private set; }

        public async Task<CredentialGateDecision> EvaluateAsync(
            string stateJson,
            CancellationToken cancellationToken)
        {
            CallCount++;
            await Task.Delay(delay);
            return CredentialGateDecision.Clear;
        }
    }

    private sealed class CancellingClient : ICredentialDecisionClient
    {
        public Task<CredentialGateDecision> EvaluateAsync(string stateJson, CancellationToken cancellationToken) =>
            Task.FromCanceled<CredentialGateDecision>(cancellationToken.IsCancellationRequested
                ? cancellationToken
                : new CancellationToken(canceled: true));
    }
}
