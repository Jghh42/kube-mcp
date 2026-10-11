using KubeMcp.Configuration;

namespace KubeMcp.CredentialGate;

internal sealed class ClefCredentialGate(
    ICredentialDecisionClient client,
    CredentialGateOptions options) : ICredentialGate
{
    public async Task<CredentialGateDecision> EvaluateAsync(
        string sanitizedJson,
        CancellationToken cancellationToken)
    {
        using var gateTimeout = new CancellationTokenSource(
            TimeSpan.FromSeconds(options.TotalTimeoutSeconds));
        using var combined = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            gateTimeout.Token);

        try
        {
            var chunks = new JsonStateChunker(
                options.ChunkSizeBytes,
                options.ScalarOverlapBytes).Chunk(sanitizedJson, combined.Token);

            foreach (var chunk in chunks)
            {
                combined.Token.ThrowIfCancellationRequested();
                var decision = await client.EvaluateAsync(chunk, combined.Token);
                combined.Token.ThrowIfCancellationRequested();
                if (decision != CredentialGateDecision.Clear)
                {
                    return decision;
                }
            }

            combined.Token.ThrowIfCancellationRequested();
            return CredentialGateDecision.Clear;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return CredentialGateDecision.Unavailable;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return CredentialGateDecision.Unavailable;
        }
    }
}
