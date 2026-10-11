namespace KubeMcp.CredentialGate;

public enum CredentialGateDecision
{
    Clear,
    Detected,
    Unavailable
}

public interface ICredentialGate
{
    Task<CredentialGateDecision> EvaluateAsync(string sanitizedJson, CancellationToken cancellationToken);
}

internal interface ICredentialDecisionClient
{
    Task<CredentialGateDecision> EvaluateAsync(string stateJson, CancellationToken cancellationToken);
}

internal sealed class DisabledCredentialGate : ICredentialGate
{
    public Task<CredentialGateDecision> EvaluateAsync(
        string sanitizedJson,
        CancellationToken cancellationToken) =>
        Task.FromResult(CredentialGateDecision.Clear);
}
