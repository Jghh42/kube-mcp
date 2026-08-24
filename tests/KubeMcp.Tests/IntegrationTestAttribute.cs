using System;
using Xunit;

namespace KubeMcp.Tests;

/// <summary>
/// Marks a test that runs only when an integration cluster endpoint is
/// configured. Derives from <see cref="FactAttribute"/> so it is a normal
/// xUnit test method; the runner reads <see cref="FactAttribute.Skip"/>, which
/// this attribute sets at discovery time when
/// <c>KUBE_MCP_INTEGRATION_ENDPOINT</c> is absent.
/// <para>
/// This produces a genuine Skipped result (with a reason) instead of the
/// previous behavior of returning successfully and masquerading as a pass when
/// no kind cluster was configured. When the harness sets the endpoint, the test
/// runs normally.
/// </para>
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class IntegrationTestAttribute : FactAttribute
{
    public const string EndpointVariable = "KUBE_MCP_INTEGRATION_ENDPOINT";

    public IntegrationTestAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(EndpointVariable)))
        {
            Skip = $"Integration test: '{EndpointVariable}' is not set "
                + "(no kind cluster configured); run tests/integration/run-kind.sh.";
        }
    }
}
