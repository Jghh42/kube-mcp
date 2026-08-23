using KubeMcp.Kubernetes;

namespace KubeMcp.Tests;

public sealed class KubernetesNameValidatorTests
{
    [Theory]
    [InlineData("default")]
    [InlineData("kube-system")]
    [InlineData("database-2")]
    public void AcceptsValidNamespaces(string value)
    {
        KubernetesNameValidator.ValidateNamespace(value);
    }

    [Theory]
    [InlineData("../default")]
    [InlineData("Kube-System")]
    [InlineData("namespace.example")]
    [InlineData("")]
    public void RejectsInvalidNamespaces(string value)
    {
        Assert.Throws<KubernetesReadException>(() =>
            KubernetesNameValidator.ValidateNamespace(value));
    }

    [Theory]
    [InlineData("pod-1")]
    [InlineData("generated.name-123")]
    public void AcceptsValidResourceNames(string value)
    {
        KubernetesNameValidator.ValidateResourceName(value);
    }

    [Theory]
    [InlineData("../pod")]
    [InlineData("namespace/pod")]
    [InlineData("Pod-1")]
    [InlineData("pod..name")]
    public void RejectsInvalidResourceNames(string value)
    {
        Assert.Throws<KubernetesReadException>(() =>
            KubernetesNameValidator.ValidateResourceName(value));
    }
}
