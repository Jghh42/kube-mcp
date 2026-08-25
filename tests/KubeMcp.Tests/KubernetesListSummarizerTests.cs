using System.Text;
using System.Text.Json;
using KubeMcp.Kubernetes;
using KubeMcp.Security;

namespace KubeMcp.Tests;

public sealed class KubernetesListSummarizerTests : IDisposable
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-01-01T12:00:00Z");
    private readonly SecretFingerprinter fingerprinter = new(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
    private readonly KubernetesListSummarizer summarizer;

    public KubernetesListSummarizerTests()
    {
        summarizer = new KubernetesListSummarizer(
            new SecretSanitizer(fingerprinter),
            new FixedTimeProvider(Now));
    }

    [Theory]
    [InlineData("", "pods", "Pod")]
    [InlineData("", "configmaps", "ConfigMap")]
    [InlineData("apps", "deployments", "Deployment")]
    [InlineData("networking.k8s.io", "ingresses", "Ingress")]
    public void NonSecretSummaryContainsOnlyGenericIdentityFields(
        string group,
        string resource,
        string kind)
    {
        var item = Parse($$"""
            {
              "apiVersion": "{{(group.Length == 0 ? "v1" : group + "/v1")}}",
              "kind": "{{kind}}",
              "metadata": {
                "name": "sample",
                "namespace": "production",
                "creationTimestamp": "2026-01-01T11:03:00Z",
                "annotations": { "unsafe": "annotation-must-not-leak" },
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": { "password": "spec-must-not-leak" },
              "status": { "history": "status-must-not-leak" },
              "data": { "token": "data-must-not-leak" },
              "arbitrary": { "crdField": "arbitrary-field-must-not-leak" }
            }
            """);

        var result = Summarize(item, group, resource, kind);

        Assert.Equal("sample", result.GetProperty("name").GetString());
        Assert.Equal("production", result.GetProperty("namespace").GetString());
        Assert.Equal(kind, result.GetProperty("kind").GetString());
        Assert.Equal("57m", result.GetProperty("age").GetString());
        AssertFields(result, "name", "namespace", "kind", "age");
        AssertExcludesUnapprovedContent(result);
    }

    [Fact]
    public void CustomResourceSummaryDoesNotExposeArbitraryFields()
    {
        var item = Parse("""
            {
              "apiVersion": "example.test/v1",
              "kind": "Widget",
              "metadata": {
                "name": "sample",
                "namespace": "production",
                "labels": { "owner": "labels-must-not-leak" },
                "annotations": { "note": "annotation-must-not-leak" },
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": { "credential": "spec-must-not-leak" },
              "status": { "debug": "status-must-not-leak" },
              "customSecretValue": "arbitrary-field-must-not-leak"
            }
            """);

        var result = Summarize(item, "example.test", "widgets", "Widget");

        AssertFields(result, "name", "namespace", "kind");
        Assert.False(result.TryGetProperty("age", out _));
        AssertExcludesUnapprovedContent(result);
    }

    [Fact]
    public void GenericSummaryUsesConfiguredKindWhenItemTypeMetaIsOmitted()
    {
        var item = Parse("""
            {
              "metadata": {
                "name": "sample",
                "namespace": "production",
                "creationTimestamp": "not-a-timestamp"
              }
            }
            """);

        var result = Summarize(item, "example.test", "widgets", "Widget");

        Assert.Equal("Widget", result.GetProperty("kind").GetString());
        AssertFields(result, "name", "namespace", "kind");
    }

    [Fact]
    public void SecretSummaryReturnsSafeTypeAndKeyNamesWithoutValuesOrFingerprints()
    {
        const string rawValue = "correct-horse-battery-staple";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawValue));
        var item = Parse($$"""
            {
              "kind": "Secret",
              "metadata": {
                "name": "credentials",
                "namespace": "production",
                "creationTimestamp": "2026-01-01T11:00:00Z",
                "annotations": { "unsafe": "annotation-must-not-leak" },
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "type": "Opaque",
              "data": { "password": "{{encoded}}" },
              "stringData": { "username": "raw-string-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "secrets", "Secret");

        Assert.Equal("credentials", result.GetProperty("name").GetString());
        Assert.Equal("Opaque", result.GetProperty("type").GetString());
        Assert.Equal(
            ["password", "username"],
            result.GetProperty("keys").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal("1h", result.GetProperty("age").GetString());
        AssertFields(result, "name", "type", "keys", "age");
        var json = result.GetRawText();
        Assert.DoesNotContain(rawValue, json);
        Assert.DoesNotContain(encoded, json);
        Assert.DoesNotContain("raw-string-data-must-not-leak", json);
        Assert.DoesNotContain("hmac-sha256:", json);
        Assert.DoesNotContain("annotations", json);
        Assert.DoesNotContain("managedFields", json);
        Assert.DoesNotContain("data", json, StringComparison.OrdinalIgnoreCase);
    }

    private JsonElement Summarize(
        DynamicKubernetesObject item,
        string group,
        string resource,
        string kind)
    {
        var descriptor = new KubernetesResourceDescriptor(group, "v1", resource, kind);
        return JsonSerializer.SerializeToElement(
            descriptor.IsSecret
                ? summarizer.SummarizeSecret(JsonSerializer.SerializeToElement(item))
                : summarizer.Summarize(item, descriptor));
    }

    private static DynamicKubernetesObject Parse(string json) =>
        JsonSerializer.Deserialize<DynamicKubernetesObject>(json)!;

    private static void AssertFields(JsonElement result, params string[] expectedFields)
    {
        Assert.Equal(
            expectedFields.Order(StringComparer.Ordinal),
            result.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
    }

    private static void AssertExcludesUnapprovedContent(JsonElement result)
    {
        var json = result.GetRawText();
        foreach (var excluded in new[]
                 {
                     "spec", "status", "managedFields", "annotations", "labels", "data",
                     "arbitrary", "credential", "must-not-leak"
                 })
        {
            Assert.DoesNotContain(excluded, json, StringComparison.OrdinalIgnoreCase);
        }
    }

    public void Dispose() => fingerprinter.Dispose();

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
