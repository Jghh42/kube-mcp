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

    [Fact]
    public void PodSummaryContainsWideFieldsWithoutHeavyweightContent()
    {
        var pod = Parse("""
            {
              "apiVersion": "v1",
              "kind": "Pod",
              "metadata": {
                "name": "api-123",
                "namespace": "production",
                "creationTimestamp": "2026-01-01T11:03:00Z",
                "managedFields": [{ "manager": "must-not-leak" }]
              },
              "spec": {
                "nodeName": "worker-1",
                "containers": [
                  { "name": "api", "env": [{ "value": "spec-must-not-leak" }] },
                  { "name": "sidecar" }
                ]
              },
              "status": {
                "phase": "Running",
                "podIP": "10.244.0.12",
                "containerStatuses": [
                  { "name": "api", "ready": true, "restartCount": 2, "imageID": "status-must-not-leak" },
                  { "name": "sidecar", "ready": false, "restartCount": 3, "state": { "waiting": { "reason": "CrashLoopBackOff" } } }
                ],
                "initContainerStatuses": [{ "restartCount": 1, "state": { "terminated": { "exitCode": 0 } } }]
              }
            }
            """);

        var result = Summarize(pod, "", "pods", "Pod");

        Assert.Equal("api-123", result.GetProperty("name").GetString());
        Assert.Equal("1/2", result.GetProperty("ready").GetString());
        Assert.Equal("CrashLoopBackOff", result.GetProperty("status").GetString());
        Assert.Equal(6, result.GetProperty("restarts").GetInt64());
        Assert.Equal("57m", result.GetProperty("age").GetString());
        Assert.Equal("10.244.0.12", result.GetProperty("ip").GetString());
        Assert.Equal("worker-1", result.GetProperty("node").GetString());
        AssertCompact(result, "spec-must-not-leak", "status-must-not-leak", "managedFields", "containerStatuses");
    }

    [Theory]
    [InlineData("deployments", "Deployment")]
    [InlineData("statefulsets", "StatefulSet")]
    [InlineData("replicasets", "ReplicaSet")]
    public void ReplicaWorkloadSummaryContainsOnlyReplicaCounts(string resource, string kind)
    {
        var item = Parse($$"""
            {
              "apiVersion": "apps/v1",
              "kind": "{{kind}}",
              "metadata": { "name": "web", "namespace": "production", "creationTimestamp": "2026-01-01T10:00:00Z" },
              "spec": { "replicas": 3, "template": { "heavy": "template-must-not-leak" } },
              "status": { "replicas": 3, "readyReplicas": 2, "availableReplicas": 1, "conditions": [{ "message": "condition-must-not-leak" }] }
            }
            """);

        var result = Summarize(item, "apps", resource, kind);

        Assert.Equal("web", result.GetProperty("name").GetString());
        Assert.Equal("2/3", result.GetProperty("ready").GetString());
        Assert.Equal(3, result.GetProperty("replicas").GetInt64());
        Assert.Equal(1, result.GetProperty("available").GetInt64());
        Assert.Equal("2h", result.GetProperty("age").GetString());
        AssertCompact(result, "template-must-not-leak", "condition-must-not-leak", "conditions", "template");
    }

    [Fact]
    public void DaemonSetSummaryContainsSchedulingCounts()
    {
        var item = Parse("""
            {
              "kind": "DaemonSet",
              "metadata": { "name": "agent", "creationTimestamp": "2025-12-30T12:00:00Z" },
              "spec": { "template": { "heavy": "must-not-leak" } },
              "status": {
                "desiredNumberScheduled": 4,
                "currentNumberScheduled": 4,
                "numberReady": 3,
                "numberAvailable": 2,
                "conditions": [{ "heavy": true }]
              }
            }
            """);

        var result = Summarize(item, "apps", "daemonsets", "DaemonSet");

        Assert.Equal(4, result.GetProperty("desired").GetInt64());
        Assert.Equal(4, result.GetProperty("current").GetInt64());
        Assert.Equal(3, result.GetProperty("ready").GetInt64());
        Assert.Equal(2, result.GetProperty("available").GetInt64());
        Assert.Equal("2d", result.GetProperty("age").GetString());
        AssertCompact(result, "must-not-leak", "conditions", "template");
    }

    [Fact]
    public void ServiceSummaryContainsAddressesAndStructuredPorts()
    {
        var item = Parse("""
            {
              "kind": "Service",
              "metadata": { "name": "frontend", "creationTimestamp": "2026-01-01T11:59:30Z" },
              "spec": {
                "type": "LoadBalancer",
                "clusterIP": "10.96.0.20",
                "externalIPs": ["192.0.2.10"],
                "selector": { "heavy": "selector-must-not-leak" },
                "ports": [{ "name": "https", "port": 443, "targetPort": "web", "nodePort": 30443, "protocol": "TCP" }]
              },
              "status": {
                "loadBalancer": { "ingress": [{ "hostname": "service.example.test" }] },
                "conditions": [{ "heavy": "condition-must-not-leak" }]
              }
            }
            """);

        var result = Summarize(item, "", "services", "Service");

        Assert.Equal("LoadBalancer", result.GetProperty("type").GetString());
        Assert.Equal("10.96.0.20", result.GetProperty("clusterIp").GetString());
        Assert.Equal(
            ["192.0.2.10", "service.example.test"],
            result.GetProperty("externalIps").EnumerateArray().Select(value => value.GetString()));
        var port = Assert.Single(result.GetProperty("ports").EnumerateArray());
        Assert.Equal(443, port.GetProperty("port").GetInt64());
        Assert.Equal("web", port.GetProperty("targetPort").GetString());
        Assert.Equal("30s", result.GetProperty("age").GetString());
        AssertCompact(result, "selector-must-not-leak", "condition-must-not-leak", "selector", "conditions");
    }

    [Fact]
    public void ConfigMapSummaryReturnsSortedKeyNamesNotValues()
    {
        var item = Parse("""
            {
              "kind": "ConfigMap",
              "metadata": { "name": "settings", "creationTimestamp": "2026-01-01T11:00:00Z" },
              "data": { "zeta": "data-must-not-leak", "alpha": "also-secret-like" },
              "binaryData": { "binary": "AAE=" }
            }
            """);

        var result = Summarize(item, "", "configmaps", "ConfigMap");

        Assert.Equal(["alpha", "binary", "zeta"], result.GetProperty("keys").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(3, result.GetProperty("keyCount").GetInt32());
        Assert.Equal("1h", result.GetProperty("age").GetString());
        AssertCompact(result, "data-must-not-leak", "also-secret-like", "AAE=", "binaryData");
    }

    [Fact]
    public void SecretSummaryReturnsKeysWithoutValuesOrFingerprints()
    {
        const string rawValue = "correct-horse-battery-staple";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawValue));
        var item = Parse($$"""
            {
              "kind": "Secret",
              "metadata": { "name": "credentials", "creationTimestamp": "2026-01-01T11:00:00Z" },
              "type": "Opaque",
              "data": { "password": "{{encoded}}" }
            }
            """);

        var result = Summarize(item, "", "secrets", "Secret");

        Assert.Equal("credentials", result.GetProperty("name").GetString());
        Assert.Equal("Opaque", result.GetProperty("type").GetString());
        Assert.Equal("password", Assert.Single(result.GetProperty("keys").EnumerateArray()).GetString());
        Assert.Equal("1h", result.GetProperty("age").GetString());
        AssertCompact(result, rawValue, encoded, "hmac-sha256:", "data");
    }

    [Fact]
    public void UnknownCustomResourceUsesMinimalFallback()
    {
        var item = Parse("""
            {
              "apiVersion": "example.test/v1",
              "kind": "Widget",
              "metadata": {
                "name": "sample",
                "namespace": "production",
                "creationTimestamp": "2025-12-31T12:00:00Z",
                "labels": { "heavy": "labels-must-not-leak" }
              },
              "spec": { "password": "spec-must-not-leak" },
              "status": { "history": ["status-must-not-leak"] }
            }
            """);

        var result = Summarize(item, "example.test", "widgets", "Widget");

        Assert.Equal("sample", result.GetProperty("name").GetString());
        Assert.Equal("production", result.GetProperty("namespace").GetString());
        Assert.Equal("Widget", result.GetProperty("kind").GetString());
        Assert.Equal("1d", result.GetProperty("age").GetString());
        Assert.Equal(4, result.EnumerateObject().Count());
        AssertCompact(result, "labels-must-not-leak", "spec-must-not-leak", "status-must-not-leak", "apiVersion");
    }

    private JsonElement Summarize(
        DynamicKubernetesObject item,
        string group,
        string resource,
        string kind)
    {
        var descriptor = new KubernetesResourceDescriptor(
            group,
            "v1",
            resource,
            kind,
            [resource],
            ["get", "list"]);
        return JsonSerializer.SerializeToElement(summarizer.Summarize(item, descriptor));
    }

    private static DynamicKubernetesObject Parse(string json) =>
        JsonSerializer.Deserialize<DynamicKubernetesObject>(json)!;

    private static void AssertCompact(JsonElement result, params string[] excludedValues)
    {
        var json = result.GetRawText();
        Assert.DoesNotContain("\"spec\"", json);
        Assert.DoesNotContain("managedFields", json);
        foreach (var excluded in excludedValues)
        {
            Assert.DoesNotContain(excluded, json);
        }
    }

    public void Dispose()
    {
        fingerprinter.Dispose();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
