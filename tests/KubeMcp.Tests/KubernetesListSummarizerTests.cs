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
    public void EventSummaryContainsDiagnosticFieldsOnly()
    {
        var item = Parse("""
            {
              "kind": "Event",
              "metadata": {
                "name": "api.123",
                "creationTimestamp": "2026-01-01T11:50:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "type": "Warning",
              "reason": "Failed",
              "message": "Image pull failed",
              "count": 3,
              "lastTimestamp": "2026-01-01T11:59:00Z",
              "source": { "component": "kubelet", "host": "source-detail-must-not-leak" },
              "involvedObject": { "kind": "Pod", "name": "api", "uid": "object-uid-must-not-leak" },
              "spec": { "rawData": "raw-data-must-not-leak" },
              "status": { "history": "complete-status-must-not-leak" },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "events", "Event");

        Assert.Equal("Warning", result.GetProperty("type").GetString());
        Assert.Equal("Failed", result.GetProperty("reason").GetString());
        Assert.Equal("Pod/api", result.GetProperty("object").GetString());
        Assert.Equal("Image pull failed", result.GetProperty("message").GetString());
        Assert.Equal(3, result.GetProperty("count").GetInt64());
        Assert.Equal("kubelet", result.GetProperty("reporting").GetString());
        Assert.Equal("10m", result.GetProperty("age").GetString());
        AssertFields(result, "name", "type", "reason", "object", "message", "count", "lastSeen", "reporting", "age");
        AssertCompact(result, "source-detail-must-not-leak", "object-uid-must-not-leak");
    }

    [Fact]
    public void EndpointsSummaryUsesCountsAndDeduplicatedPortsInsteadOfRawAddresses()
    {
        var item = Parse("""
            {
              "kind": "Endpoints",
              "metadata": {
                "name": "api",
                "creationTimestamp": "2026-01-01T11:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "subsets": [
                {
                  "addresses": [
                    { "ip": "10.0.0.1", "targetRef": { "uid": "raw-address-detail-must-not-leak" } },
                    { "ip": "10.0.0.2" }
                  ],
                  "notReadyAddresses": [{ "ip": "10.0.0.3" }],
                  "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }]
                },
                {
                  "ports": [
                    { "name": "https", "port": 443, "protocol": "TCP" },
                    { "name": "dns", "port": 53, "protocol": "UDP", "appProtocol": "dns" }
                  ]
                }
              ],
              "spec": { "rawData": "raw-data-must-not-leak" },
              "status": { "history": "complete-status-must-not-leak" },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "endpoints", "Endpoints");

        Assert.Equal(2, result.GetProperty("readyAddresses").GetInt64());
        Assert.Equal(1, result.GetProperty("notReadyAddresses").GetInt64());
        Assert.Equal(2, result.GetProperty("ports").GetArrayLength());
        Assert.Contains(
            result.GetProperty("ports").EnumerateArray(),
            port => port.GetProperty("port").GetInt64() == 53 && port.GetProperty("protocol").GetString() == "UDP");
        AssertFields(result, "name", "readyAddresses", "notReadyAddresses", "ports", "age");
        AssertCompact(result, "10.0.0.1", "10.0.0.2", "10.0.0.3", "raw-address-detail-must-not-leak");
    }

    [Fact]
    public void EndpointSliceSummaryContainsServiceReadinessAndPortFields()
    {
        var item = Parse("""
            {
              "kind": "EndpointSlice",
              "metadata": {
                "name": "api-abc",
                "creationTimestamp": "2026-01-01T11:00:00Z",
                "labels": { "kubernetes.io/service-name": "api", "raw": "label-detail-must-not-leak" },
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "addressType": "IPv4",
              "ports": [{ "name": "https", "port": 443, "protocol": "TCP", "appProtocol": "https" }],
              "endpoints": [
                { "addresses": ["10.0.0.1"], "conditions": { "ready": true } },
                { "addresses": ["10.0.0.2", "10.0.0.3"], "conditions": { "ready": false, "terminating": true }, "hints": "endpoint-detail-must-not-leak" }
              ],
              "spec": { "rawData": "raw-data-must-not-leak" },
              "status": { "history": "complete-status-must-not-leak" },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "discovery.k8s.io", "endpointslices", "EndpointSlice");

        Assert.Equal("api", result.GetProperty("service").GetString());
        Assert.Equal("IPv4", result.GetProperty("addressType").GetString());
        Assert.Equal(2, result.GetProperty("endpoints").GetInt64());
        Assert.Equal(1, result.GetProperty("ready").GetInt64());
        Assert.Equal(1, result.GetProperty("terminating").GetInt64());
        Assert.Equal(3, result.GetProperty("addresses").GetInt64());
        Assert.Equal(443, Assert.Single(result.GetProperty("ports").EnumerateArray()).GetProperty("port").GetInt64());
        AssertFields(result, "name", "service", "addressType", "endpoints", "ready", "terminating", "addresses", "ports", "age");
        AssertCompact(result, "10.0.0.1", "10.0.0.2", "label-detail-must-not-leak", "endpoint-detail-must-not-leak");
    }

    [Fact]
    public void PersistentVolumeClaimSummaryContainsBindingAndStorageFields()
    {
        var item = Parse("""
            {
              "kind": "PersistentVolumeClaim",
              "metadata": {
                "name": "database",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "volumeName": "pvc-123",
                "accessModes": ["ReadWriteOnce"],
                "storageClassName": "fast",
                "volumeMode": "Filesystem",
                "resources": { "requests": { "storage": "spec-storage-must-not-leak" } },
                "rawData": "raw-data-must-not-leak"
              },
              "status": {
                "phase": "Bound",
                "capacity": { "storage": "20Gi" },
                "conditions": [{ "message": "complete-status-must-not-leak" }]
              },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "persistentvolumeclaims", "PersistentVolumeClaim");

        Assert.Equal("Bound", result.GetProperty("status").GetString());
        Assert.Equal("pvc-123", result.GetProperty("volume").GetString());
        Assert.Equal("20Gi", result.GetProperty("capacity").GetString());
        Assert.Equal("ReadWriteOnce", Assert.Single(result.GetProperty("accessModes").EnumerateArray()).GetString());
        Assert.Equal("fast", result.GetProperty("storageClass").GetString());
        AssertFields(result, "name", "status", "volume", "capacity", "accessModes", "storageClass", "volumeMode", "age");
        AssertCompact(result, "spec-storage-must-not-leak", "conditions");
    }

    [Fact]
    public void ReplicationControllerSummaryContainsReplicaCounts()
    {
        var item = Parse("""
            {
              "kind": "ReplicationController",
              "metadata": {
                "name": "legacy-api",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": { "replicas": 4, "template": "raw-data-must-not-leak" },
              "status": {
                "replicas": 3,
                "readyReplicas": 2,
                "availableReplicas": 1,
                "conditions": [{ "message": "complete-status-must-not-leak" }]
              },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "replicationcontrollers", "ReplicationController");

        Assert.Equal(4, result.GetProperty("desired").GetInt64());
        Assert.Equal(3, result.GetProperty("current").GetInt64());
        Assert.Equal(2, result.GetProperty("ready").GetInt64());
        Assert.Equal(1, result.GetProperty("available").GetInt64());
        AssertFields(result, "name", "desired", "current", "ready", "available", "age");
        AssertCompact(result, "template", "conditions");
    }

    [Fact]
    public void IngressSummaryContainsRoutingOverviewWithoutRulesOrStatus()
    {
        var item = Parse("""
            {
              "kind": "Ingress",
              "metadata": {
                "name": "public-api",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "ingressClassName": "nginx",
                "tls": [{ "hosts": ["api.example.test"], "secretName": "tls-secret-must-not-leak" }],
                "rules": [
                  { "host": "api.example.test", "http": { "paths": [{ "backend": "raw-data-must-not-leak" }] } },
                  { "http": { "paths": [] } }
                ]
              },
              "status": {
                "loadBalancer": { "ingress": [{ "ip": "192.0.2.1" }, { "hostname": "lb.example.test" }] },
                "history": "complete-status-must-not-leak"
              },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "networking.k8s.io", "ingresses", "Ingress");

        Assert.Equal("nginx", result.GetProperty("class").GetString());
        Assert.Equal(["*", "api.example.test"], result.GetProperty("hosts").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(["192.0.2.1", "lb.example.test"], result.GetProperty("addresses").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal([80, 443], result.GetProperty("ports").EnumerateArray().Select(value => value.GetInt32()));
        AssertFields(result, "name", "class", "hosts", "addresses", "ports", "age");
        AssertCompact(result, "tls-secret-must-not-leak", "paths");
    }

    [Fact]
    public void NetworkPolicySummaryContainsSelectorTypesAndRuleCounts()
    {
        var item = Parse("""
            {
              "kind": "NetworkPolicy",
              "metadata": {
                "name": "api-policy",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "podSelector": {
                  "matchLabels": { "app": "api" },
                  "matchExpressions": [{ "key": "tier", "operator": "In", "values": ["web", "edge"] }]
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{ "from": [{ "rawData": "raw-data-must-not-leak" }] }],
                "egress": [{ "to": [] }, { "ports": [] }]
              },
              "status": { "history": "complete-status-must-not-leak" },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "networking.k8s.io", "networkpolicies", "NetworkPolicy");

        Assert.Equal("app=api,tier in (edge,web)", result.GetProperty("podSelector").GetString());
        Assert.Equal(["Egress", "Ingress"], result.GetProperty("policyTypes").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(1, result.GetProperty("ingressRules").GetInt32());
        Assert.Equal(2, result.GetProperty("egressRules").GetInt32());
        AssertFields(result, "name", "podSelector", "policyTypes", "ingressRules", "egressRules", "age");
        AssertCompact(result, "\"from\"", "\"to\"");
    }

    [Fact]
    public void HorizontalPodAutoscalerSummaryContainsScaleTargetAndReplicaBounds()
    {
        var item = Parse("""
            {
              "kind": "HorizontalPodAutoscaler",
              "metadata": {
                "name": "api",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "scaleTargetRef": { "apiVersion": "apps/v1", "kind": "Deployment", "name": "api" },
                "minReplicas": 2,
                "maxReplicas": 10,
                "metrics": [{ "resource": { "name": "cpu", "target": "raw-data-must-not-leak" } }]
              },
              "status": {
                "currentReplicas": 4,
                "desiredReplicas": 6,
                "currentMetrics": [{ "complete": "complete-status-must-not-leak" }],
                "conditions": [{ "message": "condition-must-not-leak" }]
              },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "autoscaling", "horizontalpodautoscalers", "HorizontalPodAutoscaler");

        Assert.Equal("Deployment/api", result.GetProperty("target").GetString());
        Assert.Equal(2, result.GetProperty("minReplicas").GetInt64());
        Assert.Equal(10, result.GetProperty("maxReplicas").GetInt64());
        Assert.Equal(4, result.GetProperty("currentReplicas").GetInt64());
        Assert.Equal(6, result.GetProperty("desiredReplicas").GetInt64());
        Assert.Equal(1, result.GetProperty("metrics").GetInt32());
        AssertFields(result, "name", "target", "minReplicas", "maxReplicas", "currentReplicas", "desiredReplicas", "metrics", "age");
        AssertCompact(result, "currentMetrics", "conditions");
    }

    [Fact]
    public void PodDisruptionBudgetSummaryContainsAvailabilityAndHealthCounts()
    {
        var item = Parse("""
            {
              "kind": "PodDisruptionBudget",
              "metadata": {
                "name": "api",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "minAvailable": "75%",
                "selector": { "matchLabels": { "rawData": "raw-data-must-not-leak" } }
              },
              "status": {
                "disruptionsAllowed": 1,
                "currentHealthy": 3,
                "desiredHealthy": 3,
                "expectedPods": 4,
                "disruptedPods": { "api-1": "complete-status-must-not-leak" },
                "conditions": [{ "message": "condition-must-not-leak" }]
              },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "policy", "poddisruptionbudgets", "PodDisruptionBudget");

        Assert.Equal("75%", result.GetProperty("minAvailable").GetString());
        Assert.Equal(JsonValueKind.Null, result.GetProperty("maxUnavailable").ValueKind);
        Assert.Equal(1, result.GetProperty("disruptionsAllowed").GetInt64());
        Assert.Equal(3, result.GetProperty("currentHealthy").GetInt64());
        Assert.Equal(3, result.GetProperty("desiredHealthy").GetInt64());
        Assert.Equal(4, result.GetProperty("expectedPods").GetInt64());
        AssertFields(result, "name", "minAvailable", "maxUnavailable", "disruptionsAllowed", "currentHealthy", "desiredHealthy", "expectedPods", "age");
        AssertCompact(result, "selector", "disruptedPods", "conditions");
    }

    [Fact]
    public void LimitRangeSummaryFlattensOnlyConfiguredResourceLimits()
    {
        var item = Parse("""
            {
              "kind": "LimitRange",
              "metadata": {
                "name": "defaults",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "limits": [
                  {
                    "type": "Container",
                    "min": { "cpu": "100m" },
                    "max": { "cpu": "2", "memory": "2Gi" },
                    "defaultRequest": { "cpu": "250m" },
                    "unknownRawData": "raw-data-must-not-leak"
                  }
                ],
                "other": "spec-detail-must-not-leak"
              },
              "status": { "history": "complete-status-must-not-leak" },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "limitranges", "LimitRange");

        Assert.Equal(2, result.GetProperty("limitCount").GetInt32());
        var cpu = Assert.Single(
            result.GetProperty("limits").EnumerateArray(),
            limit => limit.GetProperty("resource").GetString() == "cpu");
        Assert.Equal("Container", cpu.GetProperty("type").GetString());
        Assert.Equal("100m", cpu.GetProperty("min").GetString());
        Assert.Equal("2", cpu.GetProperty("max").GetString());
        Assert.Equal("250m", cpu.GetProperty("defaultRequest").GetString());
        AssertFields(result, "name", "limits", "limitCount", "age");
        AssertCompact(result, "unknownRawData", "spec-detail-must-not-leak");
    }

    [Fact]
    public void ResourceQuotaSummaryPairsUsedAndHardValuesWithoutCompleteStatus()
    {
        var item = Parse("""
            {
              "kind": "ResourceQuota",
              "metadata": {
                "name": "compute",
                "creationTimestamp": "2026-01-01T10:00:00Z",
                "managedFields": [{ "manager": "managed-fields-must-not-leak" }]
              },
              "spec": {
                "hard": { "requests.cpu": "8", "requests.memory": "32Gi" },
                "scopes": ["BestEffort"],
                "scopeSelector": { "rawData": "raw-data-must-not-leak" }
              },
              "status": {
                "hard": { "requests.cpu": "8", "requests.memory": "32Gi" },
                "used": { "requests.cpu": "3", "requests.memory": "12Gi" },
                "conditions": [{ "message": "complete-status-must-not-leak" }]
              },
              "data": { "token": "sensitive-data-must-not-leak" }
            }
            """);

        var result = Summarize(item, "", "resourcequotas", "ResourceQuota");

        Assert.Equal("BestEffort", Assert.Single(result.GetProperty("scopes").EnumerateArray()).GetString());
        Assert.Equal(2, result.GetProperty("resourceCount").GetInt32());
        var cpu = Assert.Single(
            result.GetProperty("resources").EnumerateArray(),
            resource => resource.GetProperty("name").GetString() == "requests.cpu");
        Assert.Equal("3", cpu.GetProperty("used").GetString());
        Assert.Equal("8", cpu.GetProperty("hard").GetString());
        AssertFields(result, "name", "scopes", "resources", "resourceCount", "age");
        AssertCompact(result, "scopeSelector", "conditions");
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
            kind);
        return JsonSerializer.SerializeToElement(summarizer.Summarize(item, descriptor));
    }

    private static DynamicKubernetesObject Parse(string json) =>
        JsonSerializer.Deserialize<DynamicKubernetesObject>(json)!;

    private static void AssertFields(JsonElement result, params string[] expectedFields)
    {
        Assert.Equal(
            expectedFields.Order(StringComparer.Ordinal),
            result.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
    }

    private static void AssertCompact(JsonElement result, params string[] excludedValues)
    {
        var json = result.GetRawText();
        Assert.DoesNotContain("\"spec\"", json);
        Assert.DoesNotContain("managedFields", json);
        Assert.DoesNotContain("managed-fields-must-not-leak", json);
        Assert.DoesNotContain("raw-data-must-not-leak", json);
        Assert.DoesNotContain("complete-status-must-not-leak", json);
        Assert.DoesNotContain("sensitive-data-must-not-leak", json);
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
