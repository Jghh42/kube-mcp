# kube-mcp

Tiny read-only Kubernetes MCP service built with .NET 10, ASP.NET Core, the official
MCP C# SDK, and the official Kubernetes .NET client.

The service currently exposes exactly one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

Omitting `name` performs a compact namespaced LIST. Supplying `name` performs a
namespaced GET. Kubernetes Secrets are never returned raw: LIST returns names and
key names, while GET replaces each value with a keyed HMAC-SHA256 fingerprint.

> **Stage 2 development warning:** authentication and resource/namespace policy
> are not implemented yet. API discovery currently permits all namespaced resource
> types that Kubernetes RBAC allows. Do not expose this version outside a trusted
> development environment.

## Prerequisites

- .NET 10 SDK
- Docker
- kind
- kubectl
- OpenSSL (for generating the development HMAC key)

## Build and test

```sh
dotnet restore
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build
```

The test suite includes Secret sanitization/fingerprinting tests and an in-process
MCP transport test that verifies `k8s_get` is the only exposed tool.

## End-to-end test with kind

The integration harness builds and loads `kube-mcp:stage2`, generates an ephemeral
HMAC key, deploys the service, creates ConfigMap and Secret fixtures, and calls the
running service through the official MCP client:

```sh
./tests/integration/run-kind.sh
```

The fixture namespace is removed afterward. The tested `kube-mcp` deployment is
left running in kind.

## Manual kind deployment

Build and load the image:

```sh
docker build --tag kube-mcp:stage2 .
kind load docker-image kube-mcp:stage2 --name kind
```

Create the namespace and a stable, server-held HMAC key. Keep this key stable if
fingerprints must remain comparable across restarts:

```sh
kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic kube-mcp-hmac \
  --namespace kube-mcp \
  --from-literal="key=$(openssl rand -base64 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Deploy and wait for readiness:

```sh
kubectl apply --filename deployment.yaml
kubectl rollout status deployment/kube-mcp --namespace kube-mcp
```

Access the service locally:

```sh
kubectl port-forward --namespace kube-mcp service/kube-mcp 8080:80
curl http://127.0.0.1:8080/healthz
```

The MCP endpoint is:

```text
http://127.0.0.1:8080/mcp
```

## Configuration

Configuration uses standard ASP.NET Core configuration. Environment variable names
use double underscores, for example `KubeMcp__SecretHmacKey`.

| Setting | Default | Description |
| --- | ---: | --- |
| `KubeMcp:SecretHmacKey` | required | Base64-encoded HMAC key of at least 32 bytes |
| `KubeMcp:KubeConfigPath` | automatic | Optional kubeconfig path; in-cluster configuration is detected automatically |
| `KubeMcp:MaxListItems` | `100` | Maximum objects returned by LIST |
| `KubeMcp:MaxResponseBytes` | `1048576` | Maximum serialized tool response size |
| `KubeMcp:KubernetesRequestTimeoutSeconds` | `15` | Kubernetes operation timeout |
| `KubeMcp:DiscoveryCacheSeconds` | `300` | API discovery cache lifetime |

The HMAC key must not be committed to source control. Production environments
should provide it through the organization’s normal secret-management system.

## Kubernetes RBAC

The current `ClusterRole` deliberately allows only `get` and `list`, but allows
those verbs on all Kubernetes resource types as required by the staged plan. It
grants no create, update, patch, delete, watch, exec, or proxy operations.
