# kube-mcp

Tiny read-only Kubernetes MCP service built with .NET 10, ASP.NET Core, the official
MCP C# SDK, and the official Kubernetes .NET client.

The service currently exposes exactly one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

Omitting `name` performs a compact namespaced LIST. Supplying `name` performs a
namespaced GET. LIST uses resource-specific structured summaries (for Pods,
workloads, Services, ConfigMaps, Secrets, Jobs, and CronJobs) and a minimal
name/namespace/kind/age fallback for other resources. GET remains detailed.
Kubernetes Secrets are never returned raw: LIST returns safe discovery fields and
key names, while GET replaces each value with a keyed HMAC-SHA256 fingerprint.

> **Development warning:** authentication is not implemented yet. Resource and
> namespace access policies are enforced, but this version should still not be
> exposed outside a trusted development environment.

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

The test suite includes Secret sanitization/fingerprinting tests, compact LIST
summary tests that reject heavyweight object content, and an in-process MCP
transport test that verifies `k8s_get` is the only exposed tool.

## CI and container publishing

[`.github/workflows/container.yml`](.github/workflows/container.yml) builds and tests
every pull request targeting `main`. After a successful push to `main`, it publishes
the container to:

```text
ghcr.io/jghh42/kube-mcp:latest
ghcr.io/jghh42/kube-mcp:main
ghcr.io/jghh42/kube-mcp:sha-<commit>
```

Tags beginning with `v` also publish version tags. For example, Git tag `v1.2.3`
produces container tags `v1.2.3`, `1.2.3`, and `1.2`. The workflow authenticates
with its short-lived `GITHUB_TOKEN` and requires no repository secret.

A newly created GHCR package is private by default. After the first successful
publish, change the package visibility to public in its GitHub package settings so
clusters can pull it without an image pull secret.

## End-to-end test with kind

The integration harness builds and loads a local test image, generates an ephemeral
HMAC key, deploys the service, creates ConfigMap and Secret fixtures, and calls the
running service through the official MCP client. It verifies compact Pod,
Deployment, Service, ConfigMap, and Secret LIST output, detailed GET, resource
denials, both namespace policy modes, and explicit resource `AllowAll` mode:

```sh
./tests/integration/run-kind.sh
```

The fixture namespace is removed afterward. The tested `kube-mcp` deployment is
left running in kind.

## Deploy the published image

The deployment manifest uses `ghcr.io/jghh42/kube-mcp:latest`. For a repeatable
production deployment, replace `latest` with an immutable `sha-<commit>` tag.
Ensure the GHCR package is public, or configure an appropriate Kubernetes image
pull secret before deploying.

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
| `KubeMcp:ResourcePolicy:Mode` | `Allowlist` | `Allowlist` or the explicit `AllowAll` opt-in |
| `KubeMcp:AllowedResources` | see `appsettings.json` | Explicit MCP name to Kubernetes group/version/resource/kind mappings in allowlist mode |
| `KubeMcp:NamespacePolicy:Mode` | `Blacklist` | `Blacklist` or `LabelSelector` |
| `KubeMcp:NamespacePolicy:DeniedNamespaces` | Kubernetes system namespaces | Names denied in blacklist mode |
| `KubeMcp:NamespacePolicy:LabelSelector` | none | Required Kubernetes label selector in label-selector mode |
| `KubeMcp:MaxListItems` | `100` | Maximum objects returned by LIST |
| `KubeMcp:MaxResponseBytes` | `1048576` | Maximum serialized tool response size |
| `KubeMcp:KubernetesRequestTimeoutSeconds` | `15` | Kubernetes operation timeout |
| `KubeMcp:DiscoveryCacheSeconds` | `300` | API discovery cache lifetime when resource `AllowAll` mode is enabled |

Resources are denied unless their MCP name has an explicit mapping. The defaults
cover common namespaced Kubernetes resources plus CloudNativePG and Traefik CRDs.
The mapping is resolved before any Kubernetes request and API discovery cannot
expand it. Custom mappings also require corresponding read-only Kubernetes RBAC.
A custom mapping looks like:

```json
{
  "KubeMcp": {
    "AllowedResources": {
      "widgets.example.com": {
        "Group": "example.com",
        "Version": "v1",
        "Resource": "widgets",
        "Kind": "Widget"
      }
    }
  }
}
```

To allow every discoverable namespaced resource supporting GET/LIST, explicitly
opt in with:

```text
KubeMcp__ResourcePolicy__Mode=AllowAll
```

`AllowAll` restores Kubernetes API discovery for resource resolution and emits a
startup warning. Namespace policy, GET/LIST-only behavior, Secret sanitization,
response limits, and Kubernetes RBAC continue to apply. To expand the supplied
ClusterRole as well, deliberately apply the separate high-privilege manifest:

```sh
kubectl apply --filename deployment-allow-all-rbac.yaml
```

Reapply `deployment.yaml` to restore the default narrow ClusterRole.

Namespace blacklist mode allows new namespaces automatically while denying the
configured names. The defaults deny `kube-system`, `kube-public`, and
`kube-node-lease`. Label-selector mode instead allows only namespaces matching a
normal Kubernetes label selector. For example:

```text
KubeMcp__NamespacePolicy__Mode=LabelSelector
KubeMcp__NamespacePolicy__LabelSelector=platform.example.com/group in (production,staging)
```

The HMAC key must not be committed to source control. Production environments
should provide it through the organization’s normal secret-management system.

## Kubernetes RBAC

The default `ClusterRole` grants only `get` and `list` for the default resource
allowlist. It additionally grants namespace `list` so Kubernetes can evaluate
label-selector namespace policy. It grants no wildcard resources and no create,
update, patch, delete, watch, exec, or proxy operations.

`deployment-allow-all-rbac.yaml` is a separate, explicit opt-in that changes this
identity to cluster-wide wildcard GET/LIST access. Application resource mode and
Kubernetes RBAC are independent: enabling only one does not bypass the other.
