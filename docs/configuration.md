# Configuration reference

Configuration follows standard ASP.NET Core conventions. Environment variable names use double underscores; for example, `KubeMcp:SecretHmacKey` becomes `KubeMcp__SecretHmacKey`.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `KubeMcp:SecretHmacKey` | required | Base64-encoded HMAC key of at least 32 bytes. |
| `KubeMcp:KubeConfigPath` | automatic | Optional kubeconfig path; in-cluster configuration is detected automatically. |
| `KubeMcp:AllowedResources` | see `appsettings.json` | MCP names mapped to Kubernetes group/version/resource/kind. |
| `KubeMcp:NamespacePolicy:Mode` | `Blacklist` | `Blacklist` or `LabelSelector`. |
| `KubeMcp:NamespacePolicy:DeniedNamespaces` | system namespaces | Names denied in blacklist mode. |
| `KubeMcp:NamespacePolicy:LabelSelector` | none | Required selector in label-selector mode. |
| `KubeMcp:MaxListItems` | `100` | Maximum objects returned by LIST. |
| `KubeMcp:MaxResponseBytes` | `1048576` | Maximum inner tool-content JSON size, excluding the MCP/HTTP envelope. |
| `KubeMcp:MaxUpstreamBodyBytes` | `4194304` | Per-page or single-object Kubernetes response limit before deserialization. |
| `KubeMcp:ListPageSize` | `50` | Page size for non-Secret LISTs. |
| `KubeMcp:SecretListPageSize` | `10` | Page size for Secret LISTs. |
| `KubeMcp:MaxListPages` | `20` | Maximum continuation pages per LIST. |
| `KubeMcp:KubernetesRequestTimeoutSeconds` | `15` | Kubernetes operation timeout. |
| `KubeMcp:OverallMcpRequestTimeoutSeconds` | `30` | End-to-end MCP deadline; must exceed the Kubernetes timeout. |
| `KubeMcp:Authentication:Mode` | `ApiKey` | `ApiKey`, or `None` only when the host environment is `Development`. |
| `KubeMcp:Authentication:ApiKey` | none | Static bearer key of at least 32 UTF-8 bytes. Required in API-key mode. |
| `AllowedHosts` | local and service names | Semicolon-delimited ASP.NET Core host allowlist. |

## Resource policy

A resource resolves only when its MCP name has an explicit local mapping. Every mapping must provide a non-null `Group`; use `""` for the core API group.

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

Custom mappings also need matching read-only Kubernetes RBAC. See [optional overlays](../overlays/README.md) for examples. There is no wildcard application resource mode; resources that are not explicitly mapped are denied before any Kubernetes request.

## Namespace policy

Blacklist mode allows new namespaces automatically while denying configured names. Defaults deny `kube-system`, `kube-public`, and `kube-node-lease`.

Label-selector mode allows only matching namespaces:

```text
KubeMcp__NamespacePolicy__Mode=LabelSelector
KubeMcp__NamespacePolicy__LabelSelector=platform.example.com/group in (production,staging)
```

## Authentication

### Static API key

```text
KubeMcp__Authentication__Mode=ApiKey
KubeMcp__Authentication__ApiKey=<high-entropy-key>
```

Clients send `Authorization: Bearer <high-entropy-key>`. Comparison is constant-time and temporary credential buffers are zeroed after use. Supply the key through the deployment platform's secret-management system.

### Unauthenticated mode

`None` is intended only for isolated local development and is rejected unless the host environment is `Development`. There is no non-development override.

## Edge traffic limits

The application does not configure HTTP request-body, header, rate, concurrency, or forwarded-header handling. Production must run on a private network behind an ingress, load balancer, or service mesh that enforces limits appropriate to the expected MCP workload, blocks untrusted direct Service access where required, and owns originating-client IP, external scheme, and external host logging.

`MaxUpstreamBodyBytes`, `MaxResponseBytes`, list item/page sizes and counts, continuation-token bounds, and Kubernetes and overall MCP deadlines remain application settings because they bound Kubernetes input and agent-facing output rather than edge traffic. The reference pod retains explicit CPU and memory requests and limits.

Standard ASP.NET Core `AllowedHosts` filtering remains available. Configure it with the internal hostnames presented directly to the application; the application does not derive hosts from forwarded headers.

## Secret management

The HMAC key and static API key must not be committed. Supply them through the deployment platform's secret-management system.
