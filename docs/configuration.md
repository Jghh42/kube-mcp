# Configuration reference

Configuration follows standard ASP.NET Core conventions. Environment variable names use double underscores; for example, `KubeMcp:SecretHmacKey` becomes `KubeMcp__SecretHmacKey`.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `KubeMcp:SecretHmacKey` | required | Base64-encoded HMAC key of at least 32 bytes. |
| `KubeMcp:KubeConfigPath` | automatic | Optional kubeconfig path; in-cluster configuration is detected automatically. |
| `KubeMcp:AllowedResources` | see `appsettings.json` | `k8s_get` names mapped to Kubernetes group/version/resource/kind; namespace discovery is independent. |
| `KubeMcp:NamespacePolicy:Mode` | `Blacklist` | `Blacklist` or `LabelSelector`. |
| `KubeMcp:NamespacePolicy:DeniedNamespaces` | system namespaces | Names denied in blacklist mode. |
| `KubeMcp:NamespacePolicy:LabelSelector` | none | Required selector in label-selector mode. |
| `KubeMcp:MaxListItems` | `100` | Maximum objects returned by LIST. |
| `KubeMcp:MaxResponseBytes` | `1048576` | Maximum inner tool-content JSON size, excluding the MCP/HTTP envelope. |
| `KubeMcp:MaxUpstreamBodyBytes` | `4194304` | Per-page or single-object Kubernetes response limit before deserialization; must be at least `MaxResponseBytes`. |
| `KubeMcp:ListPageSize` | `50` | Page size for non-Secret LISTs. |
| `KubeMcp:SecretListPageSize` | `10` | Page size for Secret LISTs; must not exceed `ListPageSize`. |
| `KubeMcp:MaxListPages` | `20` | Maximum continuation pages per LIST. |
| `KubeMcp:KubernetesRequestTimeoutSeconds` | `15` | Kubernetes operation timeout. |
| `KubeMcp:OverallMcpRequestTimeoutSeconds` | `30` | End-to-end MCP deadline; must exceed the Kubernetes timeout plus the credential-gate timeout when that gate is enabled. |
| `KubeMcp:CredentialGate:Enabled` | `false` | Enables the optional Clef credential gate for detailed `k8s_get` GET results only. |
| `KubeMcp:CredentialGate:Endpoint` | required when enabled | Complete absolute HTTP/HTTPS URL whose path ends in `/systemone`; userinfo, query, fragment, and redirects are prohibited. |
| `KubeMcp:CredentialGate:ApiKey` | empty | Optional Clef bearer key, bounded to 8192 UTF-8 bytes. Empty means no `Authorization` header. |
| `KubeMcp:CredentialGate:RequestModel` | required when enabled | Logical model sent in each request. |
| `KubeMcp:CredentialGate:ExpectedResponseModel` | required when enabled | Exact physical model required in Clef responses. |
| `KubeMcp:CredentialGate:ProbabilityThreshold` | none | Required finite release threshold in `[0,0.5)` when enabled. There is deliberately no production default. |
| `KubeMcp:CredentialGate:Prompt` | built-in credential policy | Optional policy override, bounded to 16384 characters. An explicitly empty value is invalid when enabled. |
| `KubeMcp:CredentialGate:ChunkSizeBytes` | `4096` | Maximum UTF-8 bytes in each complete structural JSON state. |
| `KubeMcp:CredentialGate:ScalarOverlapBytes` | `256` | Maximum overlap when an oversized string is split at rune boundaries; cannot exceed one quarter of `ChunkSizeBytes`. |
| `KubeMcp:CredentialGate:TotalTimeoutSeconds` | `15` | Whole-gate deadline, including chunking, every chunk, and every retry. |
| `KubeMcp:CredentialGate:AttemptTimeoutSeconds` | `5` | Per-attempt deadline; must not exceed the total gate timeout. |
| `KubeMcp:CredentialGate:RetryCount` | `2` | Retries (`0`–`2`) for transport failures and HTTP 408, 429, or 5xx; backoffs are 100 ms then 300 ms. |
| `KubeMcp:CredentialGate:MaxInputTokens` | `4096` | Maximum accepted `usage.input_tokens` in a Clef decision (`1`–`1000000`). Set to the deployed slot's validated bound. |
| `KubeMcp:CredentialGate:MaxResponseBodyBytes` | `65536` | Maximum Clef response body read before validation. |
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

The `k8s_get` tool description advertises the configured resource argument names, grouped by API group and sorted deterministically. It is generated at startup from the validated `AllowedResources` mapping; changes require a restart and clients may need to refresh their tool list. These are configured mappings, not a claim that the corresponding APIs are installed or that RBAC permits access. No Kubernetes discovery calls are made, and no additional tool or endpoint is exposed.

Custom mappings also need matching read-only Kubernetes RBAC. Helm deployments can opt into [five predefined namespaced CRD families](../charts/kube-mcp/README.md#optional-crds) using `crds.certManager`, `crds.traefik`, `crds.rookCeph`, `crds.cnpg`, or `crds.argoCD` flags. Each enabled flag adds explicit application mappings and matching chart RBAC (unless `rbac.create=false`, in which case external RBAC is required). Non-Helm deployments can use [optional overlays](../overlays/README.md) for examples. There is no wildcard application resource mode; resources that are not explicitly mapped are denied before any Kubernetes request. Do not add `namespaces`: argument-free `k8s_list_namespaces` is a fixed core-v1 LIST independent of this mapping, and `k8s_get` remains namespaced-only.

## Namespace policy

Blacklist mode allows new namespaces automatically while denying configured names. Defaults deny `kube-system`, `kube-public`, and `kube-node-lease`. Namespace discovery silently omits denied names, including on filtered-only pages.

Label-selector mode allows only matching namespaces. Namespace discovery sends this server-controlled selector to Kubernetes on every page; clients cannot provide or override it:

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

## Optional Clef credential gate

The gate is an outbound release check, not an authorization mechanism. It receives the exact bounded JSON returned by `IKubernetesReader` after Secret sanitization, then structurally chunks that JSON if needed. Classification is scalar-centric: every field value retains available nearest and ancestor `name` identity context, while pairwise state overlap is defense in depth; detection of credentials deliberately fragmented across three or more independent fields is not guaranteed. It runs only when `k8s_get` has a non-null `name`; all LIST results and namespace discovery bypass it. See the [credential decision gate](decision-model-gate.md) for the response contract and failure behavior.

Use generic environment configuration and a deployment secret; no dedicated chart values are required. This illustrative threshold is experimental and must be privately qualified for the actual workload:

```text
KubeMcp__CredentialGate__Enabled=true
KubeMcp__CredentialGate__Endpoint=https://clef.internal.example/systemone
KubeMcp__CredentialGate__ApiKey=<from-secret-manager-or-empty>
KubeMcp__CredentialGate__RequestModel=decision
KubeMcp__CredentialGate__ExpectedResponseModel=clef-flash-q4_k_m
KubeMcp__CredentialGate__ProbabilityThreshold=0.20
KubeMcp__OverallMcpRequestTimeoutSeconds=35
```

The built-in prompt treats state as untrusted and detects reusable credentials while allowing HMAC-SHA256 fingerprints, placeholders, and unresolved Secret references. It intentionally does not classify PII. The API key, payload, prompt, response, and probabilities must not be logged.

## Edge traffic limits

The application does not configure HTTP request-body, header, rate, concurrency, or forwarded-header handling. Production must run on a private network behind an ingress, load balancer, or service mesh that enforces limits appropriate to the expected MCP workload, blocks untrusted direct Service access where required, and owns originating-client IP, external scheme, and external host logging.

`MaxUpstreamBodyBytes`, `MaxResponseBytes`, list item/page sizes and counts, continuation-token bounds, and Kubernetes and overall MCP deadlines remain application settings because they bound Kubernetes input and agent-facing output rather than edge traffic. The reference pod retains explicit CPU and memory requests and limits.

Standard ASP.NET Core `AllowedHosts` filtering remains available. Configure it with the internal hostnames presented directly to the application; the application does not derive hosts from forwarded headers.

## Secret management

The HMAC key and static API key must not be committed. Supply them through the deployment platform's secret-management system.
