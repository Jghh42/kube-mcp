# Configuration reference

Configuration follows standard ASP.NET Core conventions. Environment variable names use double underscores; for example, `KubeMcp:SecretHmacKey` becomes `KubeMcp__SecretHmacKey`.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `KubeMcp:SecretHmacKey` | required | Base64-encoded HMAC key of at least 32 bytes. |
| `KubeMcp:KubeConfigPath` | automatic | Optional kubeconfig path; in-cluster configuration is detected automatically. |
| `KubeMcp:ReadinessNamespace` | none | Representative namespace for namespaced readiness authorization checks. |
| `KubeMcp:ResourcePolicy:Mode` | `Allowlist` | `Allowlist` or explicit `AllowAll`. |
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
| `KubeMcp:DiscoveryParallelism` | `4` | Maximum parallel API-group discovery requests in `AllowAll` mode. |
| `KubeMcp:KubernetesRequestTimeoutSeconds` | `15` | Kubernetes operation timeout. |
| `KubeMcp:OverallMcpRequestTimeoutSeconds` | `30` | End-to-end MCP deadline; must exceed the Kubernetes timeout. |
| `KubeMcp:DiscoveryCacheSeconds` | `300` | Discovery cache lifetime in `AllowAll` mode. |
| `KubeMcp:McpAdmission:PermitLimit` | `16` | Pre-authentication `/mcp` permits (1–128). |
| `KubeMcp:McpAdmission:QueueLimit` | `16` | Pre-authentication queue bound (0–128). |
| `KubeMcp:McpConcurrency:PermitLimit` | `2` | Concurrent authenticated `/mcp` requests (1–16). |
| `KubeMcp:McpConcurrency:QueueLimit` | `2` | Authenticated oldest-first queue bound (0–4). |
| `KubeMcp:Telemetry:Enabled` | `false` | Enable OpenTelemetry metrics, traces, and OTLP export. |
| `KubeMcp:Authentication:Mode` | `ApiKey` | `None`, `ApiKey`, or `OAuthClientCredentials`; Development settings select `None`. |
| `KubeMcp:Authentication:AllowUnauthenticated` | `false` | Required opt-in for `None` outside the Development environment. |
| `KubeMcp:Authentication:ApiKey` | none | Static bearer key of at least 32 bytes. |
| `KubeMcp:Authentication:OAuth:Authority` | none | Exact OIDC issuer/authority URL. |
| `KubeMcp:Authentication:OAuth:Audience` | none | Required JWT audience. |
| `KubeMcp:Authentication:OAuth:RequiredScopes` | `k-mcp:read` | Scopes every token must contain. |
| `KubeMcp:Authentication:OAuth:RequiredRoles` | empty | Roles every token must contain. |
| `KubeMcp:Authentication:OAuth:RequireHttpsMetadata` | `true` | Require HTTPS for OIDC discovery. |
| `KubeMcp:Authentication:OAuth:ClockSkewSeconds` | `60` | JWT lifetime tolerance (0–300 seconds). |
| `KubeMcp:ForwardedHeaders:KnownProxies` | loopback | Trusted reverse-proxy IP addresses. |
| `KubeMcp:ForwardedHeaders:KnownNetworks` | loopback | Trusted reverse-proxy CIDRs. |
| `KubeMcp:ForwardedHeaders:AllowedForwardedHeaders` | `XForwardedFor, XForwardedProto, XForwardedHost` | Headers accepted from trusted proxies and networks. |
| `AllowedHosts` | local and service names | Semicolon-delimited ASP.NET Core host allowlist. |

## Resource policy

Allowlist mode resolves a resource only when its MCP name has an explicit mapping. Discovery cannot expand the allowlist. Every mapping must provide a non-null `Group`; use `""` for the core API group.

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

Custom mappings also need matching read-only Kubernetes RBAC. See [optional overlays](../overlays/README.md) for examples.

To resolve every discoverable namespaced resource supporting GET/LIST, explicitly set:

```text
KubeMcp__ResourcePolicy__Mode=AllowAll
```

This emits a startup warning and does not expand Kubernetes RBAC automatically. See the [deployment guide](deployment.md#resource-access-and-rbac).

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

Clients send `Authorization: Bearer <high-entropy-key>`. The key is not an OAuth token; the bearer header is used for client compatibility.

### OAuth client credentials

The server validates access tokens but never receives or stores the caller's OAuth client secret. The caller exchanges its credentials with the authorization server:

```sh
curl --request POST "$KEYCLOAK/realms/$REALM/protocol/openid-connect/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode client_id="$CLIENT_ID" \
  --data-urlencode client_secret="$CLIENT_SECRET"
```

Configure `Mode=OAuthClientCredentials`, the exact realm authority, audience, and required scopes/roles. Arrays use numeric environment-variable suffixes:

```text
KubeMcp__Authentication__OAuth__RequiredScopes__0=k-mcp:read
```

JWT validation covers signature, issuer, audience, lifetime, all configured scopes, and all configured roles. Top-level, Keycloak realm, and configured-audience `resource_access` roles are supported. HTTPS metadata is required by default.

### Unauthenticated mode

`None` is intended only for isolated local development. Outside the Development environment it is rejected unless `KubeMcp__Authentication__AllowUnauthenticated=true` is also set. Do not use this override in production.

## Concurrency and memory

The outer admission gate bounds work before authentication. The inner gate bounds authenticated MCP/Kubernetes work. Both are process-wide, oldest-first limits rather than per-IP or per-token quotas.

Validation requires the outer permit count to cover authenticated permits plus all inner queue slots. It also requires:

```text
McpConcurrency:PermitLimit × MaxUpstreamBodyBytes <= 64 MiB
```

This reserves most of the reference pod's 256 MiB limit for object expansion, protocol envelopes, and runtime overhead. Queued requests remain subject to the overall MCP deadline.

## Reverse proxies and hosts

Forwarded client IP, scheme, and host are accepted only when the immediate peer matches a configured trusted proxy or network. Loopback is the only built-in trust.

```text
KubeMcp__ForwardedHeaders__KnownProxies__0=10.0.0.5
KubeMcp__ForwardedHeaders__KnownNetworks__0=10.42.0.0/16
AllowedHosts=k-mcp.example.internal;kube-mcp;kube-mcp.kube-mcp.svc;localhost;127.0.0.1;[::1]
```

Use the narrowest ingress address or network possible; never trust `0.0.0.0/0` or `::/0`. Include every external and direct in-cluster hostname in `AllowedHosts`. Forwarded values from untrusted peers are ignored.

## Secret management

The HMAC key, static API key, OAuth client secrets, and telemetry exporter credentials must not be committed. Supply them through the deployment platform's secret-management system.
