# kube-mcp

Tiny read-only Kubernetes MCP service built with .NET 10, ASP.NET Core, the official
MCP C# SDK, and the official Kubernetes .NET client.

The service currently exposes exactly one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

Omitting `name` performs a compact namespaced LIST. Supplying `name` performs a
namespaced GET. LIST uses compact resource-specific structured summaries for the
default built-in resource set and a minimal name/namespace/kind/age fallback for
unknown resources and CRDs. GET remains detailed.
Kubernetes Secrets are never returned raw: LIST returns safe discovery fields and
key names, while GET replaces each value with a keyed HMAC-SHA256 fingerprint.

Authentication is configurable per deployment: a static bearer API key, OAuth
client credentials with JWT bearer validation, or an explicitly selected
unauthenticated development mode. The base configuration fails closed in API-key
mode until a key is supplied, while `appsettings.Development.json` is the only
application settings file that selects `None`. Outside the `Development`
environment, `None` is rejected at startup unless the deployment deliberately sets
`KubeMcp:Authentication:AllowUnauthenticated=true`. OAuth validates signature,
issuer, audience, lifetime, all configured scopes, and all configured roles before
MCP execution. Resource and namespace access policies are enforced independently.

Two process-wide admission layers apply only to `/mcp`. A cheap outer bound admits
at most 16 requests before authentication and queues 16 oldest-first; overflow
fails with HTTP `429` before authentication, protocol parsing, observability, or
per-request audit publication. This prevents invalid JWT/API-key floods from
creating unbounded authentication or logging work. After successful authentication
and authorization, the smaller MCP/Kubernetes limiter allows two requests to
execute while two wait oldest-first, preserving fair ordering for authenticated
clients and bounding simultaneous upstream response allocations. Root, liveness,
and readiness remain outside both limiters. `/mcp` request bodies are limited to
64 KiB; declared oversized bodies receive HTTP `413` before body parsing or audit
logging.

Every dispatched `k8s_get` call emits a structured Kubernetes audit event. Requests
rejected by authentication, authorization, or the concurrency limiter before tool
dispatch emit a separate MCP access-denial event with no invented resource
coordinates; the middleware never reads an arbitrary request body to derive audit
fields. Events include UTC
timestamp, authenticated client identity when available, authentication mode,
result, a stable low-cardinality category, duration, request ID, and client IP.
Kubernetes events additionally contain GET/LIST, resource coordinates, and a
successful object count. Audit records contain no Kubernetes response bodies,
Secret values, fingerprints, credentials, or token contents. In unauthenticated
mode the client is recorded as `anonymous`; static API-key calls use the non-secret
shared identity `static-api-key`; OAuth calls prefer the validated
`client_id`/`azp`/`sub` claim.

The structured `ILogger` audit sink remains enabled by default, but it and every
additional organization `IAuditSink` run only behind the bounded, non-blocking,
best-effort dispatcher—never on request threads. `CompositeAuditSink` fans each
sanitized record out sequentially in the background with a two-second deadline per
sink. Exceptions and deadline overruns do not stop later sinks. A sink that ignores
cancellation is allowed at most one outstanding invocation and is skipped for later
records until it completes, preventing a hung provider from permanently starving
the fan-out. Sink/logging failures never replace a response or the original tool
error. If the 1,024-record queue is full, the newest record is dropped; aggregate
local event `AuditQueueFull` is reported every 30 seconds from a separate background
loop, never on the request path. The queue is drained during the host's
graceful-shutdown window; cancellation of that window may leave records
undelivered. Deployments requiring durable, tamper-resistant retention should
register their audit provider and alert on sink failures, deadlines, and queue
drops.

Kubernetes failures are mapped to fixed safe messages and categories such as
`resource_not_found`, `kubernetes_access_denied`, `upstream_throttled`,
`upstream_server_error`, `upstream_network_error`,
`upstream_malformed_response`, `response_too_large`, `upstream_timeout`, and
`internal_error`. Upstream error bodies and arbitrary exception messages never
cross the Kubernetes boundary. Overall server deadlines use `server_timeout`, while
a caller disconnect/cancellation uses `client_cancelled`. Authenticated inner
concurrency rejections use `rate_limited`, return HTTP `429`, and use the same safe
audit and low-cardinality telemetry paths as other pre-tool denials. Outer
pre-authentication admission overflow also returns `429` but intentionally bypasses
per-request observability/audit to prevent flood amplification.

### OpenTelemetry

Set `KubeMcp__Telemetry__Enabled=true` to export custom MCP and Kubernetes metrics
and traces over OTLP. Exporter connection and authentication use standard
OpenTelemetry settings understood by organization-managed collectors:

```text
OTEL_EXPORTER_OTLP_ENDPOINT=https://otel-collector.example.internal:4317
OTEL_EXPORTER_OTLP_PROTOCOL=grpc
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <collector credential>
```

`http/protobuf` is also supported through `OTEL_EXPORTER_OTLP_PROTOCOL`. Keep
collector credentials in the deployment's secret-management system. The custom
instruments cover MCP request count/duration/denials, Kubernetes duration/errors,
safe tool-content response size, LIST count, sanitized Secret GET count, and
server/upstream timeouts. Only curated custom spans from the `/mcp` middleware and
Kubernetes tool boundary are exported; generic ASP.NET URL/query/user-agent spans,
request/response bodies, and arbitrary exception events are not recorded. Metrics
and custom spans use only fixed operations, outcomes, HTTP status codes, and safe
error categories. They never tag Kubernetes resource/object names, namespaces, request
or response bodies, tokens, fingerprints, or arbitrary exception text.

## Prerequisites

- .NET 10 SDK
- Docker
- kind
- kubectl
- curl and Python 3 (for the kind OAuth harness)
- OpenSSL (for generating the development HMAC key)

## Build and test

```sh
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build --no-restore
```

The test suite includes Secret sanitization/fingerprinting tests, compact LIST
summary tests that reject heavyweight object content, production authentication
fail-closed tests, trusted reverse-proxy/host/audit tests, and an in-process MCP
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
produces container tags `v1.2.3`, `1.2.3`, and `1.2`. Release-tag builds never
create or move `latest`; only an explicit successful push to the repository's
default branch publishes that tag. The workflow authenticates with its short-lived
`GITHUB_TOKEN` and requires no repository secret.

A newly created GHCR package is private by default. After the first successful
publish, change the package visibility to public in its GitHub package settings so
clusters can pull it without an image pull secret.

## End-to-end test with kind

For a local run, the integration harness builds and loads a test image. In CI, the
kind job instead builds one content-addressed image archive and hands that exact
archive to the harness; after kind succeeds, the container job scans, SBOMs, and
publishes the same payload without rebuilding it. The harness generates an
ephemeral HMAC key and deploys a one-pod Keycloak development server with an
imported test realm. It obtains a token through the real `client_credentials` grant
and verifies invalid client secrets, audience/scope/role enforcement, compact LIST
output, detailed GET, Secret sanitization, resource denials, both namespace policy
modes, and explicit resource `AllowAll` mode:

```sh
./tests/integration/run-kind.sh
```

Both harness-owned namespaces are removed afterward, so the tested
OAuth-protected `kube-mcp` deployment, local Keycloak, Secrets, and fixture objects
do not remain in kind. Any pre-existing `kube-mcp-reader` ClusterRole and
ClusterRoleBinding are restored from exact snapshots (and removed again when they
did not exist before the run). Keycloak uses ephemeral H2 storage and fixed,
local-only test credentials from
[`tests/integration/keycloak.yaml`](tests/integration/keycloak.yaml); it is not a
production deployment.

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

The reference manifest is a **production, authenticated** deployment. Before
applying it, replace the example OAuth authority, audience/scope/role values, and
`k-mcp.example.internal` in `AllowedHosts` with values for your deployment. The
MCP endpoint returns `401` when credentials are absent or invalid. A missing or
invalid authentication configuration fails application startup rather than
silently exposing `/mcp`.

Deploy and wait for readiness:

```sh
kubectl apply --filename deployment.yaml
kubectl rollout status deployment/kube-mcp --namespace kube-mcp
```

For an isolated local development cluster only, apply the explicitly named
development overlay after the reference manifest. It sets both `Mode=None` and the
non-production opt-in, making `/mcp` reachable without credentials:

```sh
kubectl apply --filename deployment.yaml
kubectl apply --filename deployment-development.yaml
```

Never expose `deployment-development.yaml` on a shared or production network.
Reapply `deployment.yaml` to restore authenticated mode.

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
| `KubeMcp:ReadinessNamespace` | none | Optional representative namespace for accurately scoped namespaced readiness SSARs; omit for a cluster-wide authorization check |
| `KubeMcp:ResourcePolicy:Mode` | `Allowlist` | `Allowlist` or the explicit `AllowAll` opt-in |
| `KubeMcp:AllowedResources` | see `appsettings.json` | Explicit MCP name to Kubernetes group/version/resource/kind mappings in allowlist mode |
| `KubeMcp:NamespacePolicy:Mode` | `Blacklist` | `Blacklist` or `LabelSelector` |
| `KubeMcp:NamespacePolicy:DeniedNamespaces` | Kubernetes system namespaces | Names denied in blacklist mode |
| `KubeMcp:NamespacePolicy:LabelSelector` | none | Required Kubernetes label selector in label-selector mode |
| `KubeMcp:MaxListItems` | `100` | Maximum objects returned by LIST |
| `KubeMcp:MaxResponseBytes` | `1048576` | Maximum safe inner tool-content JSON size (not the complete MCP/HTTP wire envelope) |
| `KubeMcp:MaxUpstreamBodyBytes` | `4194304` | Per-page or single-object Kubernetes response cap enforced before deserialization |
| `KubeMcp:McpAdmission:PermitLimit` | `16` | Outer pre-authentication `/mcp` admission permits (1-128); must cover authenticated permits plus the complete inner queue |
| `KubeMcp:McpAdmission:QueueLimit` | `16` | Oldest-first pre-authentication queue bound (0-128); overflow receives HTTP 429 without per-request audit work |
| `KubeMcp:McpConcurrency:PermitLimit` | `2` | Process-wide maximum authenticated `/mcp` requests executing concurrently (1-16) |
| `KubeMcp:McpConcurrency:QueueLimit` | `2` | Oldest-first waiting-request bound (0-4); `0` makes overflow fail fast with HTTP 429 |
| `KubeMcp:ListPageSize` | `50` | Kubernetes page size for non-Secret LISTs |
| `KubeMcp:SecretListPageSize` | `10` | Smaller Kubernetes page size for Secret LISTs |
| `KubeMcp:MaxListPages` | `20` | Maximum continuation pages fetched for one LIST |
| `KubeMcp:KubernetesRequestTimeoutSeconds` | `15` | Kubernetes reader operation timeout |
| `KubeMcp:OverallMcpRequestTimeoutSeconds` | `30` | End-to-end `/mcp` server deadline; must be greater than the Kubernetes timeout |
| `KubeMcp:DiscoveryCacheSeconds` | `300` | API discovery cache lifetime when resource `AllowAll` mode is enabled |
| `KubeMcp:Telemetry:Enabled` | `false` | Enable low-cardinality OpenTelemetry metrics/traces and OTLP export |
| `KubeMcp:Authentication:Mode` | `ApiKey` (`None` in `appsettings.Development.json`) | `None`, `ApiKey`, or `OAuthClientCredentials` |
| `KubeMcp:Authentication:AllowUnauthenticated` | `false` | Deliberate deployment-level opt-in required for `None` outside the `Development` environment; never enable in production |
| `KubeMcp:Authentication:ApiKey` | none | Static key of at least 32 bytes; sent as an `Authorization: Bearer` credential |
| `KubeMcp:Authentication:OAuth:Authority` | none | Exact OIDC issuer/authority URL |
| `KubeMcp:Authentication:OAuth:Audience` | none | Required JWT audience, normally `k-mcp` |
| `KubeMcp:Authentication:OAuth:RequiredScopes` | `k-mcp:read` | Scopes all accepted tokens must contain |
| `KubeMcp:Authentication:OAuth:RequiredRoles` | empty | Roles all accepted tokens must contain; top-level, Keycloak realm, and `resource_access` roles for the configured audience are supported |
| `KubeMcp:Authentication:OAuth:RequireHttpsMetadata` | `true` | Require HTTPS for OIDC discovery; set false only for local HTTP testing |
| `KubeMcp:Authentication:OAuth:ClockSkewSeconds` | `60` | JWT lifetime validation tolerance, from 0 to 300 seconds |
| `KubeMcp:ForwardedHeaders:KnownProxies` | loopback only | Explicit trusted reverse-proxy IP addresses |
| `KubeMcp:ForwardedHeaders:KnownNetworks` | loopback only | Explicit trusted reverse-proxy CIDRs |
| `KubeMcp:ForwardedHeaders:AllowedForwardedHeaders` | `XForwardedFor, XForwardedProto, XForwardedHost` | Headers honored only from the trusted proxies/networks |
| `AllowedHosts` | localhost and in-cluster service names | Semicolon-delimited ASP.NET Core host allowlist; production manifests must add their public hostname(s) |

Both admission layers are global partitions, not per-IP or per-token quotas, so
they do not trust caller-controlled addressing. `McpAdmission` is the larger,
bounded oldest-first outer gate; its overflow is intentionally not audited per
request to avoid turning a credential flood into a logging amplifier.
`McpConcurrency` runs after authentication/authorization, where all authorized
clients share the pod's memory budget in oldest-first order. Validation requires
the outer permit limit to cover authenticated permits plus all inner queue slots,
and requires `McpConcurrency:PermitLimit * MaxUpstreamBodyBytes` to be at most 64
MiB, reserving
at least three quarters of the reference 256 MiB pod limit for managed-object
expansion, protocol envelopes, and runtime overhead. Raise values only with the pod
memory limit considered. Queued requests remain subject to the overall MCP
deadline.

Resources are denied unless their MCP name has an explicit mapping. The defaults
cover common namespaced, built-in Kubernetes resources only. Optional
CloudNativePG and Traefik resources and RBAC are separate, explicit overlays under
[`overlays/`](overlays/README.md). The mapping is resolved before any Kubernetes
request and API discovery cannot expand it. Custom mappings also require
corresponding read-only Kubernetes RBAC.
Every mapping must provide a non-null `Group`; use `""` for the core Kubernetes API
group. A custom mapping looks like:

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

The HMAC key, static API key, and OAuth client secrets must not be committed to
source control. Production environments should provide them through the
organization’s normal secret-management system.

### Authentication modes

The checked-in production deployment explicitly uses
`OAuthClientCredentials`; it never uses unauthenticated mode. In static API-key
mode, configure `KubeMcp__Authentication__Mode=ApiKey`, inject
`KubeMcp__Authentication__ApiKey` from a Kubernetes Secret, and send:

```http
Authorization: Bearer <configured static key>
```

The static key is not an OAuth token; the standard bearer header is used because it
is broadly supported by MCP clients and HTTP tooling. The configured authentication
mode determines whether the bearer credential is compared to the static key or
validated as an OAuth JWT.

In OAuth mode, the MCP server is a resource server: it never receives or stores an
OAuth client secret. The caller exchanges its credentials at Keycloak and sends the
resulting access token:

```sh
curl --request POST "$KEYCLOAK/realms/$REALM/protocol/openid-connect/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode client_id="$CLIENT_ID" \
  --data-urlencode client_secret="$CLIENT_SECRET"

# MCP requests then include:
# Authorization: Bearer <access_token>
```

Configure `Mode=OAuthClientCredentials`, an exact Keycloak realm authority, the
`k-mcp` audience, and the required scope/role arrays. Array environment variables
use numeric suffixes, for example
`KubeMcp__Authentication__OAuth__RequiredScopes__0=k-mcp:read`. The JWT bearer
middleware obtains signing keys through OIDC discovery/JWKS. HTTPS metadata remains
mandatory by default; the kind harness disables it only for cluster-local testing.
Health, readiness, and the informational root endpoint remain public in every mode.
Readiness uses an opaque two-second Kubernetes authorization probe. Concurrent
callers share one probe and its result is cached for one second; label-selector mode
also verifies cluster-scoped namespace LIST authorization. Set
`KubeMcp:ReadinessNamespace` to a representative policy-allowed namespace when
readiness should check namespaced GET/LIST RoleBinding access instead of the default
cluster-wide authorization question.

`None` is intended only for local development. It is selected by the explicitly
named `appsettings.Development.json` and `deployment-development.yaml` examples.
The validator rejects it in every other environment unless
`KubeMcp__Authentication__AllowUnauthenticated=true` is also set by the deployment.
That override exists for isolated development deployments, not production.

### Reverse proxies and host filtering

Forwarded client IP, scheme, and host are processed before authentication and MCP
audit handling. They are accepted only when the immediate peer matches an explicit
`KnownProxies` address or `KnownNetworks` CIDR; loopback is the only built-in trust.
There is no trust-all setting. For example:

```text
KubeMcp__ForwardedHeaders__KnownProxies__0=10.0.0.5
KubeMcp__ForwardedHeaders__KnownNetworks__0=10.42.0.0/16
AllowedHosts=k-mcp.example.internal;kube-mcp;kube-mcp.kube-mcp.svc;localhost;127.0.0.1;[::1]
```

Use the narrowest ingress-controller address/network possible and never enter
`0.0.0.0/0` or `::/0`. `AllowedHosts` values are semicolon-delimited and must
include every external production hostname and any direct in-cluster hostname used
by probes or proxy-to-service requests. With a trusted proxy, audit events record
the forwarded originating client IP; forwarded values from untrusted peers are
ignored.

## Kubernetes RBAC

The default `ClusterRole` grants only `get` and `list` for the core built-in
resource allowlist. It additionally grants namespace `list` so Kubernetes can
evaluate label-selector namespace policy. It grants no optional CloudNativePG or
Traefik CRDs, wildcard resources, create, update, patch, delete, watch, exec, or
proxy operations. Enable optional CRD mappings and their matching RBAC only through
the documented [`overlays/`](overlays/README.md).

`deployment-allow-all-rbac.yaml` is a separate, explicit opt-in that changes this
identity to cluster-wide wildcard GET/LIST access. Application resource mode and
Kubernetes RBAC are independent: enabling only one does not bypass the other.
