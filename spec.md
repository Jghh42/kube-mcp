# Tiny Read-Only Kubernetes MCP

## 1. Purpose

The service provides an intentionally minimal, read-only interface between AI agents and Kubernetes clusters.

Its purpose is to support Kubernetes inspection and troubleshooting while minimizing:

* MCP tool/context overhead
* attack surface
* Kubernetes privileges
* credential exposure
* accidental Secret disclosure
* implementation complexity
* operational complexity
* ambiguity about what an agent is allowed to do

The service exposes exactly **one MCP tool**.

The service must not provide mutation, execution, tunneling, shell access, arbitrary Kubernetes API access, or direct access to Kubernetes credentials.

The Kubernetes credentials used by the service remain isolated from the agent environment and exist only within the MCP server environment.

---

# 2. Core Design Principles

The service should favor:

```text
small
boring
explicit
auditable
deny-by-default
read-only
```

The security model should remain simple enough to explain as:

> An authenticated agent can perform one operation: read explicitly allowed Kubernetes resources. Kubernetes RBAC independently enforces read-only access. Secret values are never returned and are replaced with keyed HMAC fingerprints. Kubernetes credentials and HMAC keys exist only on the MCP server.

Features that substantially complicate this model should require deliberate reconsideration.

---

# 3. Implementation Platform

The service will be implemented using **.NET and ASP.NET Core**.

The intended core technology stack is:

```text
ASP.NET Core
├── ModelContextProtocol.AspNetCore
├── KubernetesClient
├── ASP.NET Core JWT Bearer authentication
├── existing Keycloak integration
├── existing telemetry stack
├── existing structured logging
└── existing audit logging infrastructure
```

The implementation should follow the organization's existing .NET service conventions wherever possible, including:

* application hosting
* dependency injection
* configuration
* secrets/configuration management
* health checks
* telemetry
* structured logging
* audit logging
* containerization
* CI/CD
* security scanning
* deployment practices

The service should not introduce a separate infrastructure pattern merely because it interacts with Kubernetes.

---

# 4. High-Level Architecture

```text
┌─────────────────────────────┐
│ Agent / MCP Client          │
│                             │
│ No kubeconfig               │
│ No Kubernetes credentials   │
└──────────────┬──────────────┘
               │
               │ OAuth client_credentials
               ▼
┌─────────────────────────────┐
│ Keycloak                    │
│                             │
│ client_id + client_secret   │
│          ↓                  │
│ short-lived access token    │
└──────────────┬──────────────┘
               │
               │ MCP over HTTPS
               │ Authorization: Bearer <token>
               ▼
┌─────────────────────────────┐
│ ASP.NET Core / k-mcp        │
│                             │
│ • JWT authentication        │
│ • authorization             │
│ • MCP HTTP transport        │
│ • one MCP tool              │
│ • resource allowlist        │
│ • namespace access policy   │
│ • GET/LIST only             │
│ • Secret sanitization       │
│ • HMAC fingerprints         │
│ • telemetry                 │
│ • audit logging             │
└──────────────┬──────────────┘
               │
               │ KubernetesClient
               ▼
┌─────────────────────────────┐
│ Kubernetes API              │
│                             │
│ Dedicated kubeconfig /      │
│ Kubernetes identity         │
│                             │
│ Read-only RBAC              │
└─────────────────────────────┘
```

---

# 5. Deployment Model

The service should run independently from the agent environment.

Suitable deployment locations include:

* a dedicated management VM
* an internal management host
* a management Kubernetes cluster
* another trusted infrastructure environment

The MCP server owns the Kubernetes credentials.

The agent never receives them.

The preferred initial deployment model is:

```text
one k-mcp instance
        ↓
one Kubernetes cluster/context
```

For example:

```text
k-mcp-prod.internal
        ↓
production cluster

k-mcp-staging.internal
        ↓
staging cluster
```

Each instance may therefore have independent:

* Kubernetes credentials
* Kubernetes RBAC
* HMAC key
* resource allowlist
* namespace access policy
* Keycloak authorization policy
* network policy
* audit trail

Dynamic cluster selection is not required.

---

# 6. MCP Transport

The service will use standard remote MCP transport over HTTP.

Preferred transport:

```text
MCP Streamable HTTP over HTTPS
```

Conceptually:

```text
https://k-mcp.example.internal/mcp
```

STDIO transport is explicitly not the deployment model because Kubernetes credentials must remain isolated from the agent environment.

ASP.NET Core will host the MCP HTTP transport.

TLS must be used for non-local communication.

Direct exposure to the public Internet is not a design goal.

---

# 7. MCP SDK

The service should use the official .NET MCP SDK.

Expected package:

```text
ModelContextProtocol.AspNetCore
```

This provides the MCP server functionality and HTTP transport within the normal ASP.NET Core hosting model.

MCP should therefore be treated as another application endpoint hosted inside the existing ASP.NET Core application rather than as a separate custom networking stack.

---

# 8. Authentication

Production authentication will use the organization's existing Keycloak service-to-service pattern.

Authentication mechanism:

```text
OAuth 2.x
grant_type = client_credentials
Authorization Server = Keycloak
```

Each MCP client or agent receives its own:

```text
client_id
client_secret
```

The MCP client exchanges these with Keycloak and receives a short-lived access token.

The MCP server receives:

```text
Authorization: Bearer <access-token>
```

The MCP server does not receive the original Keycloak client secret.

---

# 9. ASP.NET Authentication

Authentication should use the organization's existing ASP.NET Core / Keycloak integration.

Conceptually:

```text
ASP.NET Core request
        ↓
JWT Bearer authentication
        ↓
Keycloak token validation
        ↓
authenticated ClaimsPrincipal
        ↓
MCP endpoint
        ↓
k8s_get
```

Authentication should occur using normal ASP.NET Core middleware before execution reaches the MCP tool.

The MCP implementation should not build a second custom authentication system.

---

# 10. Token Validation

The server must validate every access token before performing Kubernetes operations.

Validation should include at least:

```text
signature
issuer
audience
expiration
not-before, if applicable
required role/scope
```

A conceptual valid token would contain claims corresponding to:

```text
issuer   = expected Keycloak realm
audience = k-mcp
scope    = k-mcp:read
```

A token issued for another internal application must not automatically authorize access to `k-mcp`.

---

# 11. Authorization Scope

The initial OAuth authorization model should remain deliberately simple.

A single capability such as:

```text
k-mcp:read
```

is sufficient.

There is no initial need for OAuth scopes such as:

```text
k-mcp:pods
k-mcp:secrets
k-mcp:get
k-mcp:list
```

Resource-level authorization remains controlled through:

```text
Keycloak authentication
        ↓
server resource allowlist
        ↓
server namespace access policy
        ↓
Kubernetes RBAC
```

More complicated identity-based policy may be added later only if a concrete requirement appears.

---

# 12. Single MCP Tool

The server exposes exactly one MCP tool:

```text
k8s_get
```

Conceptual input:

```text
resource
namespace
name (optional)
```

Example:

```text
k8s_get(
    resource = "secrets",
    namespace = "database"
)
```

means:

```text
LIST Secrets in namespace database
```

while:

```text
k8s_get(
    resource = "secrets",
    namespace = "database",
    name = "cnpg-db-credentials"
)
```

means:

```text
GET Secret cnpg-db-credentials
```

The same semantics apply to other allowlisted resources.

---

# 13. Tool Semantics

Only two Kubernetes operations exist.

## Name omitted

```text
resource + namespace
        ↓
LIST
```

## Name supplied

```text
resource + namespace + name
        ↓
GET
```

There is no caller-controlled HTTP verb or Kubernetes action.

The MCP interface does not expose:

```text
POST
PUT
PATCH
DELETE
CREATE
UPDATE
WATCH
EXEC
ATTACH
PROXY
PORT-FORWARD
```

These operations should not merely be disabled through runtime configuration.

They should have no implementation path from the MCP tool.

---

# 14. Structured Input Only

The MCP tool accepts structured parameters.

It must not accept:

```text
kubectl commands
shell commands
arbitrary Kubernetes URLs
arbitrary HTTP paths
HTTP verbs
JSONPath expressions
Go templates
command-line arguments
raw API requests
```

For example:

```text
resource = "pods"
namespace = "database"
name = "postgres-1"
```

is valid.

Something equivalent to:

```text
kubectl get --raw ...
```

is not representable through the tool.

---

# 15. Kubernetes Client

The service should interact directly with the Kubernetes API using the official .NET Kubernetes client:

```text
KubernetesClient
```

The service should **not shell out to `kubectl`**.

Direct library access provides:

* structured objects
* normal .NET cancellation
* request timeouts
* HTTP connection reuse
* structured Kubernetes errors
* easier testing
* direct telemetry integration
* no subprocess lifecycle
* no stdout/stderr parsing
* no dependency on an installed kubectl binary
* a smaller command-injection surface

`kubectl` is therefore not part of the normal runtime dependency set.

---

# 16. Generic Kubernetes Resource Access

Because the MCP tool is generic across a small number of resource types, the Kubernetes access layer should use generic Kubernetes API capabilities rather than dedicated code paths for every resource.

The .NET Kubernetes client provides generic resource access suitable for:

```text
core Kubernetes resources
+
CRDs
```

The MCP-facing resource name should resolve through the server-side allowlist to an explicit Kubernetes resource definition.

Conceptually:

```text
"pods"
    ↓
group: ""
version: v1
resource: pods

"deployments"
    ↓
group: apps
version: v1
resource: deployments

"secrets"
    ↓
group: ""
version: v1
resource: secrets

"cnpg-clusters"
    ↓
group: postgresql.cnpg.io
version: v1
resource: clusters
```

The exact .NET representation of this mapping is an implementation detail.

---

# 17. No Implicit Resource Discovery for Authorization

Kubernetes API discovery may be useful internally, but it must not determine what the agent is authorized to access.

Authorization is based on an explicit configured allowlist.

The server must never behave like:

```text
resource exists in Kubernetes
        ↓
therefore agent may access it
```

Instead:

```text
resource explicitly configured
        ↓
therefore request may proceed
```

Kubernetes discovery may later assist validation or resource resolution, but it must not expand the security boundary.

---

# 18. Resource Allowlist

All Kubernetes resources are denied by default.

A resource may only be requested if explicitly configured.

Conceptually:

```text
allowed_resources:

pods:
  group: ""
  version: v1
  resource: pods

deployments:
  group: apps
  version: v1
  resource: deployments

secrets:
  group: ""
  version: v1
  resource: secrets
```

A request for an unknown resource must be rejected before contacting Kubernetes.

The allowlist also provides a convenient stable MCP vocabulary that does not need to exactly mirror arbitrary Kubernetes API naming.

---

# 19. Suggested Initial Resources

A conservative initial troubleshooting set could contain:

```text
pods
services
endpoints
configmaps
secrets
events
persistentvolumeclaims
replicationcontrollers
limitranges
resourcequotas

deployments
statefulsets
daemonsets
replicasets

jobs
cronjobs
endpointslices
ingresses
networkpolicies
horizontalpodautoscalers
poddisruptionbudgets
```

Additional resources should be added only because an actual troubleshooting requirement exists.

For CloudNativePG environments, useful explicitly configured CRDs could include:

```text
clusters.postgresql.cnpg.io
backups.postgresql.cnpg.io
scheduledbackups.postgresql.cnpg.io
poolers.postgresql.cnpg.io
```

For Traefik environments, useful namespaced CRDs include:

```text
ingressroutes.traefik.io
middlewares.traefik.io
traefikservices.traefik.io
tlsoptions.traefik.io
tlsstores.traefik.io
serverstransports.traefik.io
ingressroutetcps.traefik.io
middlewaretcps.traefik.io
serverstransporttcps.traefik.io
ingressrouteudps.traefik.io
```

The principle is:

> A Kubernetes resource is not exposed merely because it exists.

---

# 20. Namespace Access Policy

Requests must require an explicit namespace. There is no implicit all-namespaces
operation.

A static namespace allowlist is not suitable for environments where application
namespaces are created frequently. The server must instead support two explicit
policy modes:

```text
Blacklist:
  allow namespaces by default
  deny configured namespace names such as kube-system

LabelSelector:
  allow only namespaces matching a configured Kubernetes label selector
```

Blacklist mode permits newly created namespaces automatically unless their names
are denied. Label-selector mode supports dynamic grouping such as:

```text
platform.example.com/group in (production,staging)
```

A request therefore proceeds only when:

```text
resource allowed
AND
namespace policy permits the requested namespace
```

Blacklist validation occurs before contacting Kubernetes. Label-selector mode may
query namespace metadata through the Kubernetes API, but this check must complete
before the requested resource GET or LIST is sent.

---

# 21. Kubernetes Credential Isolation

The Kubernetes credential belongs exclusively to the MCP server.

The initial implementation may use a dedicated kubeconfig.

The MCP client must never receive:

```text
kubeconfig
Kubernetes bearer token
client certificate
client private key
ServiceAccount token
```

There is no MCP operation for:

```text
reading the kubeconfig
changing the kubeconfig
selecting a kubeconfig
uploading a kubeconfig
selecting arbitrary Kubernetes contexts
returning Kubernetes credentials
```

---

# 22. Kubernetes RBAC

The server must use a dedicated Kubernetes identity.

Kubernetes RBAC remains an independent security layer and should allow the same or a smaller set of operations than the MCP server.

The authorization sequence is:

```text
valid Keycloak identity?
        ↓ yes

required MCP permission?
        ↓ yes

resource allowlisted?
        ↓ yes

namespace policy permits access?
        ↓ yes

Kubernetes RBAC allows GET/LIST?
        ↓ yes

execute request
```

The MCP allowlist must never be considered a replacement for Kubernetes RBAC.

---

# 23. Internal Component Boundaries

The implementation should remain deliberately small.

A conceptual component structure is:

```text
Mcp/
    KubernetesGetTool

Kubernetes/
    KubernetesReader
    ResourceAllowlist
    NamespaceAccessPolicy

Security/
    SecretSanitizer
    SecretFingerprinter

Authentication/
    existing ASP.NET / Keycloak integration

Audit/
    existing audit infrastructure

Observability/
    existing telemetry infrastructure
```

The exact folders and class names are not normative.

The important requirement is separation of responsibilities.

---

# 24. Single Kubernetes Access Path

There should be exactly one application component responsible for communicating with Kubernetes.

Conceptually:

```text
MCP tool
   ↓
KubernetesReader
   ↓
KubernetesClient
   ↓
Kubernetes API
```

Other parts of the application should not independently create Kubernetes clients or issue Kubernetes API calls.

This creates a single auditable security boundary for all Kubernetes access.

The `KubernetesReader` should only expose the application-level equivalents of:

```text
List
Get
```

There should be no general-purpose method such as:

```text
ExecuteKubernetesRequest(...)
```

that can later be repurposed into arbitrary API access.

---

# 25. Safe Output Boundary

Raw Kubernetes objects should not flow directly from the Kubernetes client to MCP serialization without going through the appropriate safety logic.

The desired model is:

```text
Kubernetes API
      ↓
KubernetesReader
      ↓
resource classification
      ↓
Secret?
 ┌────┴────┐
yes        no
 ↓          ↓
sanitize    safe representation
 ↓          ↓
Safe Kubernetes result
      ↓
MCP tool
```

The MCP presentation layer should only receive data that is already considered safe to return.

This is particularly important for Secrets.

---

# 26. Secrets

Secrets are a special resource with mandatory sanitization.

The primary invariant is:

> No successful MCP response may contain a raw Kubernetes Secret value.

There must be no per-request option that disables this behavior.

The API must not contain parameters such as:

```text
raw=true
showSecret=true
redact=false
includeValues=true
```

---

# 27. Secret Sanitizer Boundary

Secret sanitization should happen within the Kubernetes/security boundary rather than inside MCP response rendering.

Avoid:

```text
KubernetesReader
       ↓
raw Secret
       ↓
MCP tool
       ↓
maybe sanitize
```

Prefer:

```text
KubernetesReader
       ↓
raw Secret
       ↓
mandatory SecretSanitizer
       ↓
safe Secret representation
       ↓
MCP tool
```

This prevents future MCP changes from accidentally bypassing redaction.

A raw Secret should have as small an in-process lifetime and scope as reasonably possible.

---

# 28. Listing Secrets

A Secret LIST request should return a compact discovery representation.

Example:

```yaml
- name: cnpg-db-credentials
  type: kubernetes.io/basic-auth
  keys:
    - username
    - password
    - host
    - port

- name: redis-auth
  type: Opaque
  keys:
    - password
```

A LIST response should expose only useful safe information such as:

```text
name
type
key names
selected safe metadata
```

Fingerprints should not normally be returned during LIST.

This minimizes both data exposure and MCP context use.

---

# 29. Getting an Individual Secret

A GET request for an individual Secret should preserve useful Kubernetes structure while replacing every Secret value.

Example:

```yaml
apiVersion: v1
kind: Secret

metadata:
  name: cnpg-db-credentials
  namespace: database

type: kubernetes.io/basic-auth

data:
  username: hmac-sha256:f6a39d2b...
  password: hmac-sha256:03cd89f1...
  host: hmac-sha256:ab7391cd...
  port: hmac-sha256:9838df20...
```

The agent can therefore determine:

```text
key exists
key missing
same underlying value
different underlying value
value changed over time
```

without receiving the underlying Secret.

---

# 30. Secret Fingerprinting

Secret values must use a keyed fingerprint rather than an ordinary hash.

Conceptually:

```text
fingerprint =
    HMAC-SHA256(
        server-held-HMAC-key,
        raw-secret-bytes
    )
```

The HMAC key must:

* exist only in the MCP server environment
* never be returned over MCP
* never be accepted from MCP input
* never appear in normal logs
* never appear in audit logs

The HMAC approach prevents an observer from trivially computing fingerprints for guessed low-entropy Secret values without possessing the server key.

---

# 31. Secret Value Normalization

Fingerprints represent the underlying Secret bytes.

For Kubernetes `.data`:

```text
base64 value
    ↓
decode
    ↓
raw bytes
    ↓
HMAC-SHA256
```

The fingerprint should not be calculated over the textual base64 representation.

The implementation must treat Secret values as arbitrary binary data rather than assuming UTF-8 text.

---

# 32. HMAC Stability

The recommended production model is one stable HMAC key per MCP/cluster environment.

Therefore:

```text
same underlying value
        ↓
same fingerprint
```

across multiple calls and server restarts.

This permits troubleshooting over time.

Different environments should normally use separate keys:

```text
production
staging
development
```

This prevents unnecessary correlation between environments.

---

# 33. Fingerprint Representation

The output should make it obvious that the value is not the actual Secret.

For example:

```text
hmac-sha256:7e83c2910b864f15
```

A truncated HMAC may be used if the chosen length makes accidental collisions operationally negligible.

The precise representation and truncation length are implementation details.

---

# 34. Secret Metadata Sanitization

Secret sanitization must include more than `.data`.

Metadata or annotations may contain embedded manifests or copies of Secret contents.

The Secret sanitizer must therefore explicitly inspect and remove known unsafe metadata.

The implementation must protect against Secret disclosure through:

```text
.data
.stringData if encountered
annotations
embedded manifests
serialization
exceptions
debug logs
HTTP logging
telemetry enrichment
audit logs
```

The exact sanitization rules should be defined and tested before production use.

---

# 35. Logging of Raw Kubernetes Responses

Raw Kubernetes Secret response bodies must never be written to application logs.

Existing HTTP/body logging or diagnostic middleware must be reviewed to ensure Kubernetes API responses containing Secrets cannot be captured.

This applies to:

* normal structured logs
* debug logs
* request/response logging
* exception logging
* OpenTelemetry spans
* audit logs

Safe metadata about Secret access may be logged, but the Secret body itself may not.

---

# 36. Non-Secret GET Responses

Allowed non-Secret resources may generally be returned with their Kubernetes structure intact.

For example:

```text
k8s_get(
    resource = "deployments",
    namespace = "production",
    name = "payments-api"
)
```

may return the relevant Deployment representation.

The service does not automatically follow references.

If a Deployment references:

```yaml
secretKeyRef:
  name: database-password
```

the agent must explicitly perform another `k8s_get`.

This keeps every Kubernetes access intentional and auditable.

---

# 37. Compact LIST Responses

LIST and GET are intentionally asymmetric.

LIST is optimized for:

```text
discovery
small responses
minimal agent context
```

GET is optimized for:

```text
detailed inspection
```

LIST responses must return compact, resource-specific summaries instead of full manifests or complete Kubernetes `.status` objects.

Responses should remain structured JSON rather than formatted terminal tables, while exposing fields comparable to useful `kubectl get -o wide` output. For example, a Pod LIST could return:

```json
{
  "operation": "LIST",
  "resource": "pods",
  "namespace": "kube-mcp",
  "items": [
    {
      "name": "kube-mcp-88f475c56-8r77x",
      "ready": "1/1",
      "status": "Running",
      "restarts": 0,
      "age": "57m",
      "ip": "10.244.0.12",
      "node": "kind-control-plane"
    }
  ],
  "count": 1,
  "limited": false
}
```

The exact summary fields should vary by resource. Examples include:

```text
Pods:
  name, ready, status, restarts, age, IP, node

Deployments and StatefulSets:
  name, ready, replicas, available, age

DaemonSets:
  name, desired, current, ready, available, age

Services:
  name, type, cluster IP, external IPs, ports, age

ConfigMaps:
  name, key count or key names, age

Secrets:
  name, type, key names, age
```

For an allowed CRD without a resource-specific summarizer, the fallback should contain only compact discovery fields such as:

```text
name
namespace
kind
age or creation timestamp
```

A LIST response should not include complete `.spec`, `.status`, `managedFields`, container status arrays, or other full-object structures merely because they were returned by Kubernetes. The agent should use LIST for discovery and then explicitly GET an interesting object for detailed inspection.

The service should prefer useful compact information over generic serialization of entire lists.

---

# 38. Response Limits

The service must guard against unexpectedly large responses.

Configuration should support limits for:

```text
maximum LIST object count
maximum serialized response size
Kubernetes request timeout
overall MCP request timeout
```

A limited result should explicitly indicate that it was limited.

The server should not silently place very large Kubernetes responses into agent context.

Pagination may be added later if a real requirement appears.

---

# 39. Cancellation and Timeouts

ASP.NET request cancellation should propagate through:

```text
HTTP request
    ↓
MCP tool
    ↓
KubernetesReader
    ↓
KubernetesClient
```

If the MCP client disconnects or the request times out, outstanding Kubernetes work should be cancelled where supported.

The service should use the normal .NET cancellation model rather than independent unmanaged timeouts where possible.

---

# 40. Dependency Injection

Core components should be registered through the normal ASP.NET Core dependency-injection system.

Long-lived infrastructure components such as the Kubernetes HTTP client should be managed in a way that supports:

* connection reuse
* proper lifetime management
* testing
* telemetry
* controlled configuration

The service should avoid creating a new Kubernetes client and new network stack for every MCP call.

Exact service lifetimes are implementation details to determine during implementation.

---

# 41. Error Handling

Errors returned to the MCP client should be concise and safe.

Useful categories include:

```text
authentication_failed
authorization_failed
resource_not_allowed
namespace_not_allowed
resource_not_found
kubernetes_access_denied
invalid_request
response_too_large
upstream_timeout
internal_error
```

Example:

```text
Resource "jobs" is not included in the configured resource allowlist.
```

Kubernetes client exceptions should be translated into safe service-level errors.

Raw upstream HTTP bodies should not automatically be returned to the agent.

---

# 42. Audit Logging

The service will use the organization's existing audit logging system.

Every MCP `k8s_get` operation should generate an audit event.

Useful fields include:

```text
timestamp
authenticated Keycloak identity/client
operation: GET or LIST
resource
namespace
name, if supplied
result
object count
duration
correlation/request ID
```

Example:

```text
client=claude-prod-debug
operation=GET
resource=secrets
namespace=database
name=cnpg-db-credentials
result=success
```

The authenticated identity must come from validated ASP.NET/Keycloak claims, not from MCP arguments.

Audit records must never contain:

```text
client_secret
access token
kubeconfig
Kubernetes credentials
raw Secret values
HMAC key
```

HMAC fingerprints should preferably not be audit-logged by default.

---

# 43. Telemetry

The service should integrate with the organization's existing .NET telemetry stack.

Useful telemetry includes:

```text
request count
request duration
authentication failures
authorization failures
resource allowlist denials
namespace denials
Kubernetes API errors
Kubernetes API latency
response sizes
LIST object counts
Secret GET count
timeouts
```

Telemetry should allow correlation between:

```text
incoming MCP request
    ↓
application processing
    ↓
Kubernetes API request
```

without recording sensitive request or response bodies.

---

# 44. Structured Logging

The service should use the organization's existing structured logging conventions.

Useful safe properties include:

```text
correlation ID
client identity
resource
namespace
resource name
operation
result
duration
```

Logging should avoid serializing arbitrary Kubernetes objects as structured properties because this could capture Secret values.

---

# 45. Health and Readiness

The ASP.NET Core service should expose the organization's normal health/readiness endpoints.

For example:

```text
/healthz
/readyz
```

Exact paths should follow existing organizational conventions.

Health endpoints must not expose:

```text
kubeconfig contents
Kubernetes credentials
HMAC keys
Keycloak secrets
detailed security configuration
```

Whether readiness verifies Kubernetes API connectivity is an implementation decision.

---

# 46. Configuration

Configuration should use the organization's existing .NET configuration approach.

High-level configuration areas include:

```text
HTTP/listener settings
TLS/reverse-proxy settings

Keycloak issuer
expected audience
required scope/role

Kubernetes kubeconfig location

allowed resources
namespace blacklist or namespace label selector

HMAC key/reference

response limits
timeouts

telemetry settings
audit settings
logging settings
```

Sensitive configuration should use the organization's normal secret-management mechanism.

The HMAC key and Kubernetes credentials must not live in ordinary source-controlled configuration.

---

# 47. No Dangerous Feature Flags

There should be no configuration switches equivalent to:

```text
enableWrites
allowKubectl
allowExec
allowArbitraryApi
disableSecretRedaction
returnRawSecrets
```

Dangerous capabilities should require a deliberate future architecture/security decision rather than an accidentally enabled option.

---

# 48. Testing Expectations

The security invariants should be covered by automated tests.

Particularly important tests include:

```text
unknown resource is rejected
disallowed namespace is rejected
invalid identity is rejected

GET can only perform GET
LIST can only perform LIST

Secret .data values never survive sanitization
Secret fingerprints are deterministic with same key
different Secret values produce different fingerprints
different HMAC keys produce different fingerprints

dangerous Secret annotations are removed
raw Secret values never appear in returned JSON/YAML
raw Secret values never appear in application errors

CRDs cannot bypass the allowlist
arbitrary Kubernetes paths cannot be constructed
```

Security-sensitive transformations should have direct unit tests independent of the MCP protocol.

Integration tests should exercise the complete path against a disposable Kubernetes test cluster where practical.

---

# 49. Explicit Non-Goals

The service does not provide:

```text
kubectl execution

create
update
patch
delete
apply
edit
scale
rollout

exec
logs
attach
watch
port forwarding
proxy

Helm
Kustomize

shell execution
file access

arbitrary HTTP requests
arbitrary Kubernetes API paths
Kubernetes impersonation

ServiceAccount token creation
credential generation

raw Secret retrieval

automatic following of references

dynamic kubeconfig selection
dynamic Kubernetes context selection
```

If one of these becomes useful later, it should be evaluated as a separate capability and security decision.

---

# 50. Security Invariants

The implementation is considered correct only while all of the following remain true.

## Invariant 1

Exactly one MCP tool exists:

```text
k8s_get
```

## Invariant 2

Every Kubernetes action caused by MCP is either GET or LIST.

## Invariant 3

Only explicitly configured Kubernetes resources can be accessed.

## Invariant 4

Only permitted namespaces can be accessed.

## Invariant 5

Every Kubernetes access originates from an authenticated and authorized MCP request.

## Invariant 6

Authentication uses the organization's normal Keycloak and ASP.NET Core authentication infrastructure.

## Invariant 7

Tokens intended for unrelated services are rejected.

## Invariant 8

There is one application-level Kubernetes access path.

## Invariant 9

The Kubernetes client is used directly; arbitrary kubectl or shell execution is unavailable.

## Invariant 10

No raw Secret value may appear in an MCP response.

## Invariant 11

Raw Secrets are sanitized before reaching MCP response construction.

## Invariant 12

No configuration or MCP argument can disable Secret sanitization.

## Invariant 13

Secret fingerprints cannot be reproduced without the server-held HMAC key.

## Invariant 14

The MCP client never receives Kubernetes credentials.

## Invariant 15

The MCP client never receives the HMAC key.

## Invariant 16

The tool cannot construct arbitrary Kubernetes API calls.

## Invariant 17

Kubernetes RBAC remains an independent authorization boundary.

## Invariant 18

Raw Secret content is excluded from logs, audit records, telemetry, and error responses.

---

# 51. Example End-to-End Workflow

The agent authenticates:

```text
client_id + client_secret
        ↓
Keycloak
        ↓
short-lived Bearer token
```

The MCP client calls:

```text
k8s_get(
    resource = "pods",
    namespace = "database"
)
```

ASP.NET Core validates the token.

The service validates:

```text
pods is allowed
database is allowed
```

`KubernetesReader` performs the LIST operation through `KubernetesClient`.

The agent discovers:

```text
postgres-1
```

The agent requests:

```text
k8s_get(
    resource = "pods",
    namespace = "database",
    name = "postgres-1"
)
```

The returned Pod references:

```text
cnpg-db-credentials
```

The agent explicitly requests:

```text
k8s_get(
    resource = "secrets",
    namespace = "database",
    name = "cnpg-db-credentials"
)
```

The internal flow becomes:

```text
Kubernetes API
      ↓
raw Secret
      ↓
KubernetesReader
      ↓
SecretSanitizer
      ↓
SecretFingerprinter
      ↓
safe representation
      ↓
MCP tool
      ↓
agent
```

The agent receives:

```yaml
data:
  username: hmac-sha256:71ce...
  password: hmac-sha256:927a...
```

The raw values never leave the MCP server's Kubernetes processing boundary.

---

# 52. Recommended Initial Implementation Scope

The first version should include:

```text
.NET / ASP.NET Core

ModelContextProtocol.AspNetCore

KubernetesClient

existing Keycloak JWT authentication

existing telemetry integration

existing logging integration

existing audit logging integration

one MCP tool:
  k8s_get

operations:
  LIST
  GET

resource allowlist
namespace blacklist or label-selector policy

one Kubernetes cluster per service instance

dedicated kubeconfig / Kubernetes identity

direct Kubernetes API access
no kubectl subprocess

compact LIST responses

full GET responses for safe resources

mandatory Secret sanitization

HMAC-SHA256 Secret fingerprints

response limits

timeouts and cancellation

health/readiness endpoints
```

Do not include initially:

```text
writes
exec
logs
watch
proxy
port-forward

multi-cluster selection

arbitrary API paths

dynamic authorization from API discovery

raw Secret mode

automatic reference traversal

complex resource-specific authorization

custom authentication infrastructure
```

The objective of version 1 is not to build another Kubernetes management platform.

It is to build a very small, authenticated, auditable, read-only Kubernetes inspection gateway specifically suited for use by AI agents.
