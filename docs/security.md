# Security model

A client that passes the configured authentication boundary can perform one operation: read explicitly permitted namespaced Kubernetes resources. Production requires API-key authentication; isolated Development mode may explicitly allow anonymous access. Application policy and Kubernetes RBAC enforce access independently. The client never receives Kubernetes credentials.

## Tool boundary

The service exposes exactly one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

Omitting `name` performs a namespaced LIST; supplying it performs a namespaced GET. There are no mutation, watch, exec, proxy, shell, tunnelling, or arbitrary API tools.

Non-Secret LIST responses use one generic compact summary containing only name, namespace, kind, and age when creation metadata is available. This applies equally to built-in resources and configured CRDs. GET responses remain detailed. Response size, page count, item count, and upstream body size are bounded.

## Defence in depth

A request must pass all applicable controls:

1. ASP.NET Core authentication and authorization.
2. Explicit resource mapping policy.
3. Namespace blacklist or label-selector policy.
4. GET/LIST-only application behavior.
5. Kubernetes RBAC for the service identity.
6. Kubernetes deadlines, pagination bounds, upstream body limits, and safe-output limits.

The production reference deployment uses a static bearer API key loaded from a Kubernetes Secret. Unauthenticated mode is accepted only when the host environment is `Development`. See [configuration](configuration.md#authentication).

## Secret handling

Raw Kubernetes Secret values are never returned:

- LIST uses a dedicated safe summary with the Secret name, type, key names, and age; it returns neither values nor fingerprints.
- GET replaces each value with a keyed HMAC-SHA256 fingerprint.

The HMAC key remains on the server. Keep it stable only when fingerprints need to be comparable across restarts. Logs and audit records never contain Secret values or fingerprints.

## Edge traffic controls

Production runs on a private network behind an ingress, load balancer, or service mesh. That edge must enforce HTTP request-body and header limits plus request rate and concurrency limits. It also owns originating-client IP, external scheme, and external host logging, and must prevent untrusted direct access to the application Service where required. These controls are intentionally not implemented in the application.

The application retains the boundaries only it can enforce: Kubernetes response-body limits, safe tool-output limits, item and page counts, continuation-token bounds, and Kubernetes and overall MCP deadlines. Root, liveness, and readiness routing is independent of MCP authentication. The health endpoints return only fixed process/startup status and do not probe Kubernetes; startup validation and fixed safe request-time errors remain fail-closed.

## Safe errors

Kubernetes failures are converted to fixed messages and low-cardinality categories:

- `resource_not_found`
- `kubernetes_access_denied`
- `upstream_throttled`
- `upstream_server_error`
- `upstream_network_error`
- `upstream_malformed_response`
- `response_too_large`
- `upstream_timeout`
- `internal_error`

Overall server deadlines use `server_timeout`; caller disconnects use `client_cancelled`. Upstream response bodies and arbitrary exception messages do not cross the Kubernetes boundary.

## Audit guarantees

Every dispatched `k8s_get` call writes a sanitized structured Kubernetes audit event through the standard `ILogger` pipeline. Application-owned authorization denials write a coordinate-free MCP access-denial event. Authentication failures are handled by ASP.NET Core and infrastructure access logging. Middleware does not inspect arbitrary request bodies to infer audit fields.

Records can include:

- UTC timestamp
- client identity (`static-api-key` or Development-only `anonymous`)
- authentication mode
- operation and resource coordinates for dispatched tool calls
- result and fixed error category
- duration and request ID
- successful object count

They do not include Kubernetes response bodies, Secret values or fingerprints, credentials, tokens, arbitrary exception text, client IP addresses, or forwarded-header values. Untrusted string fields are length-bounded and have control characters replaced.

Already-sanitized events are written directly through the dedicated `ILogger<AuditLogger>` category and standard logging providers. Logging is best effort and cannot replace the original tool result or error. Deployments that require durable, tamper-resistant retention must configure that guarantee in their logging infrastructure. API-key clients are identified as `static-api-key`; unauthenticated development clients are identified as `anonymous` without recording bearer credentials.

## RBAC

The default ClusterRole grants narrow GET/LIST access for the default built-in resource set and namespace LIST for namespace-policy evaluation. Optional CRDs require explicit, coordinated application mappings and narrow RBAC changes; wildcard reads are not supported. See the [deployment guide](deployment.md#resource-access-and-rbac) and [resource overlays](../overlays/README.md).
