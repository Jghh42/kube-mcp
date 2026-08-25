# Security model

An authenticated client can perform one operation: read explicitly permitted namespaced Kubernetes resources. Application policy and Kubernetes RBAC enforce access independently. The client never receives Kubernetes credentials.

## Tool boundary

The service exposes exactly one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

Omitting `name` performs a namespaced LIST; supplying it performs a namespaced GET. There are no mutation, watch, exec, proxy, shell, tunnelling, or arbitrary API tools.

LIST responses use compact resource-specific summaries for the default built-in resources and a minimal name/namespace/kind/age fallback for unknown resources and CRDs. GET responses remain detailed. Response size, page count, item count, and upstream body size are bounded.

## Defence in depth

A request must pass all applicable controls:

1. ASP.NET Core authentication and authorization.
2. Explicit resource mapping policy.
3. Namespace blacklist or label-selector policy.
4. GET/LIST-only application behavior.
5. Kubernetes RBAC for the service identity.
6. Time, pagination, body, and response limits.

The production reference deployment uses a static bearer API key loaded from a Kubernetes Secret. Unauthenticated mode is accepted only when the host environment is `Development`. See [configuration](configuration.md#authentication).

## Secret handling

Raw Kubernetes Secret values are never returned:

- LIST returns safe summary fields and key names.
- GET replaces each value with a keyed HMAC-SHA256 fingerprint.

The HMAC key remains on the server. Keep it stable only when fingerprints need to be comparable across restarts. Audit records and telemetry never contain Secret values or fingerprints.

## Admission and request limits

Two process-wide admission layers apply only to `/mcp`:

- The outer gate admits at most 16 requests and queues 16 before authentication. Overflow returns HTTP `429` before authentication, protocol parsing, per-request observability, or audit publication. This prevents credential floods from amplifying authentication and logging work.
- After authentication and authorization, the inner gate executes two requests and queues two, oldest-first. Overflow returns HTTP `429` with safe audit and telemetry events.

Defaults are configurable. `/mcp` request bodies are limited to 64 KiB; a declared oversized body receives HTTP `413` before parsing or audit logging. Root, liveness, and readiness remain outside both gates.

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

Overall server deadlines use `server_timeout`; caller disconnects use `client_cancelled`; authenticated inner-limit rejection uses `rate_limited`. Upstream response bodies and arbitrary exception messages do not cross the Kubernetes boundary.

## Audit guarantees

Every dispatched `k8s_get` call publishes a sanitized Kubernetes audit record. Authentication, authorization, and inner concurrency denials publish an MCP access-denial record without invented resource coordinates. Middleware does not inspect arbitrary request bodies to infer audit fields.

Records can include:

- UTC timestamp
- authenticated client identity
- authentication mode
- operation and resource coordinates for dispatched tool calls
- result and fixed error category
- duration, request ID, and client IP
- successful object count

They do not include Kubernetes response bodies, Secret values or fingerprints, credentials, tokens, or arbitrary exception text. See [observability and audit logging](observability.md#audit-logging) for dispatch and sink behavior.

## Reverse proxies

Forwarded headers are trusted only from explicitly configured proxy addresses or networks. Host filtering remains active. Never configure a trust-all proxy network; see [configuration](configuration.md#reverse-proxies-and-hosts).

## RBAC

The default ClusterRole grants narrow GET/LIST access for the default built-in resource set and namespace LIST for namespace-policy evaluation. Optional CRDs require explicit, coordinated application mappings and narrow RBAC changes; wildcard reads are not supported. See the [deployment guide](deployment.md#resource-access-and-rbac) and [resource overlays](../overlays/README.md).
