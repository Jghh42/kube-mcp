# Security model

A client that passes the configured authentication boundary can read explicitly permitted namespaced Kubernetes resources and discover namespaces admitted by server policy. Production requires API-key authentication; isolated Development mode may explicitly allow anonymous access. Application policy and Kubernetes RBAC enforce access independently. The client never receives Kubernetes credentials.

## Tool boundary

The service exposes exactly two Streamable HTTP MCP tools:

```text
k8s_get(resource, namespace, name?)
k8s_list_namespaces()
```

Omitting `name` from `k8s_get` performs a namespaced LIST; supplying it performs a namespaced GET. Argument-free `k8s_list_namespaces` is the sole cluster-scoped operation and performs only core-v1 Namespace LIST. Namespace GET, watch, mutation, caller-provided selectors or continuation tokens, generic cluster-scoped reads, exec, proxy, shell, and tunnelling are unavailable.

Non-Secret namespaced LIST responses use one generic compact summary containing only name, namespace, kind, and age when creation metadata is available. Namespace discovery returns exactly operation/resource/items/count/limited, with only name and optional age per item. It is a bounded snapshot: blacklist-denied namespaces are silently filtered, while label-selector mode sends the configured selector server-side on every page. Filtered entries alone do not make the snapshot limited. Every fetched namespace is identity-validated, including filtered and output-omitted objects. GET responses remain detailed. Response size, page count, item count, continuation-token, upstream-body, and timeout bounds apply to both LIST paths.

## Defence in depth

A request must pass all applicable controls:

1. ASP.NET Core authentication and authorization.
2. Explicit resource mapping policy.
3. Namespace blacklist or label-selector policy.
4. GET/LIST-only application behavior.
5. Kubernetes RBAC for the service identity.
6. Kubernetes deadlines, pagination bounds, upstream body limits, and safe-output limits.
7. When explicitly enabled, a fail-closed Clef credential decision gate before release of detailed GET results.

The production reference deployment uses a static bearer API key loaded from a Kubernetes Secret. Unauthenticated mode is accepted only when the host environment is `Development`. See [configuration](configuration.md#authentication).

## Secret handling

Raw Kubernetes Secret values are never returned:

- LIST uses a dedicated safe summary with the Secret name, type, key names, and age; it returns neither values nor fingerprints.
- GET replaces each value with a keyed HMAC-SHA256 fingerprint.

The HMAC key remains on the server. Keep it stable only when fingerprints need to be comparable across restarts. Logs and audit records never contain Secret values or fingerprints.

## Optional credential decision gate

The optional gate is disabled by default and applies only to detailed namespaced `k8s_get` GET results (`name` is present), for every mapped resource type. Namespaced LIST and namespace discovery bypass it. The input is exactly the bounded, post-sanitization JSON from the Kubernetes reader, so raw Secret values never reach Clef; sanitized Secret GET fingerprints are still evaluated. The application adds no regex, YAML, or PII scanner, and the gate does not add a tool or expand Kubernetes access.

JSON is flattened into complete bounded states with JSON Pointer paths. The credential-classification unit is one scalar Kubernetes field value, or the overlapping segments of one oversized scalar—not arbitrary reconstruction across independent fields. Every scalar carries available nearest and ancestor `name` identity context (for example, an environment-variable name beside its value), including ordinary values and every oversized segment; required identity context that cannot fit fails closed. Adjacent entries are also packed together and one entry overlaps each state boundary as pairwise structural defense, but the service does not claim to detect a credential intentionally fragmented across three or more fields. Strings split at rune boundaries with overlap, and every source scalar is covered. Every state is evaluated sequentially. Detection, malformed input, incomplete chunking, timeout, transport/HTTP failure, or invalid Clef output blocks the whole result with the same fixed client-safe message. Redirects and cookies are disabled, responses are bounded, and only transport/per-attempt timeouts plus HTTP 408, 429, or 500–599 are retried within one total deadline. Caller and server cancellation still propagate normally; expiration of the gate-owned deadline blocks safely.

Clef receives only `{model,state,questions}` with one credential choice question. Release requires a strictly validated response, `choice=no`, and `probabilities.yes` at or below the configured threshold. The built-in policy treats state as untrusted, identifies reusable credentials, permits HMAC-SHA256 fingerprints/placeholders/unresolved Secret references, and excludes PII-only concerns. The payload, API key, policy prompt, response, probabilities, and arbitrary errors are never logged. Readiness remains a process-only check and performs no Clef network probe.

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

Overall server deadlines use `server_timeout`; caller disconnects use `client_cancelled`. Credential detection and gate unavailability use distinct low-cardinality internal audit categories but the same fixed MCP message. Upstream response bodies and arbitrary exception messages do not cross the Kubernetes or credential-gate boundaries.

## Audit guarantees

Every dispatched `k8s_get` or `k8s_list_namespaces` call writes a sanitized structured Kubernetes audit event through the standard `ILogger` pipeline. Application-owned authorization denials write a coordinate-free MCP access-denial event. Authentication failures are handled by ASP.NET Core and infrastructure access logging. Middleware does not inspect arbitrary request bodies to infer audit fields.

Records can include:

- UTC timestamp
- client identity (`static-api-key` or Development-only `anonymous`)
- authentication mode
- operation and resource coordinates for dispatched tool calls
- result and fixed error category
- duration and request ID
- successful object count
- fixed credential-gate category (`credential_detected` or `credential_gate_unavailable`) when a detailed GET is blocked

They do not include Kubernetes response bodies, Secret values or fingerprints, credentials, tokens, arbitrary exception text, client IP addresses, or forwarded-header values. Untrusted string fields are length-bounded and have control characters replaced.

Already-sanitized events are written directly through the dedicated `ILogger<AuditLogger>` category and standard logging providers. Logging is best effort and cannot replace the original tool result or error. Deployments that require durable, tamper-resistant retention must configure that guarantee in their logging infrastructure. API-key clients are identified as `static-api-key`; unauthenticated development clients are identified as `anonymous` without recording bearer credentials.

## RBAC

The default ClusterRole grants narrow GET/LIST access for the default built-in resource set and namespace LIST for policy evaluation and namespace discovery. Optional CRDs require explicit, coordinated application mappings and narrow RBAC changes; wildcard reads are not supported. Helm [CRD preset flags](../charts/kube-mcp/README.md#optional-crds) render both gates for selected namespaced families, while the non-Helm [resource overlays](../overlays/README.md) remain separate. Detailed CRD GETs may include sensitive spec/status fields; review each enabled family. See the [deployment guide](deployment.md#resource-access-and-rbac).
