# Optional Clef credential decision gate

The credential gate is an optional, fail-closed release check for detailed Kubernetes GET results. It is disabled by default. It does not authorize additional reads, expose another MCP tool, or replace resource policy, namespace policy, Kubernetes RBAC, or Secret sanitization.

## Covered path

The gate runs only for `k8s_get(resource, namespace, name)` when `name` is non-null, across every configured resource type. It receives the exact bounded JSON produced by `IKubernetesReader`. For Secret GET, this is the already-sanitized representation containing HMAC-SHA256 fingerprints, never raw Secret values. Namespaced LIST and `k8s_list_namespaces` results bypass the gate.

This deliberately narrow gate classifies reusable credentials only. Existing Secret sanitization remains the only deterministic scan. There is no regex/YAML scanner and no PII classifier. The committed prompt treats state as untrusted data, asks about reusable credential material, and explicitly permits HMAC-SHA256 fingerprints, placeholders, unresolved `secretKeyRef` metadata, and PII that is not itself a credential.

## Clef request and response

Each request is a native HTTP POST to the configured absolute HTTP/HTTPS `/systemone` endpoint. Redirects are disabled. An empty API key sends no `Authorization` header; a nonempty key sends it as a bearer credential. The body has exactly the application request model, one state chunk, and one credentials question:

```json
{"model":"decision","state":{"entries":[{"path":"/spec/template/spec/containers/0/env/0/name","value":"API_KEY"},{"path":"/spec/template/spec/containers/0/env/0/value","value":"..."}]},"questions":{"credentials":{"type":"choice","instructions":"...","criteria":{"yes":"...","no":"..."}}}}
```

A response clears a chunk only when all of these hold:

- root, answer, probability, and usage objects contain exactly their documented case-sensitive members, with no unknown or duplicate fields;
- `model` exactly matches the configured expected physical model (case-sensitive);
- `answers` contains exactly the `credentials` answer;
- its type is `choice`, and choice is exactly `yes` or `no`;
- probabilities contain exactly finite `yes` and `no` values in `[0,1]`, sum within `0.000001` of one, have a unique argmax, and agree with choice;
- confidence is finite and in `[0,1]`;
- usage has a positive integer `input_tokens` no greater than configured `MaxInputTokens`, and integer `output_tokens` equal to zero; and
- choice is `no` and `probabilities.yes` is at or below the configured release threshold.

The threshold is required when enabled, must be finite in `[0,0.5)`, and deliberately has no production default. The `0.20` value in the configuration example is experimental and must be validated against representative private holdout data.

## Complete bounded coverage

Input must be valid JSON. Source leaves are emitted as entries with RFC 6901 JSON Pointer paths. The credential-classification unit is a single scalar Kubernetes field value, including the overlapping segments of one oversized scalar. Every scalar entry carries available nearest and ancestor `name` identity context; this applies to ordinary values and every oversized segment, and required identity context that cannot fit blocks the result. Optional sibling context is omitted when it would crowd out a complete value or the overlap and forward-progress capacity needed by an oversized value, including when later segments need more JSON escaping. Ordinary values that fit do not need to reserve segment metadata. Adjacent structural entries are also greedily packed together and one complete entry overlaps every state boundary as pairwise defense across siblings and array items. This does not promise reconstruction or detection of a credential intentionally fragmented across three or more independent fields. Oversized strings split only at Unicode rune boundaries and include source offsets plus configured byte overlap. Every source scalar is covered and each serialized state is at most `ChunkSizeBytes` UTF-8 bytes. Chunking is lazy and cancellation-aware. Binary-search trials are capped by the state byte bound rather than the entire remaining string, avoiding repeated copies proportional to the remaining input. Overlap may consume at most one quarter of a state; insufficient forward progress, malformed JSON, unsafe identity-context loss, or incomplete scalar coverage blocks the result.

Evaluation is sequential. The 15-second default is one total deadline for chunking, requests, retry delays, and all states—not 15 seconds per state. Each attempt also has a configurable 5-second default deadline, no greater than the total. Transport failures, per-attempt timeouts, and HTTP 408, 429, and 500–599 may be retried up to the configured `0`–`2` times with 100 ms and 300 ms backoffs. Other statuses, invalid schemas, and model mismatches are not retried. Clef response bodies are bounded even when length is unknown. Redirects and cookies are disabled. The directly owned HTTP client uses bounded connection lifetime and avoids HttpClientFactory request logging. There is no application semaphore or startup/readiness network probe.

When enabled, `OverallMcpRequestTimeoutSeconds` must be strictly greater than `KubernetesRequestTimeoutSeconds + CredentialGate:TotalTimeoutSeconds`. Caller disconnect and server cancellation continue to propagate. A gate-owned timeout blocks safely.

## Failure and audit boundary

A model detection and every operational, validation, timeout, or chunking failure block the whole result with one fixed safe MCP message. Audit records may distinguish `credential_detected` from `credential_gate_unavailable`, but remain low-cardinality. The application never logs or returns the payload, Secret fingerprint, API key, policy prompt, Clef response, probabilities, response bodies, or arbitrary exception text.

Configuration and an environment-variable example are in [configuration.md](configuration.md#optional-clef-credential-gate). Supply private endpoints and keys through deployment configuration and secret management; do not commit them.
