---
name: kube-mcp-security-review
description: Reviews kube-mcp changes against its read-only security model and identifies required tests and documentation. Use when changing MCP tools, authentication, authorization, Kubernetes access, Secrets, errors, audit, telemetry, limits, middleware, configuration, deployment, or RBAC.
---

# kube-mcp security review

Read [AGENTS.md](../../../AGENTS.md) and the [security model](../../../docs/security.md), then inspect the complete diff. Resolve the repository root with `git rev-parse --show-toplevel`; paths below are relative to that root.

## Review boundaries

Confirm that the change preserves:

- exactly one namespaced GET/LIST MCP tool;
- no mutation, watch, exec, proxy, shell, tunnelling, or credential exposure;
- resource policy, namespace policy, and Kubernetes RBAC as independent gates;
- sanitization of Secret LIST and keyed HMAC fingerprinting of Secret GET;
- fail-closed production authentication and explicit development-only unauthenticated use;
- bounded request/upstream/response sizes, pagination, timeouts, admission, and concurrency;
- fixed safe errors and low-cardinality telemetry;
- audit/telemetry exclusion of bodies, credentials, tokens, fingerprints, and arbitrary exception text;
- trusted-proxy and host filtering without trust-all networks.

Trace untrusted data from HTTP/MCP input through Kubernetes calls and back through responses, logs, audit, and telemetry. Treat upstream Kubernetes error bodies and exception messages as sensitive.

## Cross-file consistency

For configuration changes, check options, validation, defaults, manifests, tests, and the [configuration reference](../../../docs/configuration.md).

For resource changes, check both application mappings and RBAC. Optional CRDs belong in coordinated `overlays/` files rather than the default surface unless deliberately approved.

For middleware changes, verify ordering around forwarded headers, admission, authentication/authorization, observability, timeout, body limits, audit, and MCP dispatch.

## Tests

Require regression tests at each changed boundary. Relevant suites include authentication options, access policy, Kubernetes reader boundaries, Secret sanitization, admission/concurrency, audit, telemetry, reverse proxies, readiness, endpoints, and production deployment tests.

Finish with the `kube-mcp-validation` workflow. Report concrete findings first; do not claim security from test success alone.
