# ADR 0001: Policy-filtered namespace discovery

- Status: Accepted
- Date: 2026-08-25

## Context

Namespaced reads require clients to know a namespace, while the service previously offered no safe way to discover names admitted by its namespace policy. Adding namespaces to the generic resource mapping would make a cluster-scoped resource available through a path designed for namespaced GET/LIST and could enable Namespace GET or caller-controlled query behavior.

## Decision

Expose a second fixed, argument-free `k8s_list_namespaces()` tool. It performs only paginated core-v1 Namespace LIST requests through the existing bounded Kubernetes adapter and reader path. It applies blacklist filtering locally or the configured label selector server-side on every page. It validates every fetched object before filtering or output omission and projects only name and optional age into a fixed bounded snapshot envelope.

Namespace discovery is independent of `AllowedResources`. Existing authentication, Kubernetes RBAC, pagination, body/output, continuation-token, timeout, safe-error, cancellation, and aggregate-audit behavior applies. `k8s_get` remains namespaced-only and rechecks namespace policy and RBAC for every later read.

## Consequences

Authorized clients can learn eligible namespace names and approximate ages. They cannot request Namespace GET, watch, mutation, arbitrary selectors, caller continuation tokens, or generic cluster-scoped resources. Blacklist mode intentionally reveals newly created non-denied namespaces. Label-selector mode delegates matching to Kubernetes while keeping the selector server-controlled and undisclosed in output and audit records.

The service account requires core Namespace `list`, which the reference deployment already grants. Namespace LIST is now required in both namespace-policy modes rather than only for label-selector evaluation.
