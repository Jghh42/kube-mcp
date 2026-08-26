# Domain context

## MCP surface

`kube-mcp` exposes exactly two fixed read-only tools:

- `k8s_get(resource, namespace, name?)` performs only namespaced Kubernetes GET/LIST operations for explicitly mapped resources.
- `k8s_list_namespaces()` performs only a core-v1 Namespace LIST and takes no arguments.

Namespace discovery is the sole cluster-scoped operation. It is independent of `AllowedResources`; `namespaces` is not a resource mapping and cannot be read through `k8s_get`.

## Namespace disclosure

Namespace discovery returns a bounded point-in-time snapshot of namespaces admitted by the configured namespace policy. Blacklist mode silently omits denied namespaces and automatically discovers newly created non-denied namespaces. Label-selector mode sends the configured selector to Kubernetes on every continuation page. A later `k8s_get` still re-enforces namespace policy and Kubernetes RBAC independently.

The discovery envelope contains exactly `operation`, `resource`, `items`, `count`, and `limited`. Each item contains a namespace `name` and an optional computed `age`; Kubernetes labels, annotations, status, identifiers, resource versions, managed fields, selectors, and continuation tokens are not disclosed. Existing item, page, body, output, continuation-token, and timeout bounds apply. `limited` means eligible output may have been omitted because a bound was reached; policy-filtered entries alone do not set it.

Every fetched Namespace identity is validated before filtering or output omission. Failures use the same fixed Kubernetes errors and aggregate sanitized auditing as namespaced reads.

## Security boundaries

Production authentication remains fail-closed. Resource policy, namespace policy, and Kubernetes RBAC remain independent controls. Namespace LIST RBAC supports both policy evaluation and the intentional discovery tool, but does not permit Namespace GET, watch, or mutation.

See [ADR 0001](docs/adr/0001-policy-filtered-namespace-discovery.md) for the decision record.
