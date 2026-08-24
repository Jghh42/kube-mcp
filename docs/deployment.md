# Deployment guide

## Production checklist

The reference [`deployment.yaml`](../deployment.yaml) is an authenticated production deployment. Before applying it:

1. Replace the example OAuth authority, audience, scopes, and roles.
2. Replace `k-mcp.example.internal` in `AllowedHosts` with the deployment hostname.
3. Pin the image to an immutable `sha-<commit>` tag.
4. Confirm the GHCR package is public or configure an image pull secret.
5. Review the resource allowlist, namespace policy, RBAC, and trusted proxy settings.
6. Provide secrets through your normal secret-management system; do not commit them.

Missing or invalid production authentication configuration prevents startup rather than exposing `/mcp`.

## Install

Create the namespace and a stable server-held HMAC key. Keep the key stable when Secret fingerprints must remain comparable across restarts.

```sh
kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic kube-mcp-hmac \
  --namespace kube-mcp \
  --from-literal="key=$(openssl rand -base64 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Deploy and wait for readiness:

```sh
kubectl apply --filename deployment.yaml
kubectl rollout status deployment/kube-mcp --namespace kube-mcp
```

Access the service locally:

```sh
kubectl port-forward --namespace kube-mcp service/kube-mcp 8080:80
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

The MCP endpoint is `http://127.0.0.1:8080/mcp` through this port-forward. Use TLS for non-local traffic, normally terminated by a trusted ingress, reverse proxy, or service mesh.

## Local unauthenticated deployment

For an isolated local cluster only, apply the explicitly named development overlay after the reference manifest:

```sh
kubectl apply --filename deployment.yaml
kubectl apply --filename deployment-development.yaml
```

The overlay selects `Authentication:Mode=None` and enables the required non-production opt-in. Never expose it on a shared or production network. Reapply `deployment.yaml` to restore authenticated mode.

## Health and readiness

The root, liveness, and readiness endpoints are public in every authentication mode. Readiness performs an opaque, two-second Kubernetes authorization probe. Concurrent callers share one probe and its result is cached for one second.

By default, readiness asks a cluster-wide authorization question. Set `KubeMcp:ReadinessNamespace` to a representative policy-allowed namespace when namespaced RoleBinding access should be checked instead. Label-selector namespace mode also verifies permission to list namespaces.

## Resource access and RBAC

The default `ClusterRole` grants only `get` and `list` for the built-in resource allowlist. It also grants namespace `list` so label-selector namespace policy can be evaluated. It does not grant mutation, watch, exec, proxy, wildcard resources, or optional CRDs.

Application policy and Kubernetes RBAC are independent; both must allow a request. Optional CloudNativePG and Traefik mappings have coordinated [resource and RBAC overlays](../overlays/README.md).

To permit every discoverable namespaced GET/LIST resource, both of these deliberate changes are required:

```text
KubeMcp__ResourcePolicy__Mode=AllowAll
```

```sh
kubectl apply --filename deployment-allow-all-rbac.yaml
```

This grants broad cluster-wide read access. Namespace policy, GET/LIST-only behavior, Secret sanitization, and response limits still apply. Reapply `deployment.yaml` to restore narrow RBAC.

## Container image availability

A newly created GHCR package is private by default. After its first publish, change its visibility to public in GitHub package settings if clusters should pull it without an image pull secret.
