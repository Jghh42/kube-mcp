# Deployment guide

## Production checklist

The reference [`deployment.yaml`](../deployment.yaml) is an authenticated production deployment. Before applying it:

1. Create the API-key and HMAC Kubernetes Secrets described below.
2. Replace `k-mcp.example.internal` in `AllowedHosts` with the internal hostname presented to the application.
3. Pin the image to its published immutable `ghcr.io/jghh42/kube-mcp@sha256:<digest>` reference; use the full-revision `sha-<commit>` tag only to locate that digest.
4. Confirm the GHCR package is public or configure an image pull secret.
5. Review the resource allowlist, namespace policy, RBAC, and standard ASP.NET Core host filtering.
6. Configure the private-network ingress, load balancer, or service mesh to enforce HTTP request-body, header, rate, and concurrency limits, own originating-client IP/external scheme/external host logging, and block untrusted direct Service access where required.
7. Provide secrets through your normal secret-management system; do not commit them.

Missing or invalid production authentication configuration prevents startup rather than exposing `/mcp`.

## Install

Create the namespace and a stable server-held HMAC key. Keep the key stable when Secret fingerprints must remain comparable across restarts.

```sh
kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f -
hmac_key=$(openssl rand -base64 32)
# Store $hmac_key if Secret fingerprints must remain stable across recreation.
kubectl create secret generic kube-mcp-hmac \
  --namespace kube-mcp \
  --from-literal="key=$hmac_key" \
  --dry-run=client -o yaml | kubectl apply -f -

api_key=$(openssl rand -hex 32)
# Store $api_key in your secret manager now; clients must use this same value.
kubectl create secret generic kube-mcp-api-key \
  --namespace kube-mcp \
  --from-literal="api-key=$api_key" \
  --dry-run=client -o yaml | kubectl apply -f -
```

The shell variables are only a convenient handoff during setup. Retain the API key in your secret manager and configure MCP clients with that same bearer value. Retain the HMAC key too when fingerprints must survive Secret recreation. Do not print either value into logs or commit it.

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

## Private-network edge contract

The application Service is intended to remain private. Its ingress, load balancer, or service mesh owns HTTP request-body and header limits, request rate and concurrency limits, originating-client IP, external scheme and host logging, and prevention of untrusted direct access where required. Choose limits for the expected MCP client workload and enforce them before requests reach the pod; the application has no admission, request-body, concurrency, or forwarded-header middleware.

The application still bounds Kubernetes upstream bodies, safe MCP output, list items/pages, continuation tokens, and operation deadlines. The deployment retains pod CPU and memory requests and limits because those controls cannot be delegated to HTTP infrastructure.

## Local unauthenticated deployment

For an isolated local cluster only, first create the namespace and HMAC Secret from the install steps above; the API-key Secret is not needed. Then render and apply the development Kustomize overlay:

```sh
kubectl kustomize --load-restrictor LoadRestrictionsNone overlays/development \
  | kubectl apply --filename -
```

The load-restrictor option is needed because the overlay reuses the repository-root production manifest. It changes only the environment, authentication mode, and local image pull behavior: `Development`, `Authentication:Mode=None`, and `IfNotPresent`. The production API-key environment entry is deleted; the HMAC Secret reference and all RBAC, probes, hardening, resources, and `ClusterIP` exposure are inherited unchanged. `None` is rejected in every other environment. Never expose this overlay on a shared or production network. To restore production mode, create the API-key Secret, configure the image digest and `AllowedHosts` as required by the production checklist, and then reapply `deployment.yaml`.

## Health and readiness

The root, `/healthz`, and `/readyz` endpoints are public in every authentication mode. Both probe endpoints return small fixed responses and report only that the process started successfully; they do not contact Kubernetes or expose configuration and exception details.

Startup option validation remains fail-closed, including production authentication validation. Kubernetes authorization and connectivity failures are handled through fixed safe errors when an MCP request performs a read. The deployment retains separate liveness and readiness probes for platform compatibility, but both have process-only semantics.

## Resource access and RBAC

The default `ClusterRole` grants only `get` and `list` for the built-in resource allowlist. It also grants namespace `list` so label-selector namespace policy can be evaluated. It does not grant mutation, watch, exec, proxy, wildcard resources, or optional CRDs.

Application policy and Kubernetes RBAC are independent; both must allow a request. There is no wildcard application mode or wildcard RBAC manifest. Optional CloudNativePG and Traefik mappings have coordinated [resource and RBAC overlays](../overlays/README.md); each overlay must add both the explicit mapping and matching narrow read-only RBAC.

## Container image availability

A newly created GHCR package is private by default. After its first publish, change its visibility to public in GitHub package settings if clusters should pull it without an image pull secret.
