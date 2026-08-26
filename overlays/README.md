# Resource and RBAC overlays

The default deployment grants access only to explicitly mapped built-in
Kubernetes resources (pods, services, workloads, jobs, ingresses, and so on).
Optional CloudNativePG and Traefik CRDs are **not** included in the default allowlist or
the default `ClusterRole`, following the spec principle that a resource is not
exposed merely because it exists. This keeps the default surface small and
prevents drift between the application allowlist and Kubernetes RBAC.

Enable an optional CRD family only when an actual troubleshooting requirement
exists. Each overlay is purely additive and requires **two** coordinated changes:

1. **Application allowlist** — add the CRD resource mappings to the kube-mcp
   configuration so `k8s_get` can resolve them. The `resources.json` file in
   each overlay contains the `KubeMcp:AllowedResources` mapping.

2. **Kubernetes RBAC** — apply the overlay's `rbac.yaml` so the kube-mcp
   service account can `get`/`list` those CRDs. Application allowlist and
   Kubernetes RBAC are independent; enabling only one does not grant access.

## Overlays

| Overlay | Application mappings | Kubernetes RBAC |
| --- | --- | --- |
| CloudNativePG | `cnpg/resources.json` | `cnpg/rbac.yaml` |
| Traefik | `traefik/resources.json` | `traefik/rbac.yaml` |

## Adding CRD mappings to the kube-mcp configuration

Use environment variables on the existing Deployment. For example, add the
CloudNativePG `clusters` mapping:

```sh
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Group=postgresql.cnpg.io \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Version=v1 \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Resource=clusters \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Kind=Cluster
```

Configure all four variables for every mapping in the selected
`resources.json`; its keys are the full `<resource>.<group>` names. Only after
all bundled mappings are configured, apply the matching RBAC file:

```sh
kubectl apply --filename overlays/cnpg/rbac.yaml
```

The final configuration must contain both sides. Application mapping alone is
still denied by RBAC, while RBAC alone does not expose an unmapped resource.

## Removing an overlay

First unset all four variables for every mapping enabled from that overlay. For
example, remove the CloudNativePG `clusters` mapping:

```sh
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Group-' \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Version-' \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Resource-' \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Kind-'
```

Repeat that command pattern for every other mapping from the overlay and wait
for the Deployment rollout. Only then remove the matching RBAC objects:

```sh
kubectl delete --filename overlays/cnpg/rbac.yaml
```
