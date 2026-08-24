# Resource and RBAC overlays

The default deployment grants access only to **core** built-in Kubernetes
resources (pods, services, workloads, jobs, ingresses, and so on). Optional
CloudNativePG and Traefik CRDs are **not** included in the default allowlist or
the default `ClusterRole`, following the spec principle that a resource is not
exposed merely because it exists. This keeps the default surface small and
prevents drift between the application allowlist and Kubernetes RBAC.

Enable an optional CRD family only when an actual troubleshooting requirement
exists. Each overlay is purely additive and requires **two** coordinated changes:

1. **Application allowlist** — add the CRD resource mappings to the kube-mcp
   configuration so the MCP tool can resolve them. The `resources.json` file in
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

Configuration uses standard ASP.NET Core configuration. The simplest options are
environment variables or a mounted appsettings file.

### Environment variables

```sh
# CloudNativePG clusters CRD as an example
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Group=postgresql.cnpg.io \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Version=v1 \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Resource=clusters \
  KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Kind=Cluster
```

Repeat for each CRD in the chosen `resources.json`. The keys are the full
`<resource>.<group>` names from the JSON.

### Mounted appsettings overlay

Merge the desired `resources.json` into a `ConfigMap`, mount it as
`appsettings.Production.json` (the container runs in the Production environment
by default, so this file merges on top of the core `appsettings.json`), and
restart the deployment:

```sh
kubectl create configmap kube-mcp-overrides --namespace kube-mcp \
  --from-file=appsettings.Production.json=overlays/cnpg/resources.json \
  --dry-run=client -o yaml | kubectl apply -f -
# Mount the ConfigMap at /app/appsettings.Production.json and reapply.
```

Then apply the corresponding RBAC:

```sh
kubectl apply --filename overlays/cnpg/rbac.yaml
```

## Removing an overlay

Delete the overlay RBAC and remove the corresponding application mappings
(unset the environment variables or remove the appsettings overlay), then
reapply `deployment.yaml`:

```sh
kubectl delete clusterrole kube-mcp-reader-cnpg
kubectl delete clusterrolebinding kube-mcp-reader-cnpg
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Group-' \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Version-' \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Resource-' \
  'KubeMcp__AllowedResources__clusters.postgresql.cnpg.io__Kind-'
```
