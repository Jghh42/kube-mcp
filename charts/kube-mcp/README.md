# kube-mcp Helm chart

This proof-of-concept chart packages the same authenticated, read-only deployment contract as [`deployment.yaml`](../../deployment.yaml). It deliberately does not create credentials or an Ingress.

## Install

Create the namespace and the API-key and HMAC Secrets as described in the [deployment guide](../../docs/deployment.md), then install a published release:

```sh
helm upgrade --install kube-mcp \
  oci://ghcr.io/jghh42/charts/kube-mcp \
  --version <chart-version> \
  --namespace kube-mcp \
  --create-namespace \
  --set-string image.digest='sha256:<published-image-digest>' \
  --set-json 'allowedHosts=["k-mcp.example.internal"]'
```

For local chart development, replace the OCI reference and `--version` with `charts/kube-mcp`. A newly published GHCR package may initially be private; run `helm registry login ghcr.io` with package read access until its visibility is changed.

The default Secret references are `kube-mcp-api-key/api-key` and `kube-mcp-hmac/key`. Override their names or keys without putting secret material in Helm values:

```yaml
authentication:
  apiKeySecret:
    name: my-api-key-secret
    key: api-key
secretHmacKeySecret:
  name: my-hmac-secret
  key: key
```

The chart derives the Service DNS entries in `AllowedHosts` from the Helm release name and namespace and appends `allowedHosts`. A SHA-256 `image.digest` is required outside Development. Development may use the `latest` tag for parity with the local proof-of-concept workflow.

`authentication.mode=None` is rejected unless `dotnetEnvironment=Development` and `service.type=ClusterIP`. Never expose that combination outside an isolated development cluster.

RBAC creation can be disabled with `rbac.create=false` when equivalent externally managed RBAC already exists. If `serviceAccount.create=false`, `serviceAccount.name` is mandatory; the chart never grants its ClusterRole to the shared `default` ServiceAccount implicitly. The built-in chart RBAC is intentionally fixed. Optional CRDs still require coordinated application mappings and additive read-only RBAC; see [`overlays/README.md`](../../overlays/README.md).

The Service defaults to `ClusterIP`. Edge request limits, TLS, traffic policy, and prevention of untrusted direct access remain the responsibility of a private ingress, load balancer, or service mesh.

## Validate

```sh
tests/helm/run.sh
# Requires Docker; pushes only to an ephemeral loopback OCI registry.
tests/helm/push-oci.sh
```
