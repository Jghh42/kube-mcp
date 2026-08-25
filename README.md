# kube-mcp

A small, read-only Kubernetes [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) service built with .NET 10.

It exposes one Streamable HTTP tool:

```text
k8s_get(resource, namespace, name?)
```

- Omit `name` to list resources in a namespace.
- Supply `name` to get one resource.
- Kubernetes Secrets are sanitized; raw values are never returned.
- Resource policy, namespace policy, and Kubernetes RBAC independently restrict access.
- Production uses a static bearer API key loaded from a Kubernetes Secret.

## Quick start

### Requirements

- .NET 10 SDK
- Docker
- A Kubernetes cluster and `kubectl`
- OpenSSL

### Build and test

```sh
dotnet restore KubeMcp.slnx --locked-mode
dotnet build KubeMcp.slnx --configuration Release --no-restore
dotnet test KubeMcp.slnx --configuration Release --no-build --no-restore
```

### Deploy

The reference manifest is production-oriented and requires API-key/HMAC Secrets and deployment-specific host settings.

```sh
kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f -

# Preserve existing credentials on reruns; rotate them only deliberately.
if ! kubectl get secret kube-mcp-hmac --namespace kube-mcp >/dev/null 2>&1; then
  hmac_key=$(openssl rand -base64 32)
  # Store $hmac_key if Secret fingerprints must remain stable across recreation.
  printf '%s' "$hmac_key" | kubectl create secret generic kube-mcp-hmac \
    --namespace kube-mcp \
    --from-file=key=/dev/stdin
fi

if ! kubectl get secret kube-mcp-api-key --namespace kube-mcp >/dev/null 2>&1; then
  api_key=$(openssl rand -hex 32)
  # Store $api_key in your secret manager now; clients use this same value.
  printf '%s' "$api_key" | kubectl create secret generic kube-mcp-api-key \
    --namespace kube-mcp \
    --from-file=api-key=/dev/stdin
fi

# Before applying, replace the image in deployment.yaml with the published
# ghcr.io/jghh42/kube-mcp@sha256:<digest> reference and replace
# k-mcp.example.internal in AllowedHosts with your internal application host.
kubectl apply --filename deployment.yaml
kubectl rollout status deployment/kube-mcp --namespace kube-mcp
kubectl port-forward --namespace kube-mcp service/kube-mcp 8080:80
```

Endpoints:

- MCP: `http://127.0.0.1:8080/mcp`
- Liveness: `http://127.0.0.1:8080/healthz`
- Readiness: `http://127.0.0.1:8080/readyz`

Full-revision `sha-<commit>` image tags are useful for traceability but, like all tags, can be moved. The unauthenticated [`overlays/development`](overlays/development/) Kustomize overlay is for isolated local clusters only.

## Documentation

- [Deployment guide](docs/deployment.md)
- [Configuration reference](docs/configuration.md)
- [Security model](docs/security.md)
- [Development, testing, and releases](docs/development.md)
- [Optional resource and RBAC overlays](overlays/README.md)

## Container image

Published images are available from `ghcr.io/jghh42/kube-mcp`. See the [development and release documentation](docs/development.md#container-publishing) for tags and publishing behavior.
