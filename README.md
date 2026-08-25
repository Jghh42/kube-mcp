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
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build --no-restore
```

### Deploy

The reference manifest is production-oriented and requires API-key/HMAC Secrets and deployment-specific host settings.

```sh
kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic kube-mcp-hmac \
  --namespace kube-mcp \
  --from-literal="key=$(openssl rand -base64 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic kube-mcp-api-key \
  --namespace kube-mcp \
  --from-literal="api-key=$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply --filename deployment.yaml
kubectl rollout status deployment/kube-mcp --namespace kube-mcp
kubectl port-forward --namespace kube-mcp service/kube-mcp 8080:80
```

Endpoints:

- MCP: `http://127.0.0.1:8080/mcp`
- Liveness: `http://127.0.0.1:8080/healthz`
- Readiness: `http://127.0.0.1:8080/readyz`

Use an immutable `ghcr.io/jghh42/kube-mcp:sha-<commit>` image tag for repeatable deployments. The unauthenticated [`deployment-development.yaml`](deployment-development.yaml) overlay is for isolated local clusters only.

## Documentation

- [Deployment guide](docs/deployment.md)
- [Configuration reference](docs/configuration.md)
- [Security model](docs/security.md)
- [Observability and audit logging](docs/observability.md)
- [Development, testing, and releases](docs/development.md)
- [Optional resource and RBAC overlays](overlays/README.md)

## Container image

Published images are available from `ghcr.io/jghh42/kube-mcp`. See the [development and release documentation](docs/development.md#container-publishing) for tags and publishing behavior.
