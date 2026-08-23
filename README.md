# kube-mcp

Tiny read-only Kubernetes MCP service. Stage 1 provides the .NET 10 ASP.NET Core
service shell, container image, health endpoints, and a kind-compatible Kubernetes
deployment with read-only service-account RBAC.

## Prerequisites

- .NET 10 SDK
- Docker
- kind
- kubectl

## Build and test

```sh
dotnet restore
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build
```

## Build and deploy to kind

```sh
docker build --tag kube-mcp:stage1 .
kind load docker-image kube-mcp:stage1 --name kind
kubectl apply --filename deployment.yaml
kubectl rollout status deployment/kube-mcp --namespace kube-mcp
```

Access the service locally:

```sh
kubectl port-forward --namespace kube-mcp service/kube-mcp 8080:80
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/healthz
```

The stage 1 `ClusterRole` deliberately allows `get` and `list` on all Kubernetes
resource types, as requested in `stages.md`. It grants no mutation verbs.
