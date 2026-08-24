# Development, testing, and releases

## Prerequisites

- .NET 10 SDK
- Docker
- kind
- kubectl
- curl and Python 3 for the kind OAuth harness
- OpenSSL for generating development HMAC keys

## Build and test

```sh
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore
dotnet test --configuration Release --no-build --no-restore
```

The test suite covers access policy, authentication, Secret sanitization and fingerprinting, compact LIST summaries, response boundaries, concurrency, readiness, reverse proxies, audit sinks, telemetry, production deployment settings, and the single-tool MCP surface.

## End-to-end tests with kind

```sh
./tests/integration/run-kind.sh
```

For local runs, the harness builds and loads a test image. In CI, it receives the same content-addressed image archive that is later scanned, SBOMed, and published, without rebuilding it.

The harness creates an ephemeral HMAC key and a one-pod Keycloak development server with an imported test realm. It uses the real OAuth `client_credentials` flow and checks:

- invalid client secrets
- audience, scope, and role enforcement
- compact LIST and detailed GET responses
- Secret sanitization
- resource and namespace denials
- both namespace-policy modes
- explicit resource `AllowAll` mode

Harness-owned namespaces are deleted afterward. Any pre-existing `kube-mcp-reader` ClusterRole and ClusterRoleBinding are restored from exact snapshots, or removed when they did not exist before the run.

Keycloak uses ephemeral H2 storage and fixed local-only test credentials from [`tests/integration/keycloak.yaml`](../tests/integration/keycloak.yaml). It is not a production deployment.

## Continuous integration

[`.github/workflows/container.yml`](../.github/workflows/container.yml) builds and tests pull requests targeting `main`. The workflow also performs container security and publishing steps for eligible pushes and tags.

## Container publishing

Successful pushes to the default branch publish:

```text
ghcr.io/jghh42/kube-mcp:latest
ghcr.io/jghh42/kube-mcp:main
ghcr.io/jghh42/kube-mcp:sha-<commit>
```

A tag such as `v1.2.3` publishes:

```text
v1.2.3
1.2.3
1.2
```

Release-tag builds do not create or move `latest`; only a successful push to the default branch does. Publishing uses the workflow's short-lived `GITHUB_TOKEN` and requires no repository secret.

A new GHCR package is private by default. Change its package visibility after the first publish if unauthenticated cluster pulls are required. Production deployments should use immutable `sha-<commit>` tags.
