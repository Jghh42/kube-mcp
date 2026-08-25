# Development, testing, and releases

## Prerequisites

- .NET 10 SDK
- Docker
- kind
- kubectl
- curl, Python 3, and OpenSSL for the kind harness

## Build and test

```sh
dotnet restore KubeMcp.slnx --locked-mode
dotnet build KubeMcp.slnx --configuration Release --no-restore
dotnet test KubeMcp.slnx --configuration Release --no-build --no-restore
```

The test suite covers access policy, authentication, Secret sanitization and fingerprinting, generic compact LIST summaries, upstream and safe-output boundaries, pagination, cancellation, timeouts, process health, structured audit logging, production deployment settings, and the single-tool MCP surface.

## End-to-end tests with kind

```sh
./tests/integration/run-kind.sh
```

The harness owns a new disposable kind cluster for each run. Locally it builds and loads `kube-mcp:integration`; CI supplies the same already-built local image that it scans, SBOMs, and publishes after the harness succeeds. The cluster is deleted on success or failure, so no ambient cluster resources are reused or restored.

The harness creates ephemeral HMAC and API keys, loads the API key through a Kubernetes Secret, and checks:

- missing, malformed, incorrect, and correct API-key credentials
- exactly one exposed MCP tool
- ordinary detailed GET and generic compact LIST responses
- Secret LIST key-name sanitization and GET fingerprinting
- absence of raw Secret data in responses and application logs
- application resource-policy and Kubernetes RBAC denials
- blacklist and label-selector namespace policy allow/deny behavior
- automatic access to a newly created eligible namespace
- explicit built-in resource mappings
- practical upstream-body and safe-output size boundaries

## Continuous integration

[`.github/workflows/container.yml`](../.github/workflows/container.yml) has two jobs. Pull requests run locked restore/build/test, NuGet scanning, and the container/kind/vulnerability gate with a read-only token. Trusted pushes run that same application gate followed by one container build that runs in disposable kind, is scanned and SBOMed, and is then published. GitHub provenance and SBOM attestations accompany published images.

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

Release-tag builds do not create or move `latest`; only a successful push to the default branch does. Publishing uses the workflow's short-lived `GITHUB_TOKEN` and requires no repository secret. Pull-request jobs remain read-only and never receive publication or attestation permissions.

A new GHCR package is private by default. Change its package visibility after the first publish if unauthenticated cluster pulls are required. The full `sha-<commit>` tag identifies the source revision but, like any registry tag, can technically be moved. Production deployments should pin the published `ghcr.io/jghh42/kube-mcp@sha256:<digest>` reference recorded by the workflow.
