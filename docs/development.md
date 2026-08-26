# Development, testing, and releases

## Prerequisites

- .NET 10 SDK
- Docker
- kind
- kubectl
- Helm 3 for chart validation
- curl, Python 3, and OpenSSL for the kind harness

## Build and test

```sh
dotnet restore KubeMcp.slnx --locked-mode
dotnet build KubeMcp.slnx --configuration Release --no-restore
dotnet test KubeMcp.slnx --configuration Release --no-build --no-restore
```

The test suite covers access policy, authentication, Secret sanitization and fingerprinting, generic compact LIST summaries, policy-filtered namespace discovery, upstream and safe-output boundaries, pagination, cancellation, timeouts, process health, structured audit logging, production deployment settings, and the exact two-tool MCP surface.

Validate the proof-of-concept Helm chart separately:

```sh
tests/helm/run.sh
```

## End-to-end tests with kind

```sh
./tests/integration/run-kind.sh
```

The harness owns a new disposable kind cluster for each run. Locally it builds and loads `kube-mcp:integration`; CI supplies the same already-built local image that it scans, SBOMs, and publishes after the harness succeeds. The cluster is deleted on success or failure, so no ambient cluster resources are reused or restored.

The harness creates ephemeral HMAC and API keys, loads the API key through a Kubernetes Secret, and checks:

- missing, malformed, incorrect, and correct API-key credentials
- exactly two exposed MCP tools (`k8s_get` and argument-free `k8s_list_namespaces`)
- ordinary detailed GET and generic compact LIST responses
- Secret LIST key-name sanitization and GET fingerprinting
- absence of raw Secret data in responses and application logs
- application resource-policy and Kubernetes RBAC denials
- blacklist and label-selector namespace discovery, including newly created, labelled, unlabelled, and default-denied namespaces
- the exact namespace snapshot envelope and name/optional-age projection without metadata leakage
- aggregate namespace discovery audit coordinates and counts without namespace names
- namespace LIST-only service-account RBAC, plus independent later policy and RBAC denials
- explicit built-in resource mappings
- practical upstream-body and safe-output size boundaries

## Continuous integration

[`.github/workflows/container.yml`](../.github/workflows/container.yml) validates the Helm chart alongside the application on every run. Pull requests run locked restore/build/test, chart validation, NuGet scanning, and the container/kind/vulnerability gate with a read-only token. Trusted pushes run that same application gate followed by one container build that runs in disposable kind, is scanned and SBOMed, and is then published. GitHub provenance and SBOM attestations accompany published images. Release tags publish the chart only after the container job succeeds.

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

## Helm chart publishing

A release tag such as `v1.2.3` packages the chart as version `1.2.3`, sets its application version to `1.2.3`, and publishes it only after the tested container pipeline succeeds:

```text
ghcr.io/jghh42/charts/kube-mcp:1.2.3
```

The workflow derives the package version from the release tag with `helm package --version`; it does not create version-bump commits. Release versions are required to use lowercase SemVer characters. Publications targeting the same version share a non-cancelling concurrency group, while different versions can proceed independently. Publication fails closed unless the registry explicitly reports the requested version as absent. GHCR tags can still be changed by credentials outside this workflow, so restrict package write access accordingly. Helm represents SemVer build metadata separators (`+`) as underscores in OCI tags.

Every CI run packages the chart and exercises `helm push` against an ephemeral unauthenticated registry bound to the runner loopback interface. Main-branch and release-tag pushes can publish container images, but only release tags publish Helm charts externally.
