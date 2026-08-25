# AGENTS.md

## Project

`kube-mcp` is a .NET 10 ASP.NET Core service exposing one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

The service is intentionally read-only, deny-by-default, and small. Start with [README.md](README.md); use the focused files under [docs/](docs/) for details.

## Non-negotiable behavior

- Keep a single MCP tool and namespaced GET/LIST operations only.
- Never expose Kubernetes credentials or raw Secret values. Secret GET values remain HMAC fingerprints; Secret LISTs remain sanitized.
- Preserve independent resource policy, namespace policy, and Kubernetes RBAC enforcement.
- Keep production authentication fail-closed. Unauthenticated mode is only for explicitly opted-in isolated development.
- Do not leak upstream bodies, credentials, tokens, fingerprints, resource bodies, or arbitrary exception text into errors, logs, audit records, or telemetry.
- Keep request, response, pagination, timeout, admission, and concurrency bounds intact unless a deliberate, tested change requires otherwise.
- Application resource mappings and Kubernetes RBAC must stay aligned, but neither may substitute for the other.

Read [docs/security.md](docs/security.md) before changing authentication, authorization, Kubernetes reads, Secret handling, errors, audit, telemetry, middleware ordering, or RBAC.

## Repository map

- `src/KubeMcp/` — application code and default settings
- `tests/KubeMcp.Tests/` — xUnit unit and in-process integration tests
- `tests/integration/` — disposable-kind end-to-end harness
- `deployment*.yaml` — production, development, and broad-RBAC manifests
- `overlays/` — optional CRD mappings and matching RBAC
- `.github/workflows/container.yml` — build, test, scan, and publish pipeline

Configuration belongs in `KubeMcpOptions`, its validator, settings/manifests, tests, and [docs/configuration.md](docs/configuration.md) as applicable.

## Validation

Run from the repository root:

```sh
dotnet restore KubeMcp.slnx --locked-mode
dotnet build KubeMcp.slnx --configuration Release --no-restore
dotnet test KubeMcp.slnx --configuration Release --no-build --no-restore
git diff --check
```

Use targeted tests while iterating, then run the full suite for code or manifest changes. Run `./tests/integration/run-kind.sh` for changes affecting the container, deployment, authentication, Kubernetes integration, or kind harness. See [docs/development.md](docs/development.md).

When dependencies change, refresh and commit both relevant `packages.lock.json` files, then verify a locked restore. Keep CI actions and Docker base images pinned; do not replace immutable pins with mutable tags.

## Change expectations

- Add or update tests for behavior changes and security boundaries.
- Keep error categories and telemetry labels low-cardinality and sanitized.
- Update focused documentation rather than expanding the README.
- Never commit keys, tokens, kubeconfigs, API keys, HMAC keys, or exporter credentials.
- Preserve unrelated working-tree changes.
