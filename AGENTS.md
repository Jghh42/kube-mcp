# AGENTS.md

## Project

`kube-mcp` is a .NET 10 ASP.NET Core service exposing one Streamable HTTP MCP tool:

```text
k8s_get(resource, namespace, name?)
```

The service is intentionally read-only, deny-by-default, and small. Start with [README.md](README.md); use the focused files under [docs/](docs/) for details.

## Simplicity mandate

- Prefer the smallest direct implementation that preserves the documented security boundary.
- Do not add tools, authentication modes, abstraction layers, queues, caches, background services, custom middleware, configuration switches, deployment variants, or dependencies unless a concrete requirement needs them and the user explicitly approves the added complexity.
- Extend existing code paths before creating parallel mechanisms. Remove obsolete code and configuration instead of retaining compatibility scaffolding.
- If a proposed change makes the project materially more complex, stop and ask for explicit confirmation before implementing it.

## Non-negotiable behavior

- Keep a single MCP tool and namespaced GET/LIST operations only.
- Never expose Kubernetes credentials or raw Secret values. Secret GET values remain HMAC fingerprints; Secret LISTs remain sanitized.
- Preserve independent resource policy, namespace policy, and Kubernetes RBAC enforcement.
- Keep production authentication fail-closed. Unauthenticated mode is only for explicitly opted-in isolated development.
- Do not leak upstream bodies, credentials, tokens, fingerprints, resource bodies, or arbitrary exception text into errors, logs, or audit records.
- Keep upstream-body, safe-output, pagination, continuation-token, and timeout bounds intact unless a deliberate, tested change requires otherwise.
- Keep edge request-body, header, rate, concurrency, client-IP, scheme, and external-host handling delegated to the private ingress, load balancer, or service mesh.
- Application resource mappings and Kubernetes RBAC must stay aligned, but neither may substitute for the other.

Read [docs/security.md](docs/security.md) before changing authentication, authorization, Kubernetes reads, Secret handling, errors, audit, middleware ordering, limits, deployment, or RBAC.

## Repository map

- `src/KubeMcp/` — application code and default settings
- `tests/KubeMcp.Tests/` — xUnit unit and in-process integration tests
- `tests/integration/` — disposable-kind end-to-end harness
- `deployment.yaml` — production reference manifest
- `overlays/development/` — isolated Development-only unauthenticated patch
- `overlays/cnpg/` and `overlays/traefik/` — optional CRD mappings and matching RBAC
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

Use targeted tests while iterating, then run the full suite for code or manifest changes. Run `./tests/integration/run-kind.sh` for changes affecting the container, deployment, authentication, Kubernetes integration, Secret handling, resource mappings/RBAC, CI container delivery, or kind harness. See [docs/development.md](docs/development.md).

When dependencies change, refresh and commit both relevant `packages.lock.json` files, then verify a locked restore. Keep CI actions and Docker base images pinned; do not replace immutable pins with mutable tags.

## Change expectations

- Add or update tests for behavior changes and security boundaries.
- Keep error categories and structured log fields low-cardinality and sanitized.
- Update focused documentation rather than expanding the README.
- Never commit keys, tokens, kubeconfigs, API keys, or HMAC keys.
- Preserve unrelated working-tree changes.
