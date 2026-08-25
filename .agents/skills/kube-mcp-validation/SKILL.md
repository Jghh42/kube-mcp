---
name: kube-mcp-validation
description: Selects and runs the appropriate validation workflow for kube-mcp changes, including targeted .NET tests, the full build gate, locked dependency checks, and kind integration. Use after modifying code, configuration, manifests, containers, dependencies, or CI.
---

# kube-mcp validation

Resolve the repository root with `git rev-parse --show-toplevel` and run commands there. Inspect `git status --short` first and do not alter unrelated changes.

## During development

Run the closest test class while iterating:

```sh
dotnet test tests/KubeMcp.Tests/KubeMcp.Tests.csproj \
  --filter 'FullyQualifiedName~<TestClassName>'
```

Match the test area to the change (for example authentication, access policy, Kubernetes boundaries, Secret handling, audit, process readiness, endpoints, or deployment).

## Standard gate

For code, configuration, or manifest changes:

```sh
dotnet restore KubeMcp.slnx --locked-mode
dotnet build KubeMcp.slnx --configuration Release --no-restore
dotnet test KubeMcp.slnx --configuration Release --no-build --no-restore
git diff --check
```

For documentation-only changes, run `git diff --check` and verify changed relative links and anchors.

## Dependency changes

A package edit must update the applicable lock files. Run a normal restore to refresh them, review the lock-file diff, then rerun `dotnet restore KubeMcp.slnx --locked-mode` and the standard gate.

## End-to-end gate

Run this for changes affecting Docker, deployment manifests, authentication, Kubernetes integration, resource mappings/RBAC, Secret handling, CI container delivery, or the harness itself:

```sh
./tests/integration/run-kind.sh
```

This requires Docker, kind, kubectl, curl, Python 3, and OpenSSL. Read the [development guide](../../../docs/development.md) before diagnosing cleanup or image-handoff behavior.

Report exactly which checks ran and whether any were skipped.
