# Secure-boundary simplification plan

## Goal

Reduce `kube-mcp` to a small, maintainable boundary between an agent and the Kubernetes API while preserving the controls that belong inside that boundary. Edge traffic management is delegated to the private-network ingress, load balancer, or service mesh.

## Features that remain

The following behavior is intentionally retained:

- exactly one namespaced GET/LIST MCP tool;
- explicit resource mappings with matching narrow Kubernetes RBAC;
- automatic namespace onboarding through the existing blacklist and label-selector policies;
- detailed GET responses and compact LIST responses;
- sanitized Secret LIST responses;
- Secret GET responses containing keyed HMAC fingerprints instead of raw values;
- raw Secret buffer handling and no-leak regression tests;
- upstream Kubernetes body limits, safe response limits, item/page limits, continuation-token bounds, and timeouts;
- fixed safe errors that never expose Kubernetes response bodies or arbitrary exception text;
- fail-closed production authentication;
- sanitized structured audit records for dispatched Kubernetes operations;
- hardened container and deployment defaults.

## Target deployment model

Production is expected to run on a private network behind an ingress, load balancer, or service mesh. That edge layer owns:

- HTTP request-body and header limits;
- request rate and concurrency limits;
- originating-client IP logging;
- public TLS and external host handling;
- blocking untrusted direct access to the application Service where required.

The application continues to own limits on Kubernetes responses and agent-facing tool output because an ingress cannot enforce those boundaries.

## Authentication target

The application will support:

- a static bearer API key in production;
- unauthenticated mode only when the host environment is `Development`.

OAuth client credentials, JWT validation, Keycloak-specific claims, and the non-development unauthenticated override will be removed.

## Delivery workflow

Use the global `github-stage-delivery` skill for every stage checkpoint. In pi, load it explicitly with `/skill:github-stage-delivery` when necessary. The detailed rules below remain authoritative for agents or environments where that global skill is unavailable.

Each implementation stage is an independent review checkpoint. For every stage:

1. implement only that stage's scoped changes;
2. update its tests and focused documentation;
3. run targeted tests while iterating;
4. run the repository validation appropriate to the change;
5. review the diff against `AGENTS.md` and `docs/security.md`;
6. create a dedicated commit with the suggested commit subject below;
7. push the branch immediately after the commit;
8. monitor all GitHub Actions checks on the draft pull request until they complete;
9. if any check fails, retrieve its failure logs, diagnose and fix the problem, rerun the appropriate local validation, commit and push the correction, and monitor the new checks; repeat until every required check succeeds;
10. update the draft pull request description/checklist only after the pushed stage is green, then start the next stage.

Do not combine stages into one commit. Never move to the next stage while a required pull-request check is pending, cancelled, or failing. If a stage needs a corrective follow-up after local review or CI, commit and push that correction as part of the current stage and wait for its checks to succeed before proceeding.

The standard code validation gate is:

```sh
dotnet restore KubeMcp.slnx --locked-mode
dotnet build KubeMcp.slnx --configuration Release --no-restore
dotnet test KubeMcp.slnx --configuration Release --no-build --no-restore
git diff --check
```

Run `./tests/integration/run-kind.sh` for stages affecting deployment, authentication, Kubernetes integration, Secrets, namespace policy, the container, or the kind harness.

## Stage 1: simplify authentication

Suggested commit subject: `Simplify authentication to API key only`

### Changes

- Remove `OAuthClientCredentials` from `AuthenticationMode`.
- Remove OAuth options, claim evaluation, JWT bearer registration, and Keycloak-specific scope/role/audience handling.
- Remove `Authentication:AllowUnauthenticated`.
- Permit `Mode=None` only in the `Development` environment.
- Preserve constant-time API-key comparison and credential-buffer zeroing.
- Make the production deployment load its API key from a Kubernetes Secret.
- Remove the JWT bearer package and refresh both NuGet lock files.
- Update authentication, production deployment, configuration, security, and development documentation.

### Tests

- Production fails startup without a sufficiently strong API key.
- Production rejects unauthenticated mode with no override available.
- Development permits unauthenticated mode.
- Missing, malformed, and incorrect bearer credentials return `401`.
- The correct API key initializes MCP and exposes exactly one tool.
- Credentials do not appear in logs or errors.

### Validation

Run the full .NET gate and the kind integration harness after converting it sufficiently to authenticate with an API key. The complete Keycloak harness removal may be finalized in stage 10, but no OAuth-dependent test path may remain active after this stage.

## Stage 2: remove `AllowAll` and dynamic discovery

Suggested commit subject: `Remove dynamic Kubernetes resource discovery`

### Changes

- Remove `ResourcePolicyMode`; resource resolution always uses explicit mappings.
- Remove Kubernetes discovery methods, parsers, DTOs, cache, locking, alias resolution, ambiguity handling, parallelism, and stale-cache behavior.
- Remove `DiscoveryParallelism` and `DiscoveryCacheSeconds`.
- Remove the `AllowAll` startup warning and discovery-related memory validation.
- Delete `deployment-allow-all-rbac.yaml`.
- Remove the AllowAll kind phase and documentation.
- Preserve coordinated CRD mapping and RBAC overlays.

### Required ordering

For each tool call:

1. validate input;
2. resolve the explicit resource mapping without network access;
3. apply static namespace policy;
4. perform the namespace label-selector check when configured;
5. execute the namespaced GET or LIST.

### Tests

- Unknown resources fail before any Kubernetes request.
- Configured resources continue to resolve as intended.
- CRD overlays remain aligned with RBAC.
- No wildcard application resource mode or wildcard RBAC manifest remains.

### Validation

Run the full .NET gate and kind integration harness, then commit and push before stage 3.

## Stage 3: use one generic LIST summary

Suggested commit subject: `Replace resource-specific list summaries`

### Changes

- Replace per-kind non-Secret summarizers with one generic compact summary containing only `name`, `namespace`, `kind`, and `age` when available.
- Keep the dedicated Secret summary containing safe metadata, type, and key names.
- Keep GET responses detailed.
- Preserve response accounting, pagination, item limits, and the `limited` marker.

### Tests

- Generic LIST output contains only approved fields.
- Generic summaries never include `spec`, `status`, `managedFields`, annotations, raw data, or arbitrary CRD fields.
- Secret LIST responses include key names but no values or fingerprints.
- Secret GET fingerprint behavior is unchanged.
- Output limits and `limited` behavior remain intact.

### Validation

Run the full .NET gate and kind integration harness, then commit and push before stage 4.

## Stage 4: remove application traffic management

Suggested commit subject: `Delegate HTTP traffic limits to ingress`

### Changes

- Remove the pre-authentication admission middleware and gate.
- Remove the MCP request-body-limit middleware.
- Remove the authenticated ASP.NET concurrency limiter.
- Remove `McpAdmissionOptions`, `McpConcurrencyOptions`, their validation, settings, manifest variables, tests, and documentation.
- Remove ASP.NET rate-limiter registration and middleware.
- Document the private-network and ingress/service-mesh deployment contract.

### Controls that remain

- `MaxUpstreamBodyBytes`;
- `MaxResponseBytes`;
- `MaxListItems`;
- list page sizes and page count;
- continuation-token limits;
- Kubernetes and overall MCP deadlines;
- pod CPU and memory requests/limits.

### Tests

- Remove admission/body/concurrency behavior tests.
- Retain all upstream-body, safe-output, pagination, cancellation, and timeout boundary tests.
- Confirm health endpoints and MCP routing still work without rate-limiter metadata.

### Validation

Run the full .NET gate. Run kind because the deployment and MCP pipeline change, then commit and push before stage 5.

## Stage 5: remove custom forwarded-header handling

Suggested commit subject: `Delegate proxy metadata handling to ingress`

### Changes

- Remove custom forwarded-header configuration and middleware.
- Remove trusted proxy/network options and CIDR validation.
- Remove client IP from application audit records.
- Remove reverse-proxy tests and focused documentation.
- Let ingress own originating-client IP, external scheme, and host logging.
- Retain standard ASP.NET host configuration only if it remains useful without custom application code.

### Tests

- Audit records retain authenticated identity and request ID without client IP.
- MCP and health endpoints work without forwarded-header configuration.
- No caller-controlled forwarded value enters application audit records.

### Validation

Run the full .NET gate and relevant in-process endpoint tests, then commit and push before stage 6.

## Stage 6: simplify readiness

Suggested commit subject: `Simplify readiness to process health`

### Changes

- Remove the Kubernetes SelfSubjectAccessReview readiness implementation.
- Remove readiness caching, single-flight synchronization, target selection, and separate authorization-response bounds.
- Remove `ReadinessNamespace`.
- Keep opaque `/healthz` and `/readyz` process/startup endpoints.
- Rely on startup option validation and safe request-time Kubernetes errors.

### Tests

- Both health endpoints return a small fixed response.
- They remain outside MCP authentication.
- Invalid production configuration still prevents startup.
- Health responses expose no configuration or exception details.

### Validation

Run the full .NET gate and kind integration harness because deployment probes change, then commit and push before stage 7.

## Stage 7: remove custom OpenTelemetry

Suggested commit subject: `Remove optional OpenTelemetry instrumentation`

### Changes

- Remove the observability directory, telemetry options, middleware, and tool hooks.
- Remove OpenTelemetry package references and refresh both lock files.
- Remove telemetry tests and OTLP documentation.
- Retain sanitized structured logs and platform-provided ingress, pod, and container metrics.

### Tests

- Remove telemetry-specific tests.
- Verify tool errors, cancellation, timeouts, and audit records still retain their safe categories.
- Confirm no telemetry exporter configuration remains.

### Validation

Refresh lock files, run locked restore and the full .NET gate, then commit and push before stage 8.

## Stage 8: collapse audit delivery to structured logging

Suggested commit subject: `Simplify audit delivery to structured logging`

### Changes

- Remove `AuditSinkDispatcher`, `CompositeAuditSink`, `IAuditSink`, `IAuditEventPublisher`, and `StructuredLoggerAuditSink`.
- Remove the custom queue, fan-out, per-sink deadlines, drop reporting, and background service.
- Write already-sanitized audit events directly through a dedicated `ILogger<AuditLogger>`.
- Continue recording every dispatched `k8s_get` success, policy denial, Kubernetes/RBAC failure, timeout, cancellation, and internal failure.
- Leave authentication failures to ingress/ASP.NET access logging rather than parsing arbitrary MCP bodies for coordinates.

### Tests

- Required structured audit fields remain present.
- Untrusted values are length-bounded and stripped of control characters.
- API keys, HMAC keys, Kubernetes bodies, raw Secret values, and fingerprints never appear.
- Secret success and failure records remain safe.
- Logging does not replace the original tool result/error.

### Validation

Run the full .NET gate and kind log assertions, then commit and push before stage 9.

## Stage 9: simplify deployment and development configuration

Suggested commit subject: `Simplify deployment configuration`

### Changes

- Finalize the production API-key and HMAC Secret configuration.
- Remove all obsolete OAuth, traffic-management, proxy, telemetry, discovery, and readiness settings and comments.
- Preserve namespace LIST RBAC because label-selector policy requires it.
- Preserve container hardening and narrow resource RBAC.
- Replace the duplicated development Deployment with a small Kustomize overlay or patch that changes only the environment, authentication mode, and development image behavior where necessary.
- Consolidate documentation and remove documents that no longer justify a separate file.

### Tests

- Production manifest is fail-closed and sources credentials from Secret references.
- Development overlay selects Development-only unauthenticated mode.
- Manifest resource mappings and RBAC remain aligned.
- Security context, liveness/readiness probes, resource limits, and ClusterIP exposure remain intentional.

### Validation

Run the full .NET gate, manifest-focused tests, and kind integration harness, then commit and push before stage 10.

## Stage 10: simplify integration tests and CI

Suggested commit subject: `Simplify kind integration and container CI`

### Integration harness changes

- Delete the Keycloak manifest and OAuth overlay.
- Remove token acquisition, scope/role/audience checks, and OAuth port forwarding.
- Remove the AllowAll phase.
- Use an ephemeral, harness-owned kind cluster so exact restoration of pre-existing cluster-scoped resources is unnecessary.
- Remove the custom image-archive graph verifier and related Python/cache files.

The reduced end-to-end suite must cover:

1. API-key rejection and acceptance;
2. exactly one MCP tool;
3. ordinary GET;
4. compact generic LIST;
5. Secret GET fingerprinting;
6. Secret LIST sanitization;
7. resource-policy denial;
8. blacklist namespace denial;
9. automatic access to a newly created namespace;
10. label-selector allow and deny behavior;
11. Kubernetes RBAC denial;
12. absence of raw Secret values in responses and logs;
13. practical upstream and safe-output boundary checks.

### CI target

Use two straightforward jobs:

1. **Build and test** — locked restore, Release build, unit/in-process tests, NuGet vulnerability scan, and diff checks.
2. **Container, kind, scan, and publish** — build the image once, load it into a disposable kind cluster, run integration tests, scan the same local image, and publish it on eligible pushes/tags.

Retain:

- commit-SHA-pinned GitHub Actions;
- digest-pinned Docker base images;
- locked NuGet dependencies;
- vulnerability scanning;
- an SBOM and standard provenance where practical;
- full-revision `sha-<commit>` traceability tags and immutable digest references;
- a real Kubernetes/Secret boundary test before publication.

Remove custom archive hashing, manifest/config graph verification, cross-job candidate artifacts, and registry round-trip verification.

### Validation

Run the complete local gate and the new harness. Validate the workflow YAML and inspect the complete security-sensitive diff. Commit and push the final stage, then mark the pull request ready for review only after CI succeeds.

## Final acceptance criteria

- Only API-key and Development-only unauthenticated modes remain.
- No OAuth, JWT, or Keycloak code remains.
- No `AllowAll`, discovery, or wildcard RBAC remains.
- Ordinary LIST uses one generic safe summary.
- Secret HMAC fingerprinting, sanitization, and no-leak tests remain.
- Both namespace-policy modes remain functional.
- Newly created eligible namespaces are picked up automatically.
- No application request-body, admission, concurrency, or rate-limiting feature remains.
- No custom forwarded-header handling remains.
- Readiness is process-only.
- No OpenTelemetry dependencies or middleware remain.
- Audit uses direct sanitized structured logging.
- CI still runs a real Kubernetes and Secret boundary test.
- Documentation explicitly assigns edge traffic controls to ingress or service-mesh infrastructure.
- The full build, test, integration, and diff validation gates pass.
