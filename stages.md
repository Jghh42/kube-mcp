We want to over time implement the entire spec as defined in spec.md but we will do so in stages. After each stage do your own automated testing, when you are happy with the result let it continue running, explain what you have done + how you have tested it, i will then manually test/verify/review it and we will iterate on it until we have something to commit and go to the next stage.


1.
Setup dev env, create a basic .net project with a dockerfile + deployment.yaml + service account (read / list on everything). We already have kind on this machine so use that for testing, and use the "kind load" to inject our build container image. 
-----------
 Stage 1 is complete and running in the kind cluster.

 ### Implemented

 - .NET 10 ASP.NET Core project: src/KubeMcp/
 - Functional tests: tests/KubeMcp.Tests/
 - Health endpoints:
     - /healthz
     - /readyz
 - Multi-stage, non-root container: Dockerfile
 - Kubernetes resources: deployment.yaml
     - Namespace and Service
     - Deployment with probes and restricted security context
     - ServiceAccount
     - ClusterRole allowing only get and list on all resources
     - ClusterRoleBinding
 - Build/deployment instructions: README.md
 - SDK configuration: global.json

 ### Validation

 - Release build: 0 warnings, 0 errors
 - Functional tests: 3/3 passed
 - Docker image built and loaded with kind load
 - Kubernetes rollout completed
 - Endpoints verified through port-forward
 - RBAC verified:
     - get: allowed
     - list: allowed
     - create, delete, watch: denied
 - Container runs as UID 1654
 - Pod is ready with zero restarts

 Current deployment:

 ```text
   pod/kube-mcp-769f7fdfbb-bdg9d   1/1   Running   0
 ```

 The deployment remains running in namespace kube-mcp
-----------

2.
Implement the MCP + Kubernetes part with the secret value hashing (no auth, audit logging, allowlisting for now)

2.5.
Implement compact, resource-specific LIST responses to minimize agent context use.

- Return structured JSON summaries comparable to useful `kubectl get -o wide` output rather than terminal-formatted tables.
- Do not return complete `.spec`, `.status`, `managedFields`, container status arrays, or other full-object structures from LIST.
- Include useful Pod fields such as name, ready, status, restarts, age, IP, and node.
- Add suitable compact summaries for common workloads, Services, ConfigMaps, and Secrets.
- Use a minimal name/namespace/kind/age fallback for CRDs without a resource-specific summarizer.
- Preserve LIST limits and the explicit `limited` indicator.
- Keep GET responses detailed so the agent can explicitly inspect objects discovered through LIST.
- Add unit and end-to-end tests that assert LIST responses remain compact and exclude heavyweight object content.

3.
Add CI/CD for building the container and pushing to a real container registry (ghcr)

4.
Add allowlisting for resource types and (blacklisting for namespaces or whitelisting namespaces based on labels)

5.
Add simple token based auth and client credential flow. It should be configurable to either have no auth, simple token auth or client credential auth.

6.
Add Audit logging (based on the normal ILogger for now)
-----------
Stage 6 is complete and running in the kind cluster.

### Implemented

- A dedicated audit boundary using the standard `ILogger` pipeline and its default console provider.
- One structured audit event for every attempted `k8s_get` execution, including successful, failed, and cancelled operations.
- Safe audit fields for UTC timestamp, authenticated client identity when available, authentication mode, GET/LIST operation, resource, namespace, optional name, result, object count, duration, request ID, and client IP.
- Identity resolution for OAuth client claims (`client_id`, `azp`, or `sub`), the non-secret shared API-key identity, and `anonymous` when authentication is disabled.
- Audit values are length-bounded and stripped of control characters to prevent multiline/log-forging input.
- Audit events never include Kubernetes response bodies, Secret values or fingerprints, bearer tokens, client secrets, Kubernetes credentials, or the HMAC key.
- Unit tests for structured audit fields, identity handling, safe value handling, and success/failure recording at the MCP tool boundary.
- The kind integration harness now verifies that OAuth-attributed audit events reach container console logs and that Secret values and unsafe annotations do not.

### Validation

- Release build: 0 warnings, 0 errors.
- Automated tests: 56/56 passed.
- Docker image built and loaded into kind.
- End-to-end tests passed in blacklist and label-selector namespace-policy modes with explicit resource mappings.
- Console audit output verified for an authenticated Secret GET, including client identity and object count.
- Audit logs verified not to contain the raw Secret value or unsafe Secret annotation.
- Narrow default RBAC and resource policy restored after integration testing.
- `kube-mcp` and the local Keycloak test deployment remain running in namespace `kube-mcp`.
-----------
