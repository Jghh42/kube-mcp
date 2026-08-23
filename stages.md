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

3.
Add CI/CD for building the container and pushing to a real container registry (ghcr)

3.
Add allowlisting for resource types and blacklisting for namespaces

4. 
Add simple token based auth

5.
Add Audit logging (based on the normal ILogger for now)

6.
Add clientcredential flow auth