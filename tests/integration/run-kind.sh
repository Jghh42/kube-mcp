#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

cluster_name=${KIND_CLUSTER_NAME:-kube-mcp-e2e-$$}
kind_context="kind-${cluster_name}"
kube_namespace=kube-mcp
fixture_namespace=kube-mcp-e2e
local_port=${KUBE_MCP_TEST_PORT:-18082}
test_image=kube-mcp:integration
secret_value=correct-horse-battery-staple
secret_value_base64=$(printf '%s' "$secret_value" | base64 | tr -d '\n')
secret_username=integration-user
secret_username_base64=$(printf '%s' "$secret_username" | base64 | tr -d '\n')
upstream_secret_prefix='UPSTREAM-SECRET-BOUNDARY!!!'
upstream_secret_prefix_base64=$(printf '%s' "$upstream_secret_prefix" | base64 | tr -d '\n')

for command in kind kubectl curl docker openssl python3 dotnet; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 1
  }
done

if kind get clusters | grep -Fxq "$cluster_name"; then
  echo "kind cluster '$cluster_name' already exists; refusing to reuse it" >&2
  exit 1
fi

cluster_owned=false
port_forward_pid=
port_forward_log=$(mktemp)
deployment_manifest=$(mktemp)

kubectl() {
  command kubectl --context "$kind_context" "$@"
}

stop_port_forward() {
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
    port_forward_pid=
  fi
}

cleanup() {
  local exit_code=$?
  trap - EXIT
  set +e
  stop_port_forward
  if [[ "$cluster_owned" == true ]] && ! kind delete cluster --name "$cluster_name"; then
    echo "failed to delete disposable kind cluster '$cluster_name'" >&2
    exit_code=1
  fi
  rm -f "$port_forward_log" "$deployment_manifest" || exit_code=1
  exit "$exit_code"
}
trap cleanup EXIT

wait_for_rollout() {
  if kubectl rollout status deployment/kube-mcp \
    --namespace "$kube_namespace" --timeout=120s; then
    return
  fi

  # Keep failure diagnostics useful without describing pods or printing Secret values.
  kubectl get deployment,replicaset,pod --namespace "$kube_namespace" \
    --selector app.kubernetes.io/name=kube-mcp -o wide >&2 || true
  kubectl get events --namespace "$kube_namespace" \
    --field-selector type=Warning --sort-by=.lastTimestamp >&2 || true
  kubectl logs deployment/kube-mcp --namespace "$kube_namespace" \
    --all-containers --tail=100 >&2 || true
  return 1
}

start_port_forward() {
  local target_pod
  target_pod=$(kubectl get pods --namespace "$kube_namespace" \
    --selector app.kubernetes.io/name=kube-mcp -o json | python3 -c '
import json, sys
pods = [
    pod for pod in json.load(sys.stdin)["items"]
    if not pod["metadata"].get("deletionTimestamp")
    and any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in pod.get("status", {}).get("conditions", [])
    )
]
if not pods:
    raise SystemExit("no ready kube-mcp pod found")
pods.sort(key=lambda pod: pod["metadata"].get("creationTimestamp", ""), reverse=True)
print(pods[0]["metadata"]["name"])
')
  : >"$port_forward_log"
  command kubectl --context "$kind_context" port-forward \
    --namespace "$kube_namespace" "pod/$target_pod" \
    "$local_port:8080" >"$port_forward_log" 2>&1 &
  port_forward_pid=$!

  for _ in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:$local_port/readyz" >/dev/null; then
      return
    fi
    if ! kill -0 "$port_forward_pid" 2>/dev/null; then
      cat "$port_forward_log" >&2
      return 1
    fi
    sleep 1
  done
  cat "$port_forward_log" >&2
  return 1
}

run_test() {
  local description=$1
  local filter=$2
  echo "Running $description..."
  KUBE_MCP_INTEGRATION_ENDPOINT="http://127.0.0.1:$local_port/mcp" \
  KUBE_MCP_INTEGRATION_API_KEY="$api_key" \
    dotnet test tests/KubeMcp.Tests/KubeMcp.Tests.csproj \
      --configuration Release --no-restore --filter "$filter" \
      --logger 'console;verbosity=normal'
}

assert_no_sensitive_logs() {
  local logs=$1
  local forbidden
  for forbidden in "$api_key" "$hmac_key" 'hmac-sha256:' "$secret_value" \
    "$secret_value_base64" "$secret_username" "$secret_username_base64" \
    "$upstream_secret_prefix" "$upstream_secret_prefix_base64" \
    'annotation-must-not-leak'; do
    if grep -Fq "$forbidden" <<<"$logs"; then
      echo "sensitive integration fixture data leaked into application logs" >&2
      return 1
    fi
  done
}

echo "Restoring integration test dependencies in locked mode..."
dotnet restore KubeMcp.slnx --locked-mode

echo "Creating disposable kind cluster $cluster_name..."
cluster_owned=true
kind create cluster \
  --name "$cluster_name" \
  --image kindest/node:v1.32.2@sha256:f226345927d7e348497136874b6d207e0b32cc52154ad8323129352923a3142f \
  --wait 60s
kubectl get --raw=/readyz >/dev/null

if [[ ${KUBE_MCP_SKIP_IMAGE_BUILD:-false} == true ]]; then
  docker image inspect "$test_image" >/dev/null
else
  echo "Building $test_image..."
  docker build --platform linux/amd64 --tag "$test_image" .
fi
kind load docker-image "$test_image" --name "$cluster_name"

echo "Rendering the integration deployment..."
kubectl kustomize --load-restrictor LoadRestrictionsNone tests/integration \
  >"$deployment_manifest"
grep -Fq "image: $test_image" "$deployment_manifest"
grep -Fq 'value: ApiKey' "$deployment_manifest"
grep -Fq 'name: kube-mcp-api-key' "$deployment_manifest"

kubectl create namespace "$kube_namespace" >/dev/null
hmac_key=$(openssl rand -base64 32)
api_key=$(openssl rand -hex 32)
kubectl create secret generic kube-mcp-hmac --namespace "$kube_namespace" \
  --from-literal="key=$hmac_key" >/dev/null
kubectl create secret generic kube-mcp-api-key --namespace "$kube_namespace" \
  --from-literal="api-key=$api_key" >/dev/null
kubectl apply --filename "$deployment_manifest" >/dev/null

# Map Roles in application policy but omit them from RBAC to prove the two gates
# remain independent.
kubectl set env deployment/kube-mcp --namespace "$kube_namespace" \
  KubeMcp__AllowedResources__roles.rbac.authorization.k8s.io__Group=rbac.authorization.k8s.io \
  KubeMcp__AllowedResources__roles.rbac.authorization.k8s.io__Version=v1 \
  KubeMcp__AllowedResources__roles.rbac.authorization.k8s.io__Resource=roles \
  KubeMcp__AllowedResources__roles.rbac.authorization.k8s.io__Kind=Role >/dev/null
wait_for_rollout

service_account=system:serviceaccount:kube-mcp:kube-mcp
[[ $(kubectl auth can-i list pods --namespace "$fixture_namespace" --as "$service_account") == yes ]]
[[ $(kubectl auth can-i list namespaces --as "$service_account") == yes ]]
[[ $(kubectl auth can-i list roles --namespace "$fixture_namespace" --as "$service_account") == no ]]
[[ $(kubectl auth can-i create pods --namespace "$fixture_namespace" --as "$service_account") == no ]]

# This namespace is intentionally created after the service starts, proving that
# eligible namespaces are onboarded without discovery caches or restarts.
kubectl create namespace "$fixture_namespace" >/dev/null
kubectl apply -f - <<'EOF' >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: stage-ten
  namespace: kube-mcp-e2e
data:
  test: integration
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: boundary-safe-output
  namespace: kube-mcp-e2e
data:
  payload: placeholder
---
apiVersion: v1
kind: Secret
metadata:
  name: boundary-upstream
  namespace: kube-mcp-e2e
stringData:
  payload: placeholder
---
apiVersion: v1
kind: Secret
metadata:
  name: integration-secret
  namespace: kube-mcp-e2e
  annotations:
    dangerous.example.test/value: annotation-must-not-leak
type: Opaque
stringData:
  username: integration-user
  password: correct-horse-battery-staple
  duplicate: correct-horse-battery-staple
EOF
kubectl patch configmap boundary-safe-output --namespace "$fixture_namespace" --type merge \
  --patch "$(python3 -c 'import json; print(json.dumps({"data":{"payload":"s" * 4096}}))')" >/dev/null
kubectl patch secret boundary-upstream --namespace "$fixture_namespace" --type merge \
  --patch "$(python3 -c 'import json; print(json.dumps({"stringData":{"payload":"UPSTREAM-SECRET-BOUNDARY!!!" + "u" * 70000}}))')" >/dev/null

start_port_forward
run_test "API-key, policy, RBAC, resource, and Secret boundary tests" \
  'FullyQualifiedName=KubeMcp.Tests.KindIntegrationTests.McpReadsRealKindResourcesAndSanitizesSecrets'
stop_port_forward

audit_logs=$(kubectl logs deployment/kube-mcp --namespace "$kube_namespace")
grep -Fq 'KubeMcp.Audit.AuditLogger' <<<"$audit_logs"
grep -Fq 'client=static-api-key authentication=ApiKey' <<<"$audit_logs"
grep -F 'resource=roles.rbac.authorization.k8s.io namespace=kube-mcp-e2e' <<<"$audit_logs" |
  grep -Fq 'category=kubernetes_access_denied'
assert_no_sensitive_logs "$audit_logs"

kubectl label namespace "$kube_namespace" kube-mcp.io/agent-access=allowed >/dev/null
kubectl label namespace "$fixture_namespace" kube-mcp.io/agent-access=allowed >/dev/null
kubectl set env deployment/kube-mcp --namespace "$kube_namespace" \
  KubeMcp__NamespacePolicy__Mode=LabelSelector \
  KubeMcp__NamespacePolicy__LabelSelector=kube-mcp.io/agent-access=allowed >/dev/null
wait_for_rollout
start_port_forward
KUBE_MCP_NAMESPACE_POLICY_MODE=LabelSelector \
  run_test "label-selector allow and deny tests" \
  'FullyQualifiedName=KubeMcp.Tests.KindIntegrationTests.McpReadsRealKindResourcesAndSanitizesSecrets'
stop_port_forward
label_logs=$(kubectl logs deployment/kube-mcp --namespace "$kube_namespace")
assert_no_sensitive_logs "$label_logs"

kubectl set env deployment/kube-mcp --namespace "$kube_namespace" \
  KubeMcp__MaxResponseBytes=1024 \
  KubeMcp__MaxUpstreamBodyBytes=65536 >/dev/null
wait_for_rollout
start_port_forward
run_test "practical upstream and safe-output size boundaries" \
  'FullyQualifiedName=KubeMcp.Tests.KindIntegrationTests.McpEnforcesPracticalResponseBoundaries'
stop_port_forward

final_logs=$(kubectl logs deployment/kube-mcp --namespace "$kube_namespace")
assert_no_sensitive_logs "$final_logs"

echo "Integration tests passed; deleting disposable cluster $cluster_name."
