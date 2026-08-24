#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

cluster_name=${KIND_CLUSTER_NAME:-kind}
local_port=${KUBE_MCP_TEST_PORT:-18082}
keycloak_local_port=${KUBE_MCP_KEYCLOAK_TEST_PORT:-18083}
fixture_namespace=kube-mcp-e2e
secret_value=correct-horse-battery-staple
test_image=kube-mcp:stage6-test
port_forward_log=$(mktemp)
keycloak_port_forward_log=$(mktemp)
deployment_manifest=$(mktemp)
original_deployment=$(mktemp)
original_clusterrole=$(mktemp)
resource_capture=$(mktemp)
resource_restore=$(mktemp)
port_forward_pid=
keycloak_port_forward_pid=
restore_needed=false
fixture_namespace_owned=false
original_kube_namespace_exists=false
original_access_label_exists=false
original_access_label_value=

# Normalize a captured API object so it can be compared and restored. The
# resourceVersion needed by `kubectl replace` is added from the live object at
# restore time; all other server-managed identity/status fields are removed.
normalize_k8s_object() {
  python3 -c '
import json, sys
d = json.load(sys.stdin)
d.pop("status", None)
m = d.get("metadata", {})
for k in ("resourceVersion", "uid", "creationTimestamp", "generation", "managedFields"):
    m.pop(k, None)
ann = m.get("annotations")
if ann:
    ann.pop("deployment.kubernetes.io/revision", None)
    if not ann:
        m.pop("annotations", None)
json.dump(d, sys.stdout, sort_keys=True, separators=(",", ":"))
'
}

# Capture one object without treating NotFound as an error. An empty snapshot
# records that the object did not exist and must be deleted during restoration.
capture_resource() {
  local snapshot=$1
  shift
  : >"$resource_capture"
  kubectl get "$@" --ignore-not-found -o json >"$resource_capture"
  if [[ -s "$resource_capture" ]]; then
    normalize_k8s_object <"$resource_capture" >"$snapshot"
  else
    : >"$snapshot"
  fi
}

capture_original_state() {
  capture_resource "$original_deployment" \
    deployment kube-mcp --namespace kube-mcp
  capture_resource "$original_clusterrole" clusterrole kube-mcp-reader

  : >"$resource_capture"
  kubectl get namespace kube-mcp --ignore-not-found -o json >"$resource_capture"
  if [[ -s "$resource_capture" ]]; then
    original_kube_namespace_exists=true
    if original_access_label_value=$(python3 -c '
import json, sys
labels = json.load(sys.stdin).get("metadata", {}).get("labels", {})
key = "kube-mcp.io/agent-access"
if key not in labels:
    raise SystemExit(3)
print(labels[key], end="")
' <"$resource_capture"); then
      original_access_label_exists=true
    elif [[ $? -ne 3 ]]; then
      return 1
    fi
  fi
}

# Generate a complete replacement object with the live resourceVersion. Unlike
# `kubectl apply`, replace removes fields added by a test phase, so the original
# env list and RBAC rules are restored exactly rather than merge-restored.
write_restore_object() {
  local snapshot=$1
  local resource_version=$2
  python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
d.setdefault("metadata", {})["resourceVersion"] = sys.argv[2]
json.dump(d, sys.stdout)
' "$snapshot" "$resource_version" >"$resource_restore"
}

# kubectl replace rewrites kubectl.kubernetes.io/last-applied-configuration when
# that annotation is present, even with --save-config=false. Patch the complete
# original annotations map back afterward so client-maintained metadata is also
# restored exactly. Controller-maintained Deployment revision is normalized out.
restore_metadata_annotations() {
  local snapshot=$1
  shift
  : >"$resource_capture"
  if ! kubectl get "$@" -o json >"$resource_capture"; then
    return 1
  fi
  if ! python3 -c '
import json, sys
expected = json.load(open(sys.argv[1])).get("metadata", {}).get("annotations")
current_meta = json.load(open(sys.argv[2])).get("metadata", {})
if expected is None and "annotations" not in current_meta:
    operations = []
elif expected is None:
    operations = [{"op": "remove", "path": "/metadata/annotations"}]
else:
    operation = "replace" if "annotations" in current_meta else "add"
    operations = [{"op": operation, "path": "/metadata/annotations", "value": expected}]
json.dump(operations, sys.stdout)
' "$snapshot" "$resource_capture" >"$resource_restore"; then
    return 1
  fi
  if [[ $(<"$resource_restore") != "[]" ]]; then
    kubectl patch "$@" --type=json --patch-file "$resource_restore" >/dev/null
  fi
}

restore_resource() {
  local snapshot=$1
  shift
  local resource_version
  if ! resource_version=$(kubectl get "$@" --ignore-not-found \
    -o jsonpath='{.metadata.resourceVersion}'); then
    return 1
  fi

  if [[ -s "$snapshot" ]]; then
    if [[ -n "$resource_version" ]]; then
      if ! write_restore_object "$snapshot" "$resource_version"; then
        return 1
      fi
      if ! kubectl replace --filename "$resource_restore" >/dev/null; then
        return 1
      fi
    else
      if ! kubectl create --filename "$snapshot" >/dev/null; then
        return 1
      fi
    fi
    if ! restore_metadata_annotations "$snapshot" "$@"; then
      return 1
    fi
  else
    kubectl delete "$@" --ignore-not-found --wait=true >/dev/null
  fi
}

verify_resource() {
  local snapshot=$1
  shift
  : >"$resource_capture"
  if ! kubectl get "$@" --ignore-not-found -o json >"$resource_capture"; then
    return 1
  fi
  if [[ -s "$resource_capture" ]]; then
    if ! normalize_k8s_object <"$resource_capture" >"$resource_restore"; then
      return 1
    fi
  else
    : >"$resource_restore"
  fi
  if ! cmp --silent "$snapshot" "$resource_restore"; then
    echo "restored state differs for: $*" >&2
    diff --unified "$snapshot" "$resource_restore" >&2 || true
    return 1
  fi
}

restore_access_label() {
  local namespace
  if ! namespace=$(kubectl get namespace kube-mcp --ignore-not-found -o name); then
    return 1
  fi
  [[ -n "$namespace" ]] || return 0

  if [[ "$original_kube_namespace_exists" == "true" &&
        "$original_access_label_exists" == "true" ]]; then
    kubectl label namespace kube-mcp \
      "kube-mcp.io/agent-access=$original_access_label_value" \
      --overwrite >/dev/null
  else
    kubectl label namespace kube-mcp kube-mcp.io/agent-access- \
      --overwrite >/dev/null
  fi
}

verify_access_label() {
  local namespace label_value='' label_exists=false label_status
  if ! namespace=$(kubectl get namespace kube-mcp --ignore-not-found -o name); then
    return 1
  fi
  if [[ -z "$namespace" ]]; then
    [[ "$original_kube_namespace_exists" == "false" ]]
    return
  fi

  : >"$resource_capture"
  if ! kubectl get namespace kube-mcp -o json >"$resource_capture"; then
    return 1
  fi
  if label_value=$(python3 -c '
import json, sys
labels = json.load(sys.stdin).get("metadata", {}).get("labels", {})
key = "kube-mcp.io/agent-access"
if key not in labels:
    raise SystemExit(3)
print(labels[key], end="")
' <"$resource_capture"); then
    label_exists=true
  else
    label_status=$?
    [[ "$label_status" -eq 3 ]] || return 1
  fi

  [[ "$label_exists" == "$original_access_label_exists" ]] &&
    [[ "$original_access_label_exists" == "false" ||
       "$label_value" == "$original_access_label_value" ]]
}

# Restore both resources even if one operation fails, then verify their full
# normalized state. This function is used on the success path and by the EXIT
# trap, which is armed before the first kubectl mutation below.
restore_original_state() {
  local failed=0
  restore_resource "$original_clusterrole" clusterrole kube-mcp-reader || failed=1
  restore_resource "$original_deployment" \
    deployment kube-mcp --namespace kube-mcp || failed=1
  restore_access_label || failed=1
  verify_resource "$original_clusterrole" clusterrole kube-mcp-reader || failed=1
  verify_resource "$original_deployment" \
    deployment kube-mcp --namespace kube-mcp || failed=1
  verify_access_label || failed=1
  return "$failed"
}

cleanup() {
  local exit_code=$?
  local restore_code=0
  trap - EXIT
  set +e

  for pid in "$port_forward_pid" "$keycloak_port_forward_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  if [[ "$restore_needed" == "true" ]]; then
    restore_original_state
    restore_code=$?
    if ((restore_code != 0)); then
      echo "failed to restore the original kube-mcp Deployment/ClusterRole state" >&2
      exit_code=1
    fi
  fi
  if [[ "$fixture_namespace_owned" == "true" ]]; then
    if ! kubectl delete namespace "$fixture_namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1; then
      echo "failed to delete integration fixture namespace '$fixture_namespace'" >&2
      exit_code=1
    fi
  fi
  rm -f "$port_forward_log" "$keycloak_port_forward_log" "$deployment_manifest" \
    "$original_deployment" "$original_clusterrole" "$resource_capture" "$resource_restore"
  exit "$exit_code"
}
trap cleanup EXIT

kind get clusters | grep -Fxq "$cluster_name" || {
  echo "kind cluster '$cluster_name' does not exist" >&2
  exit 1
}

# The fixture namespace is owned by this run and deleted on exit. Refuse to
# destroy a pre-existing namespace with the same name.
if [[ -n $(kubectl get namespace "$fixture_namespace" --ignore-not-found -o name) ]]; then
  echo "fixture namespace '$fixture_namespace' already exists; refusing to delete it" >&2
  exit 1
fi

# Snapshot the state that existed before this harness, not the test deployment
# produced below. Arm restoration immediately after the complete snapshot and
# before kind image loading, namespace creation, apply, label, env, or RBAC
# mutations. Empty snapshots ensure a fresh CI cluster is restored to absence.
capture_original_state
restore_needed=true

start_port_forward() {
  : >"$port_forward_log"
  kubectl port-forward --namespace kube-mcp service/kube-mcp "$local_port:80" \
    >"$port_forward_log" 2>&1 &
  port_forward_pid=$!

  for _ in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:$local_port/readyz" >/dev/null; then
      return
    fi
    if ! kill -0 "$port_forward_pid" 2>/dev/null; then
      cat "$port_forward_log" >&2
      exit 1
    fi
    sleep 1
  done
  curl --fail --silent "http://127.0.0.1:$local_port/readyz" >/dev/null
}

echo "Restoring integration test dependencies in locked mode..."
dotnet restore KubeMcp.slnx --locked-mode

echo "Building $test_image..."
docker build --tag "$test_image" .
kind load docker-image "$test_image" --name "$cluster_name"

# Build the authenticated kind test fixture from the checked-in kustomize
# overlay instead of the previous indentation-sensitive sed insertion.
# See tests/integration/overlays/oauth/kustomization.yaml.
echo "Rendering integration manifest from kustomize overlay..."
kubectl kustomize --load-restrictor LoadRestrictionsNone tests/integration/overlays/oauth/ \
  >"$deployment_manifest"
grep -Fq "image: $test_image" "$deployment_manifest" || {
  echo "kustomize overlay did not set the test image in the integration manifest" >&2
  exit 1
}
grep -Fq "value: OAuthClientCredentials" "$deployment_manifest" || {
  echo "kustomize overlay did not enable OAuth authentication in the integration manifest" >&2
  exit 1
}

kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply --filename tests/integration/keycloak.yaml >/dev/null
kubectl rollout restart deployment/keycloak --namespace kube-mcp >/dev/null
kubectl rollout status deployment/keycloak --namespace kube-mcp --timeout=180s

kubectl port-forward --namespace kube-mcp service/keycloak "$keycloak_local_port:8080" \
  >"$keycloak_port_forward_log" 2>&1 &
keycloak_port_forward_pid=$!
for _ in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:$keycloak_local_port/realms/kube-mcp" >/dev/null; then
    break
  fi
  if ! kill -0 "$keycloak_port_forward_pid" 2>/dev/null; then
    cat "$keycloak_port_forward_log" >&2
    exit 1
  fi
  sleep 1
done
curl --fail --silent "http://127.0.0.1:$keycloak_local_port/realms/kube-mcp" >/dev/null

token_endpoint="http://127.0.0.1:$keycloak_local_port/realms/kube-mcp/protocol/openid-connect/token"
request_token() {
  curl --fail --silent --show-error --request POST "$token_endpoint" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=$1" \
    --data-urlencode "client_secret=$2" |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])'
}

invalid_secret_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --request POST "$token_endpoint" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode client_id=kube-mcp-e2e \
  --data-urlencode client_secret=incorrect)
[[ "$invalid_secret_status" == 401 ]] || {
  echo "Keycloak accepted an invalid client secret (HTTP $invalid_secret_status)" >&2
  exit 1
}

hmac_key=$(openssl rand -base64 32)
kubectl create secret generic kube-mcp-hmac \
  --namespace kube-mcp \
  --from-literal="key=$hmac_key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl apply --filename "$deployment_manifest" >/dev/null
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__NamespacePolicy__Mode- \
  KubeMcp__NamespacePolicy__LabelSelector- >/dev/null
kubectl rollout restart deployment/kube-mcp --namespace kube-mcp >/dev/null
kubectl rollout status deployment/kube-mcp --namespace kube-mcp --timeout=120s

service_account=system:serviceaccount:kube-mcp:kube-mcp
[[ $(kubectl auth can-i list pods --namespace kube-mcp --as "$service_account") == "yes" ]]
[[ $(kubectl auth can-i list namespaces --as "$service_account" 2>/dev/null) == "yes" ]]
[[ $(kubectl auth can-i list roles --namespace kube-mcp --as "$service_account") == "no" ]]
[[ $(kubectl auth can-i create pods --namespace kube-mcp --as "$service_account") == "no" ]]

fixture_namespace_owned=true
kubectl apply -f - <<'EOF' >/dev/null
apiVersion: v1
kind: Namespace
metadata:
  name: kube-mcp-e2e
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: stage-two
  namespace: kube-mcp-e2e
data:
  test: integration
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

# Run one integration test phase. OAuth tokens are re-acquired here (per phase)
# because the Keycloak access tokens have a 300-second lifetime and the three
# phases plus rollouts can exceed it on slow runners. Extra KUBE_MCP_* env vars
# passed as arguments configure the per-phase policy mode under test.
run_integration_phase() {
  local description="$1"
  shift
  local access_token wrong_audience_token missing_permission_token
  access_token=$(request_token kube-mcp-e2e stage-five-e2e-client-secret)
  wrong_audience_token=$(request_token kube-mcp-wrong-audience stage-five-wrong-audience-secret)
  missing_permission_token=$(request_token kube-mcp-missing-permission stage-five-missing-permission-secret)

  echo "Running $description..."
  env \
    KUBE_MCP_INTEGRATION_ENDPOINT="http://127.0.0.1:$local_port/mcp" \
    KUBE_MCP_INTEGRATION_ACCESS_TOKEN="$access_token" \
    KUBE_MCP_INTEGRATION_WRONG_AUDIENCE_TOKEN="$wrong_audience_token" \
    KUBE_MCP_INTEGRATION_MISSING_PERMISSION_TOKEN="$missing_permission_token" \
    "$@" \
    dotnet test KubeMcp.slnx \
      --configuration Release \
      --no-restore \
      --filter 'FullyQualifiedName~KindIntegrationTests' \
      --logger 'console;verbosity=normal'
}

start_port_forward

run_integration_phase "MCP-to-kind integration tests"

audit_logs=$(kubectl logs deployment/kube-mcp --namespace kube-mcp)
grep -Fq 'Kubernetes audit:' <<<"$audit_logs"
grep -Fq 'client=kube-mcp-e2e authentication=OAuthClientCredentials' <<<"$audit_logs"
grep -Fq 'operation=GET resource=secrets namespace=kube-mcp-e2e name=integration-secret result=success objectCount=1' <<<"$audit_logs"
if grep -Fq "$secret_value" <<<"$audit_logs"; then
  echo "Secret value leaked into Kubernetes audit logs" >&2
  exit 1
fi
if grep -Fq 'annotation-must-not-leak' <<<"$audit_logs"; then
  echo "unsafe Secret annotation leaked into Kubernetes audit logs" >&2
  exit 1
fi

kill "$port_forward_pid" 2>/dev/null || true
wait "$port_forward_pid" 2>/dev/null || true
port_forward_pid=

kubectl label namespace kube-mcp kube-mcp.io/agent-access=allowed --overwrite >/dev/null
kubectl label namespace "$fixture_namespace" kube-mcp.io/agent-access=allowed --overwrite >/dev/null
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__NamespacePolicy__Mode=LabelSelector \
  KubeMcp__NamespacePolicy__LabelSelector=kube-mcp.io/agent-access=allowed >/dev/null
kubectl rollout status deployment/kube-mcp --namespace kube-mcp --timeout=120s
start_port_forward

run_integration_phase "label-selector namespace policy integration tests" \
  KUBE_MCP_NAMESPACE_POLICY_MODE=LabelSelector

kill "$port_forward_pid" 2>/dev/null || true
wait "$port_forward_pid" 2>/dev/null || true
port_forward_pid=

kubectl apply --filename deployment-allow-all-rbac.yaml >/dev/null
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__ResourcePolicy__Mode=AllowAll >/dev/null
kubectl rollout status deployment/kube-mcp --namespace kube-mcp --timeout=120s
start_port_forward

run_integration_phase "AllowAll resource policy integration tests" \
  KUBE_MCP_NAMESPACE_POLICY_MODE=LabelSelector \
  KUBE_MCP_RESOURCE_POLICY_MODE=AllowAll

# Explicit, checked restoration on the success path. Keep the EXIT guard armed
# until replacement/deletion, exact-state verification, and any resulting
# original Deployment rollout have all completed successfully.
restore_original_state
if [[ -s "$original_deployment" ]]; then
  kubectl rollout status deployment/kube-mcp \
    --namespace kube-mcp --timeout=120s
fi
restore_needed=false

echo "Stage 6 integration tests passed for audit logging, authentication, allowlist, AllowAll, blacklist, and label-selector modes. Original Deployment, ClusterRole, and kube-mcp access-label state restored."
