#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

cluster_name=${KIND_CLUSTER_NAME:-kind}
kind_context="kind-${cluster_name}"
kube_namespace=kube-mcp
fixture_namespace=kube-mcp-e2e
local_port=${KUBE_MCP_TEST_PORT:-18082}
keycloak_local_port=${KUBE_MCP_KEYCLOAK_TEST_PORT:-18083}
secret_value=correct-horse-battery-staple
secret_value_base64=$(printf '%s' "$secret_value" | base64 | tr -d '\n')
test_image=kube-mcp:stage6-test
test_image_archive=${KUBE_MCP_TEST_IMAGE_ARCHIVE:-}
test_image_archive_sha256=${KUBE_MCP_TEST_IMAGE_ARCHIVE_SHA256:-}
test_image_manifest_digest=${KUBE_MCP_TEST_IMAGE_MANIFEST_DIGEST:-}
test_image_config_digest=${KUBE_MCP_TEST_IMAGE_CONFIG_DIGEST:-}

if ! kubectl_command=$(command -v kubectl); then
  echo "kubectl is required" >&2
  exit 1
fi

# Every invocation below, including client-only create/kustomize commands, goes
# through this wrapper. Refuse a caller-supplied override so no operation can
# escape to the ambient context if the user's current context changes mid-run.
kubectl() {
  local argument
  for argument in "$@"; do
    if [[ "$argument" == --context || "$argument" == --context=* ]]; then
      echo "run-kind.sh owns kubectl context selection ($kind_context)" >&2
      return 2
    fi
  done
  command "$kubectl_command" --context "$kind_context" "$@"
}

port_forward_log=$(mktemp)
keycloak_port_forward_log=$(mktemp)
deployment_manifest=$(mktemp)
kind_kubeconfig=$(mktemp)
original_clusterrole=$(mktemp)
original_clusterrolebinding=$(mktemp)
resource_capture=$(mktemp)
resource_restore=$(mktemp)
port_forward_pid=
keycloak_port_forward_pid=
cluster_state_snapshot_needed=false
kube_namespace_owned=false
fixture_namespace_owned=false

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

capture_original_cluster_state() {
  capture_resource "$original_clusterrole" clusterrole kube-mcp-reader
  capture_resource "$original_clusterrolebinding" \
    clusterrolebinding kube-mcp-reader
}

# Generate a complete replacement object with the live resourceVersion. Unlike
# `kubectl apply`, replace removes fields added by a test phase, so original
# cluster-scoped metadata and RBAC fields are restored rather than merge-restored.
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

# Restore both cluster-scoped resources even if one operation fails, then
# verify their full normalized state. Namespaced state is not merge-restored:
# this harness refuses both managed namespaces when they pre-exist, creates
# them itself, and deletes them in full on every exit.
restore_original_cluster_state() {
  local failed=0
  restore_resource "$original_clusterrole" clusterrole kube-mcp-reader || failed=1
  restore_resource "$original_clusterrolebinding" \
    clusterrolebinding kube-mcp-reader || failed=1
  verify_resource "$original_clusterrole" clusterrole kube-mcp-reader || failed=1
  verify_resource "$original_clusterrolebinding" \
    clusterrolebinding kube-mcp-reader || failed=1
  return "$failed"
}

stop_port_forwards() {
  local pid
  for pid in "$port_forward_pid" "$keycloak_port_forward_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  port_forward_pid=
  keycloak_port_forward_pid=
}

# Namespace deletion is the ownership boundary for all namespaced resources:
# kube-mcp removes the ServiceAccount, kube-mcp/keycloak Services and
# Deployments, HMAC Secret, and Keycloak realm ConfigMap; kube-mcp-e2e removes
# its ConfigMap and Secret. ClusterRole and ClusterRoleBinding are restored
# separately from exact pre-run snapshots.
remove_owned_namespaces() {
  local failed=0
  if [[ "$fixture_namespace_owned" == "true" ]]; then
    if kubectl delete namespace "$fixture_namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null; then
      fixture_namespace_owned=false
    else
      echo "failed to delete owned namespace '$fixture_namespace'" >&2
      failed=1
    fi
  fi
  if [[ "$kube_namespace_owned" == "true" ]]; then
    if kubectl delete namespace "$kube_namespace" \
      --ignore-not-found --wait=true --timeout=120s >/dev/null; then
      kube_namespace_owned=false
    else
      echo "failed to delete owned namespace '$kube_namespace'" >&2
      failed=1
    fi
  fi
  return "$failed"
}

cleanup() {
  local exit_code=$?
  local cleanup_code
  trap - EXIT
  set +e

  stop_port_forwards
  remove_owned_namespaces
  cleanup_code=$?
  if ((cleanup_code != 0)); then
    exit_code=1
  fi
  if [[ "$cluster_state_snapshot_needed" == "true" ]]; then
    restore_original_cluster_state
    cleanup_code=$?
    if ((cleanup_code != 0)); then
      echo "failed to restore the original kube-mcp ClusterRole/ClusterRoleBinding state" >&2
      exit_code=1
    fi
  fi
  rm -f "$port_forward_log" "$keycloak_port_forward_log" "$deployment_manifest" \
    "$kind_kubeconfig" "$original_clusterrole" "$original_clusterrolebinding" \
    "$resource_capture" "$resource_restore"
  exit "$exit_code"
}
trap cleanup EXIT

kind get clusters | grep -Fxq "$cluster_name" || {
  echo "kind cluster '$cluster_name' does not exist" >&2
  exit 1
}

# Fail closed before the first Kubernetes mutation. In addition to requiring the
# expected current-context, compare its API endpoint and CA with kind's own
# kubeconfig. A same-named context that targets a different cluster is rejected.
if ! current_context=$(command "$kubectl_command" --context "$kind_context" \
  config current-context 2>/dev/null); then
  echo "kubectl has no current context; expected '$kind_context'" >&2
  exit 1
fi
if [[ "$current_context" != "$kind_context" ]]; then
  echo "kubectl current context is '$current_context'; expected '$kind_context'" >&2
  exit 1
fi
if ! kind get kubeconfig --name "$cluster_name" >"$kind_kubeconfig"; then
  echo "cannot read kubeconfig for kind cluster '$cluster_name'" >&2
  exit 1
fi
if ! kubectl config view --raw --flatten --minify -o json >"$resource_capture"; then
  echo "kubectl context '$kind_context' is unavailable" >&2
  exit 1
fi
if ! KUBECONFIG="$kind_kubeconfig" command "$kubectl_command" \
  --context "$kind_context" config view --raw --flatten --minify -o json \
  >"$resource_restore"; then
  echo "kind did not provide the expected context '$kind_context'" >&2
  exit 1
fi
if ! python3 - "$resource_capture" "$resource_restore" <<'PY'
import json
import sys


def cluster_identity(path):
    config = json.load(open(path))
    context = config["contexts"][0]["context"]
    cluster_name = context["cluster"]
    cluster = next(
        item["cluster"] for item in config["clusters"] if item["name"] == cluster_name
    )
    return cluster.get("server"), cluster.get("certificate-authority-data")


if cluster_identity(sys.argv[1]) != cluster_identity(sys.argv[2]):
    raise SystemExit(1)
PY
then
  echo "kubectl context '$kind_context' does not match kind cluster '$cluster_name'" >&2
  exit 1
fi
if ! kubectl get --raw=/readyz >/dev/null; then
  echo "Kubernetes API for context '$kind_context' is unavailable" >&2
  exit 1
fi

# Both namespaces are exclusively managed by this run. Refusing either one up
# front avoids overwriting unrelated ServiceAccounts, Services, Secrets,
# ConfigMaps, or Deployments and makes namespace deletion a safe full cleanup.
for managed_namespace in "$kube_namespace" "$fixture_namespace"; do
  if [[ -n $(kubectl get namespace "$managed_namespace" --ignore-not-found -o name) ]]; then
    echo "managed namespace '$managed_namespace' already exists; refusing to mutate it" >&2
    exit 1
  fi
done

# Snapshot cluster-scoped objects before namespace creation, apply, image load,
# label, env, or RBAC mutations. Empty snapshots restore fresh CI clusters to
# absence; pre-existing ClusterRole/ClusterRoleBinding objects are restored
# exactly. The EXIT trap is already armed and the guard is enabled immediately.
capture_original_cluster_state
cluster_state_snapshot_needed=true

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

if [[ -n "$test_image_archive" ]]; then
  for required_value in \
    "$test_image_archive_sha256" \
    "$test_image_manifest_digest" \
    "$test_image_config_digest"; do
    if [[ -z "$required_value" ]]; then
      echo "archive SHA256, manifest digest, and config digest are required with KUBE_MCP_TEST_IMAGE_ARCHIVE" >&2
      exit 1
    fi
  done
  actual_archive_sha256=$(sha256sum "$test_image_archive" | cut -d' ' -f1)
  if [[ "$actual_archive_sha256" != "$test_image_archive_sha256" ]]; then
    echo "test image archive SHA256 does not match the expected content address" >&2
    exit 1
  fi
  python3 tests/integration/verify-image-archive.py \
    "$test_image_archive" \
    --image "$test_image" \
    --expected-manifest-digest "$test_image_manifest_digest" \
    --expected-config-digest "$test_image_config_digest" >/dev/null
  echo "Loading tested candidate $test_image from the verified image archive..."
  kind load image-archive "$test_image_archive" --name "$cluster_name"
else
  echo "Building $test_image..."
  docker build --tag "$test_image" .
  kind load docker-image "$test_image" --name "$cluster_name"
fi

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

# Direct creation makes ownership unambiguous: if a race creates this namespace
# after the preflight, create fails and the cleanup trap will not delete it.
kubectl create namespace "$kube_namespace" >/dev/null
kube_namespace_owned=true
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

# A handed-in archive is content-addressed before loading. Kubernetes runtimes
# report either its manifest or config digest as imageID; accept only those two
# independently verified values, never an older local tag or registry fallback.
if [[ -n "$test_image_manifest_digest" ]]; then
  running_image_id=$(kubectl get pods --namespace kube-mcp \
    --selector app.kubernetes.io/name=kube-mcp \
    -o jsonpath='{.items[0].status.containerStatuses[0].imageID}')
  running_digest=${running_image_id##*@}
  if [[ "$running_digest" != "$test_image_manifest_digest" &&
        "$running_digest" != "$test_image_config_digest" ]]; then
    echo "running kube-mcp image ID '$running_image_id' does not identify the tested candidate" >&2
    exit 1
  fi
fi

service_account=system:serviceaccount:kube-mcp:kube-mcp
[[ $(kubectl auth can-i list pods --namespace kube-mcp --as "$service_account") == "yes" ]]
[[ $(kubectl auth can-i list namespaces --as "$service_account" 2>/dev/null) == "yes" ]]
[[ $(kubectl auth can-i list roles --namespace kube-mcp --as "$service_account") == "no" ]]
[[ $(kubectl auth can-i create pods --namespace kube-mcp --as "$service_account") == "no" ]]

kubectl create namespace "$fixture_namespace" >/dev/null
fixture_namespace_owned=true
kubectl apply -f - <<'EOF' >/dev/null
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
if grep -Fq "$secret_value_base64" <<<"$audit_logs"; then
  echo "base64-encoded Secret value leaked into Kubernetes audit logs" >&2
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

# Explicit, checked cleanup on the success path. Keep the EXIT guard armed until
# both owned namespaces (and therefore every namespaced fixture) are gone and
# both cluster-scoped snapshots have been restored and exactly verified.
stop_port_forwards
remove_owned_namespaces
restore_original_cluster_state
cluster_state_snapshot_needed=false

echo "Stage 6 integration tests passed for audit logging, authentication, allowlist, AllowAll, blacklist, and label-selector modes. Owned namespaces removed; original ClusterRole and ClusterRoleBinding state restored."
