#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

cluster_name=${KIND_CLUSTER_NAME:-kind}
local_port=${KUBE_MCP_TEST_PORT:-18082}
fixture_namespace=kube-mcp-e2e
test_image=kube-mcp:stage4-test
port_forward_log=$(mktemp)
deployment_manifest=$(mktemp)
port_forward_pid=
defaults_need_restore=false

cleanup() {
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  if [[ "$defaults_need_restore" == "true" ]]; then
    kubectl apply --filename "$deployment_manifest" >/dev/null 2>&1 || true
    kubectl set env deployment/kube-mcp --namespace kube-mcp \
      KubeMcp__ResourcePolicy__Mode- \
      KubeMcp__NamespacePolicy__Mode- \
      KubeMcp__NamespacePolicy__LabelSelector- >/dev/null 2>&1 || true
  fi
  rm -f "$port_forward_log" "$deployment_manifest"
  kubectl delete namespace "$fixture_namespace" --ignore-not-found --wait=false >/dev/null
}
trap cleanup EXIT

kind get clusters | grep -Fxq "$cluster_name" || {
  echo "kind cluster '$cluster_name' does not exist" >&2
  exit 1
}

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

echo "Building $test_image..."
docker build --tag "$test_image" .
kind load docker-image "$test_image" --name "$cluster_name"

sed \
  -e "s|image: ghcr.io/jghh42/kube-mcp:latest|image: $test_image|" \
  -e "s|imagePullPolicy: Always|imagePullPolicy: IfNotPresent|" \
  deployment.yaml >"$deployment_manifest"
grep -Fq "image: $test_image" "$deployment_manifest" || {
  echo "failed to replace the published image in the integration manifest" >&2
  exit 1
}

kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f - >/dev/null
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

start_port_forward

echo "Running MCP-to-kind integration tests..."
KUBE_MCP_INTEGRATION_ENDPOINT="http://127.0.0.1:$local_port/mcp" \
  dotnet test KubeMcp.slnx \
    --configuration Release \
    --filter 'FullyQualifiedName~KindIntegrationTests' \
    --logger 'console;verbosity=normal'

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

echo "Running label-selector namespace policy integration tests..."
KUBE_MCP_INTEGRATION_ENDPOINT="http://127.0.0.1:$local_port/mcp" \
KUBE_MCP_NAMESPACE_POLICY_MODE=LabelSelector \
  dotnet test KubeMcp.slnx \
    --configuration Release \
    --filter 'FullyQualifiedName~KindIntegrationTests' \
    --logger 'console;verbosity=normal'

kill "$port_forward_pid" 2>/dev/null || true
wait "$port_forward_pid" 2>/dev/null || true
port_forward_pid=

defaults_need_restore=true
kubectl apply --filename deployment-allow-all-rbac.yaml >/dev/null
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__ResourcePolicy__Mode=AllowAll >/dev/null
kubectl rollout status deployment/kube-mcp --namespace kube-mcp --timeout=120s
start_port_forward

echo "Running AllowAll resource policy integration tests..."
KUBE_MCP_INTEGRATION_ENDPOINT="http://127.0.0.1:$local_port/mcp" \
KUBE_MCP_NAMESPACE_POLICY_MODE=LabelSelector \
KUBE_MCP_RESOURCE_POLICY_MODE=AllowAll \
  dotnet test KubeMcp.slnx \
    --configuration Release \
    --filter 'FullyQualifiedName~KindIntegrationTests' \
    --logger 'console;verbosity=normal'

kubectl apply --filename "$deployment_manifest" >/dev/null
kubectl set env deployment/kube-mcp --namespace kube-mcp \
  KubeMcp__ResourcePolicy__Mode- \
  KubeMcp__NamespacePolicy__Mode- \
  KubeMcp__NamespacePolicy__LabelSelector- >/dev/null
kubectl rollout status deployment/kube-mcp --namespace kube-mcp --timeout=120s
defaults_need_restore=false
[[ $(kubectl auth can-i list roles --namespace kube-mcp --as "$service_account") == "no" ]]
kubectl label namespace kube-mcp kube-mcp.io/agent-access- >/dev/null

echo "Stage 4 integration tests passed for allowlist, AllowAll, blacklist, and label-selector modes. kube-mcp remains running with narrow defaults."
