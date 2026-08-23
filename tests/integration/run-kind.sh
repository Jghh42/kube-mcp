#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

cluster_name=${KIND_CLUSTER_NAME:-kind}
local_port=${KUBE_MCP_TEST_PORT:-18082}
fixture_namespace=kube-mcp-e2e
port_forward_log=$(mktemp)
port_forward_pid=

cleanup() {
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  rm -f "$port_forward_log"
  kubectl delete namespace "$fixture_namespace" --ignore-not-found --wait=false >/dev/null
}
trap cleanup EXIT

kind get clusters | grep -Fxq "$cluster_name" || {
  echo "kind cluster '$cluster_name' does not exist" >&2
  exit 1
}

echo "Building kube-mcp:stage2..."
docker build --tag kube-mcp:stage2 .
kind load docker-image kube-mcp:stage2 --name "$cluster_name"

kubectl create namespace kube-mcp --dry-run=client -o yaml | kubectl apply -f - >/dev/null
hmac_key=$(openssl rand -base64 32)
kubectl create secret generic kube-mcp-hmac \
  --namespace kube-mcp \
  --from-literal="key=$hmac_key" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl apply --filename deployment.yaml >/dev/null
kubectl rollout restart deployment/kube-mcp --namespace kube-mcp >/dev/null
kubectl rollout status deployment/kube-mcp --namespace kube-mcp --timeout=120s

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

kubectl port-forward --namespace kube-mcp service/kube-mcp "$local_port:80" \
  >"$port_forward_log" 2>&1 &
port_forward_pid=$!

for _ in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:$local_port/readyz" >/dev/null; then
    break
  fi
  if ! kill -0 "$port_forward_pid" 2>/dev/null; then
    cat "$port_forward_log" >&2
    exit 1
  fi
  sleep 1
done
curl --fail --silent "http://127.0.0.1:$local_port/readyz" >/dev/null

echo "Running MCP-to-kind integration tests..."
KUBE_MCP_INTEGRATION_ENDPOINT="http://127.0.0.1:$local_port/mcp" \
  dotnet test KubeMcp.slnx \
    --configuration Release \
    --filter 'FullyQualifiedName~KindIntegrationTests' \
    --logger 'console;verbosity=normal'

echo "Stage 2 integration tests passed. kube-mcp remains running in kind."
