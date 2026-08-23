#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

cluster_name=${KIND_CLUSTER_NAME:-kind}
local_port=${KUBE_MCP_TEST_PORT:-18082}
fixture_namespace=kube-mcp-e2e
test_image=kube-mcp:stage3-test
port_forward_log=$(mktemp)
deployment_manifest=$(mktemp)
port_forward_pid=

cleanup() {
  if [[ -n "$port_forward_pid" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  rm -f "$port_forward_log" "$deployment_manifest"
  kubectl delete namespace "$fixture_namespace" --ignore-not-found --wait=false >/dev/null
}
trap cleanup EXIT

kind get clusters | grep -Fxq "$cluster_name" || {
  echo "kind cluster '$cluster_name' does not exist" >&2
  exit 1
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

echo "Stage 3 integration tests passed. kube-mcp remains running in kind."
