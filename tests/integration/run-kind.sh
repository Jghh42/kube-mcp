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
port_forward_pid=
keycloak_port_forward_pid=
defaults_need_restore=false

cleanup() {
  for pid in "$port_forward_pid" "$keycloak_port_forward_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [[ "$defaults_need_restore" == "true" ]]; then
    kubectl apply --filename "$deployment_manifest" >/dev/null 2>&1 || true
    kubectl set env deployment/kube-mcp --namespace kube-mcp \
      KubeMcp__ResourcePolicy__Mode- \
      KubeMcp__NamespacePolicy__Mode- \
      KubeMcp__NamespacePolicy__LabelSelector- >/dev/null 2>&1 || true
  fi
  rm -f "$port_forward_log" "$keycloak_port_forward_log" "$deployment_manifest"
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
  -e "s|value: None|value: OAuthClientCredentials|" \
  -e "/            - name: KubeMcp__SecretHmacKey/i\            - name: KubeMcp__Authentication__OAuth__Authority\n              value: http://keycloak.kube-mcp.svc.cluster.local:8080/realms/kube-mcp\n            - name: KubeMcp__Authentication__OAuth__Audience\n              value: k-mcp\n            - name: KubeMcp__Authentication__OAuth__RequiredScopes__0\n              value: k-mcp:read\n            - name: KubeMcp__Authentication__OAuth__RequiredRoles__0\n              value: k-mcp:read\n            - name: KubeMcp__Authentication__OAuth__RequireHttpsMetadata\n              value: \"false\"" \
  deployment.yaml >"$deployment_manifest"
grep -Fq "image: $test_image" "$deployment_manifest" || {
  echo "failed to replace the published image in the integration manifest" >&2
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

access_token=$(request_token kube-mcp-e2e stage-five-e2e-client-secret)
wrong_audience_token=$(request_token kube-mcp-wrong-audience stage-five-wrong-audience-secret)
missing_permission_token=$(request_token kube-mcp-missing-permission stage-five-missing-permission-secret)

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
KUBE_MCP_INTEGRATION_ACCESS_TOKEN="$access_token" \
KUBE_MCP_INTEGRATION_WRONG_AUDIENCE_TOKEN="$wrong_audience_token" \
KUBE_MCP_INTEGRATION_MISSING_PERMISSION_TOKEN="$missing_permission_token" \
  dotnet test KubeMcp.slnx \
    --configuration Release \
    --filter 'FullyQualifiedName~KindIntegrationTests' \
    --logger 'console;verbosity=normal'

audit_logs=$(kubectl logs deployment/kube-mcp --namespace kube-mcp)
grep -Fq 'Kubernetes audit:' <<<"$audit_logs"
grep -Fq 'client=kube-mcp-e2e authentication=OAuthClientCredentials' <<<"$audit_logs"
grep -Fq 'operation=GET resource=secrets namespace=kube-mcp-e2e name=integration-secret result=success objectCount=1' <<<"$audit_logs"
! grep -Fq "$secret_value" <<<"$audit_logs"
! grep -Fq 'annotation-must-not-leak' <<<"$audit_logs"

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
KUBE_MCP_INTEGRATION_ACCESS_TOKEN="$access_token" \
KUBE_MCP_INTEGRATION_WRONG_AUDIENCE_TOKEN="$wrong_audience_token" \
KUBE_MCP_INTEGRATION_MISSING_PERMISSION_TOKEN="$missing_permission_token" \
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
KUBE_MCP_INTEGRATION_ACCESS_TOKEN="$access_token" \
KUBE_MCP_INTEGRATION_WRONG_AUDIENCE_TOKEN="$wrong_audience_token" \
KUBE_MCP_INTEGRATION_MISSING_PERMISSION_TOKEN="$missing_permission_token" \
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

echo "Stage 6 integration tests passed for audit logging, authentication, allowlist, AllowAll, blacklist, and label-selector modes. kube-mcp and local Keycloak remain running with narrow resource defaults."
