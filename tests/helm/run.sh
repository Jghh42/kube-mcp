#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

chart=charts/kube-mcp
digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

expect_failure() {
  local expected=$1
  shift
  if helm template rejected "$chart" "$@" >"$tmp_dir/rejected.yaml" 2>"$tmp_dir/rejected.err"; then
    echo "Expected Helm rendering to fail: $*" >&2
    exit 1
  fi
  grep -F "$expected" "$tmp_dir/rejected.err" >/dev/null
}

helm lint "$chart" --set-string image.digest="$digest"
helm template kube-mcp "$chart" \
  --namespace kube-mcp \
  --set-string image.digest="$digest" >"$tmp_dir/production.yaml"

grep -F 'image: "ghcr.io/jghh42/kube-mcp@sha256:' "$tmp_dir/production.yaml" >/dev/null
grep -F 'value: "ApiKey"' "$tmp_dir/production.yaml" >/dev/null
grep -F 'resources: ["namespaces"]' "$tmp_dir/production.yaml" >/dev/null
grep -F 'verbs: ["list"]' "$tmp_dir/production.yaml" >/dev/null
grep -F 'readOnlyRootFilesystem: true' "$tmp_dir/production.yaml" >/dev/null
grep -F 'type: ClusterIP' "$tmp_dir/production.yaml" >/dev/null

helm template development "$chart" \
  --namespace development \
  --set dotnetEnvironment=Development \
  --set authentication.mode=None >"$tmp_dir/development.yaml"
grep -F 'value: "None"' "$tmp_dir/development.yaml" >/dev/null
if grep -F 'KubeMcp__Authentication__ApiKey' "$tmp_dir/development.yaml" >/dev/null; then
  echo 'Development None mode unexpectedly rendered an API-key reference' >&2
  exit 1
fi

expect_failure 'image.digest is required outside the Development environment'
expect_failure 'authentication.mode=None is permitted only when dotnetEnvironment=Development' \
  --set-string image.digest="$digest" \
  --set authentication.mode=None
expect_failure 'authentication.mode=None requires service.type=ClusterIP' \
  --set dotnetEnvironment=Development \
  --set authentication.mode=None \
  --set service.type=LoadBalancer
expect_failure 'serviceAccount.name is required when serviceAccount.create=false' \
  --set dotnetEnvironment=Development \
  --set serviceAccount.create=false
expect_failure "at '/allowedHosts/0': 'not' failed" \
  --set dotnetEnvironment=Development \
  --set-string 'allowedHosts[0]=*'
expect_failure 'podLabels must not override chart-managed selector label app.kubernetes.io/name' \
  --set dotnetEnvironment=Development \
  --set-string 'podLabels.app\.kubernetes\.io/name=unsafe'
expect_failure 'extraEnv must not override chart-managed variable allowedhosts' \
  --set dotnetEnvironment=Development \
  --set-string 'extraEnv[0].name=allowedhosts' \
  --set-string 'extraEnv[0].value=unsafe'

helm template quoted "$chart" \
  --namespace development \
  --set dotnetEnvironment=Development \
  --set-string authentication.apiKeySecret.name=true \
  --set-string authentication.apiKeySecret.key=null \
  --set-string secretHmacKeySecret.name=false \
  --set-string secretHmacKeySecret.key=yes >"$tmp_dir/quoted.yaml"
grep -F 'name: "true"' "$tmp_dir/quoted.yaml" >/dev/null
grep -F 'key: "null"' "$tmp_dir/quoted.yaml" >/dev/null
grep -F 'name: "false"' "$tmp_dir/quoted.yaml" >/dev/null
grep -F 'key: "yes"' "$tmp_dir/quoted.yaml" >/dev/null

for namespace in alpha beta; do
  helm template same-release "$chart" \
    --namespace "$namespace" \
    --set dotnetEnvironment=Development >"$tmp_dir/$namespace.yaml"
done
alpha_role=$(awk '$0 == "kind: ClusterRole" { role = 1; next } role && $1 == "name:" { print $2; exit }' "$tmp_dir/alpha.yaml")
beta_role=$(awk '$0 == "kind: ClusterRole" { role = 1; next } role && $1 == "name:" { print $2; exit }' "$tmp_dir/beta.yaml")
[[ -n "$alpha_role" && -n "$beta_role" && "$alpha_role" != "$beta_role" ]]

helm package "$chart" \
  --version 1.2.3 \
  --app-version 1.2.3 \
  --destination "$tmp_dir" >/dev/null
helm package "$chart" \
  --version 1.2.3-rc.1+build.1 \
  --app-version 1.2.3-rc.1+build.1 \
  --destination "$tmp_dir" >/dev/null
helm template packaged "$tmp_dir/kube-mcp-1.2.3-rc.1+build.1.tgz" \
  --namespace kube-mcp \
  --set-string image.digest="$digest" >"$tmp_dir/packaged.yaml"
grep -F 'app.kubernetes.io/version: "1.2.3-rc.1_build.1"' "$tmp_dir/packaged.yaml" >/dev/null

long_version="1.2.3-$(printf 'a%.0s' {1..56})-b"
helm package "$chart" \
  --version "$long_version" \
  --app-version "$long_version" \
  --destination "$tmp_dir" >/dev/null
helm template long-version "$tmp_dir/kube-mcp-${long_version}.tgz" \
  --namespace kube-mcp \
  --set-string image.digest="$digest" >"$tmp_dir/long-version.yaml"
for label in helm.sh/chart app.kubernetes.io/version; do
  value=$(awk -v label="$label" '$1 == label":" { gsub(/"/, "", $2); print $2; exit }' "$tmp_dir/long-version.yaml")
  [[ -n "$value" && ${#value} -le 63 && "$value" =~ ^[A-Za-z0-9].*[A-Za-z0-9]$ ]]
done

echo 'Helm chart validation passed.'
