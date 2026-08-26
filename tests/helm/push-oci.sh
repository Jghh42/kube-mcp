#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

registry_image=registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e
container_name=kube-mcp-helm-registry-$$
registry_port=${KUBE_MCP_HELM_REGISTRY_PORT:-5000}
version=0.0.0-ci.1
tmp_dir=$(mktemp -d)
cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

docker run --detach --rm \
  --name "$container_name" \
  --publish "127.0.0.1:${registry_port}:5000" \
  "$registry_image" >/dev/null
curl --fail --silent --show-error \
  --retry 10 \
  --retry-all-errors \
  --retry-connrefused \
  --retry-delay 1 \
  "http://127.0.0.1:${registry_port}/v2/" >/dev/null

helm package charts/kube-mcp \
  --version "$version" \
  --app-version "$version" \
  --destination "$tmp_dir" >/dev/null
push_output=$(helm push "$tmp_dir/kube-mcp-${version}.tgz" \
  "oci://127.0.0.1:${registry_port}/charts" \
  --plain-http 2>&1)
printf '%s\n' "$push_output"
grep -E '^Digest: sha256:[0-9a-f]{64}$' <<<"$push_output" >/dev/null

helm show chart "oci://127.0.0.1:${registry_port}/charts/kube-mcp" \
  --version "$version" \
  --plain-http >"$tmp_dir/published-chart.yaml"
grep -F "version: $version" "$tmp_dir/published-chart.yaml" >/dev/null
grep -F "appVersion: $version" "$tmp_dir/published-chart.yaml" >/dev/null

echo 'Helm OCI push smoke test passed.'
