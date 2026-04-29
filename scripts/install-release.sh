#!/usr/bin/env bash
set -euo pipefail

artifact="${CONSENSUS_NODE_ARTIFACT_PATH:-${1:-}}"
target_version="${CONSENSUS_NODE_TARGET_VERSION:-${2:-}}"
install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"$HOME/.consensus/node-runtime"}"

if [[ -z "${artifact}" ]]; then
  echo "CONSENSUS_NODE_ARTIFACT_PATH or first argument is required" >&2
  exit 64
fi

if [[ ! -f "${artifact}" ]]; then
  echo "Artifact not found: ${artifact}" >&2
  exit 66
fi

mkdir -p "${install_dir}/releases"

tmp_dir="$(mktemp -d "${install_dir}/.install.XXXXXX")"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

tar -xzf "${artifact}" -C "${tmp_dir}"
release_root="${tmp_dir}/consensus-node"
if [[ ! -f "${release_root}/package.json" ]]; then
  echo "Artifact does not contain consensus-node/package.json" >&2
  exit 65
fi

version="$(bun -e "console.log(require('${release_root}/package.json').version)")"
if [[ -n "${target_version}" && "${version}" != "${target_version}" ]]; then
  echo "Artifact version mismatch: expected ${target_version}, got ${version}" >&2
  exit 65
fi

release_id="${version}-$(date -u +%Y%m%d%H%M%S)"
release_dir="${install_dir}/releases/${release_id}"

mv "${release_root}" "${release_dir}"
(
  cd "${release_dir}"
  bun install --production --frozen-lockfile
)

ln -sfn "${release_dir}" "${install_dir}/current.next"
mv -Tf "${install_dir}/current.next" "${install_dir}/current" 2>/dev/null || {
  rm -f "${install_dir}/current"
  mv "${install_dir}/current.next" "${install_dir}/current"
}

echo "Installed consensus-node ${version} at ${release_dir}"
