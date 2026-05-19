#!/usr/bin/env bash
set -euo pipefail

artifact="${CONSENSUS_NODE_ARTIFACT_PATH:-${1:-}}"
target_version="${CONSENSUS_NODE_TARGET_VERSION:-${2:-}}"
install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"$HOME/.consensus/node-runtime"}"
release_retention="${CONSENSUS_NODE_RELEASE_RETENTION:-3}"
running_release="$(pwd -P 2>/dev/null || true)"

if [[ -z "${artifact}" ]]; then
  echo "CONSENSUS_NODE_ARTIFACT_PATH or first argument is required" >&2
  exit 64
fi

if [[ ! -f "${artifact}" ]]; then
  echo "Artifact not found: ${artifact}" >&2
  exit 66
fi

if ! [[ "${release_retention}" =~ ^[0-9]+$ ]] || (( release_retention < 1 )); then
  echo "CONSENSUS_NODE_RELEASE_RETENTION must be an integer greater than 0" >&2
  exit 64
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

cleanup_old_releases() {
  local releases_dir="${install_dir}/releases"
  local current_real
  current_real="$(cd -P "${install_dir}/current" && pwd)"

  local kept=0
  local candidate
  while IFS= read -r candidate; do
    [[ -d "${candidate}" ]] || continue

    local candidate_real
    candidate_real="$(cd -P "${candidate}" && pwd)"
    if [[ "${candidate_real}" == "${current_real}" || "${candidate_real}" == "${running_release}" ]]; then
      kept=$((kept + 1))
      continue
    fi

    if (( kept < release_retention )); then
      kept=$((kept + 1))
      continue
    fi

    rm -rf -- "${candidate}"
    echo "Removed old consensus-node release ${candidate}"
  done < <(ls -1dt "${releases_dir}"/* 2>/dev/null || true)
}

cleanup_old_releases

echo "Installed consensus-node ${version} at ${release_dir}"
