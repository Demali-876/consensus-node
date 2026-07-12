#!/usr/bin/env bash
set -euo pipefail

non_interactive=0
min_bun_version="${CONSENSUS_MIN_BUN_VERSION:-1.3.0}"

for arg in "$@"; do
  case "${arg}" in
    --yes|--non-interactive)
      non_interactive=1
      ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 64
      ;;
  esac
done

if [[ "${non_interactive}" == "1" ]]; then
  export CI=1
  export NONINTERACTIVE=1
fi

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

semver_ge() {
  local version="${1%%[-+]*}"
  local minimum="${2%%[-+]*}"
  local v_major v_minor v_patch m_major m_minor m_patch
  IFS=. read -r v_major v_minor v_patch <<< "${version}"
  IFS=. read -r m_major m_minor m_patch <<< "${minimum}"
  v_major="${v_major:-0}"; v_minor="${v_minor:-0}"; v_patch="${v_patch:-0}"
  m_major="${m_major:-0}"; m_minor="${m_minor:-0}"; m_patch="${m_patch:-0}"
  (( v_major > m_major )) && return 0
  (( v_major < m_major )) && return 1
  (( v_minor > m_minor )) && return 0
  (( v_minor < m_minor )) && return 1
  (( v_patch >= m_patch ))
}

detect_bun() {
  if command_exists bun; then
    command -v bun
    return 0
  fi

  for candidate in "${HOME}/.bun/bin/bun" /opt/homebrew/bin/bun /usr/local/bin/bun; do
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

persist_bun_path() {
  local profile="${HOME}/.zprofile"
  local bun_line='export BUN_INSTALL="$HOME/.bun"'
  local path_line='export PATH="$BUN_INSTALL/bin:$PATH"'

  touch "${profile}"
  if ! grep -Fq "${bun_line}" "${profile}"; then
    {
      echo
      echo "${bun_line}"
    } >> "${profile}"
  fi
  if ! grep -Fq "${path_line}" "${profile}"; then
    echo "${path_line}" >> "${profile}"
  fi
}

bun_version() {
  "$1" --version | head -n 1 | tr -d '[:space:]'
}

upgrade_bun() {
  local bun_path="$1"
  echo "Updating Bun to satisfy required version >= ${min_bun_version}..."
  "${bun_path}" upgrade || true

  if bun_path="$(detect_bun)"; then
    local version
    version="$(bun_version "${bun_path}")"
    if semver_ge "${version}" "${min_bun_version}"; then
      echo "${version}"
      return 0
    fi
  fi

  if ! command_exists curl; then
    echo "curl is required to update Bun." >&2
    return 1
  fi

  /bin/bash -c "$(curl -fsSL https://bun.sh/install)"
}

if bun_path="$(detect_bun)"; then
  if [[ "${bun_path}" == "${HOME}/.bun/bin/bun" ]]; then
    persist_bun_path
  fi
  version="$(bun_version "${bun_path}")"
  if semver_ge "${version}" "${min_bun_version}"; then
    echo "${version}"
    exit 0
  fi

  echo "Bun ${version} is below required ${min_bun_version}."
  upgrade_bun "${bun_path}"
  if ! bun_path="$(detect_bun)"; then
    echo "Bun update completed, but bun was not found on PATH or in standard locations." >&2
    exit 69
  fi
  if [[ "${bun_path}" == "${HOME}/.bun/bin/bun" ]]; then
    persist_bun_path
  fi
  version="$(bun_version "${bun_path}")"
  if ! semver_ge "${version}" "${min_bun_version}"; then
    echo "Bun ${version} is still below required ${min_bun_version} after update." >&2
    exit 69
  fi
  echo "${version}"
  exit 0
fi

if ! command_exists curl; then
  echo "curl is required to install Bun." >&2
  exit 69
fi

export BUN_INSTALL="${BUN_INSTALL:-${HOME}/.bun}"
echo "Bun is not installed. Installing Bun..."
/bin/bash -c "$(curl -fsSL https://bun.sh/install)"
persist_bun_path

if ! bun_path="$(detect_bun)"; then
  echo "Bun installation completed, but bun was not found on PATH or in standard locations." >&2
  exit 69
fi

version="$(bun_version "${bun_path}")"
if ! semver_ge "${version}" "${min_bun_version}"; then
  echo "Bun ${version} is below required ${min_bun_version} after installation." >&2
  exit 69
fi

echo "${version}"
