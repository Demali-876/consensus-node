#!/usr/bin/env bash
set -euo pipefail

homebrew_install_url="https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
non_interactive=0
min_pm2_version="${CONSENSUS_MIN_PM2_VERSION:-5.0.0}"

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

detect_brew() {
  if command_exists brew; then
    command -v brew
    return 0
  fi

  for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

detect_pm2() {
  if command_exists pm2; then
    command -v pm2
    return 0
  fi

  for candidate in /opt/homebrew/bin/pm2 /usr/local/bin/pm2; do
    if [[ -x "${candidate}" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  return 1
}

pm2_version() {
  "$1" --version 2>/dev/null | awk '/^[0-9]+([.][0-9]+)+$/ { version=$0 } END { print version }'
}

bash_supports_wait_n() {
  local bash_path="$1"
  [[ -x "${bash_path}" ]] || return 1
  local version
  version="$("${bash_path}" -c 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.0"' 2>/dev/null || true)"
  [[ -n "${version}" ]] && semver_ge "${version}" "4.3.0"
}

load_brew_shellenv() {
  local brew_path="$1"
  eval "$("${brew_path}" shellenv)"
}

persist_brew_shellenv() {
  local brew_path="$1"
  local shellenv_line="eval \"\$(${brew_path} shellenv)\""
  local profile="${HOME}/.zprofile"

  touch "${profile}"
  if ! grep -Fq "${shellenv_line}" "${profile}"; then
    {
      echo
      echo "${shellenv_line}"
    } >> "${profile}"
  fi
}

ensure_homebrew_on_macos() {
  local brew_path
  if brew_path="$(detect_brew)"; then
    load_brew_shellenv "${brew_path}"
    persist_brew_shellenv "${brew_path}"
    return 0
  fi

  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "npm is not available. Install Node.js/npm for this OS, then rerun this script." >&2
    exit 69
  fi

  if ! command_exists curl; then
    echo "Homebrew is missing, and curl is required to install it." >&2
    exit 69
  fi

  echo "Homebrew is not installed. Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL "${homebrew_install_url}")"

  if ! brew_path="$(detect_brew)"; then
    echo "Homebrew installation completed, but brew was not found on PATH or in standard locations." >&2
    exit 69
  fi

  load_brew_shellenv "${brew_path}"
  persist_brew_shellenv "${brew_path}"
}

ensure_modern_bash_on_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return 0
  fi

  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash /usr/bin/bash /bin/bash; do
    if bash_supports_wait_n "${candidate}"; then
      return 0
    fi
  done

  ensure_homebrew_on_macos
  echo "Installing modern bash for PM2 supervision..."
  brew install bash || brew upgrade bash

  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if bash_supports_wait_n "${candidate}"; then
      return 0
    fi
  done

  echo "Modern bash installation completed, but bash >= 4.3 was not found." >&2
  exit 69
}

ensure_npm() {
  if command_exists npm; then
    return 0
  fi

  ensure_homebrew_on_macos

  if command_exists npm; then
    return 0
  fi

  echo "Node.js/npm is not installed. Installing Node.js with Homebrew..."
  brew install node

  if ! command_exists npm; then
    echo "Node.js installation completed, but npm is still not available." >&2
    exit 69
  fi
}

ensure_modern_bash_on_macos

if pm2_path="$(detect_pm2)"; then
  version="$(pm2_version "${pm2_path}")"
  if [[ -n "${version}" ]] && semver_ge "${version}" "${min_pm2_version}"; then
    echo "${version}"
    exit 0
  fi

  echo "PM2 ${version:-unknown} is below required ${min_pm2_version}. Updating PM2..."
  ensure_npm
  npm install -g pm2@latest
  if ! pm2_path="$(detect_pm2)"; then
    echo "PM2 update completed, but pm2 was not found on PATH or in standard locations." >&2
    exit 69
  fi
  version="$(pm2_version "${pm2_path}")"
  if [[ -z "${version}" ]] || ! semver_ge "${version}" "${min_pm2_version}"; then
    echo "PM2 ${version:-unknown} is still below required ${min_pm2_version} after update." >&2
    exit 69
  fi
  echo "${version}"
  exit 0
fi

ensure_npm
if pm2_path="$(detect_pm2)"; then
  version="$(pm2_version "${pm2_path}")"
  if [[ -n "${version}" ]] && semver_ge "${version}" "${min_pm2_version}"; then
    echo "${version}"
    exit 0
  fi
  echo "PM2 ${version:-unknown} is below required ${min_pm2_version}. Updating PM2..."
  npm install -g pm2@latest
  if ! pm2_path="$(detect_pm2)"; then
    echo "PM2 update completed, but pm2 was not found on PATH or in standard locations." >&2
    exit 69
  fi
  version="$(pm2_version "${pm2_path}")"
  if [[ -n "${version}" ]] && semver_ge "${version}" "${min_pm2_version}"; then
    echo "${version}"
    exit 0
  fi
  echo "PM2 ${version:-unknown} is still below required ${min_pm2_version} after update." >&2
  exit 69
fi

npm install -g pm2@latest
if ! pm2_path="$(detect_pm2)"; then
  echo "PM2 installation completed, but pm2 was not found on PATH or in standard locations." >&2
  exit 69
fi
version="$(pm2_version "${pm2_path}")"
if [[ -z "${version}" ]] || ! semver_ge "${version}" "${min_pm2_version}"; then
  echo "PM2 ${version:-unknown} is below required ${min_pm2_version} after installation." >&2
  exit 69
fi

echo "${version}"
