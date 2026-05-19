#!/usr/bin/env bash
set -euo pipefail

homebrew_install_url="https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"

command_exists() {
  command -v "$1" >/dev/null 2>&1
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

if command -v pm2 >/dev/null 2>&1; then
  pm2 --version
  exit 0
fi

ensure_npm
if command_exists pm2; then
  pm2 --version
  exit 0
fi

npm install -g pm2
pm2 --version
