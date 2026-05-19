#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
release_dir="$(cd -- "${script_dir}/.." && pwd)"

install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"$HOME/.consensus/node-runtime"}"
state_dir="${CONSENSUS_STATE_DIR:-"$HOME/.consensus/node"}"
server_url="${CONSENSUS_SERVER_URL:-"https://consensus.canister.software"}"
pm2_name="${CONSENSUS_PM2_NAME:-"consensus-node-control"}"
config="${CONSENSUS_PM2_CONFIG:-"${release_dir}/ecosystem.config.cjs"}"
release_retention="${CONSENSUS_NODE_RELEASE_RETENTION:-3}"

"${script_dir}/ensure-pm2.sh"

for brew_path in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if [[ -x "${brew_path}" ]]; then
    eval "$("${brew_path}" shellenv)"
    break
  fi
done

pm2_bin="$(command -v pm2 || true)"
if [[ -z "${pm2_bin}" ]]; then
  for candidate in /opt/homebrew/bin/pm2 /usr/local/bin/pm2; do
    if [[ -x "${candidate}" ]]; then
      pm2_bin="${candidate}"
      break
    fi
  done
fi

if [[ -z "${pm2_bin}" ]]; then
  echo "PM2 was installed, but pm2 is not available on PATH or in standard Homebrew locations." >&2
  exit 69
fi

if [[ ! -d "${install_dir}/current" ]]; then
  echo "No installed release at ${install_dir}/current" >&2
  exit 70
fi

if [[ ! -f "${config}" ]]; then
  echo "PM2 config not found: ${config}" >&2
  exit 66
fi

mkdir -p "${state_dir}"

export CONSENSUS_NODE_INSTALL_DIR="${install_dir}"
export CONSENSUS_STATE_DIR="${state_dir}"
export CONSENSUS_SERVER_URL="${server_url}"
export CONSENSUS_PM2_NAME="${pm2_name}"
export CONSENSUS_NODE_RELEASE_RETENTION="${release_retention}"
export CONSENSUS_NODE_UPDATE_COMMAND="${CONSENSUS_NODE_UPDATE_COMMAND:-"${install_dir}/current/scripts/install-release.sh"}"

"${pm2_bin}" startOrReload "${config}" --only "${pm2_name}" --update-env
"${pm2_bin}" save

echo "PM2 is managing ${pm2_name}."
echo "Logs: pm2 logs ${pm2_name}"
echo "Reboot persistence: run 'pm2 startup', follow its printed command, then run 'pm2 save'."
