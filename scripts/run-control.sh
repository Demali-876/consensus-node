#!/usr/bin/env bash
set -euo pipefail

install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"$HOME/.consensus/node-runtime"}"
state_dir="${CONSENSUS_STATE_DIR:-"$HOME/.consensus/node"}"
server_url="${CONSENSUS_SERVER_URL:-"https://consensus.canister.software"}"

export CONSENSUS_STATE_DIR="${state_dir}"
export CONSENSUS_SERVER_URL="${server_url}"
export CONSENSUS_NODE_INSTALL_DIR="${install_dir}"
export CONSENSUS_NODE_UPDATE_COMMAND="${CONSENSUS_NODE_UPDATE_COMMAND:-"${install_dir}/current/scripts/install-release.sh"}"

while true; do
  current="${install_dir}/current"
  if [[ ! -d "${current}" ]]; then
    echo "No installed release at ${current}" >&2
    exit 70
  fi

  cd "${current}"
  bun run control
  code=$?

  if [[ "${code}" == "75" ]]; then
    echo "Consensus node updated; restarting from ${install_dir}/current" >&2
    sleep 1
    continue
  fi

  exit "${code}"
done
