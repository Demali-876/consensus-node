#!/usr/bin/env bash
set -euo pipefail

install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"$HOME/.consensus/node-runtime"}"
current="${install_dir}/current"

if [[ ! -d "${current}" ]]; then
  echo "No installed release at ${current}" >&2
  exit 70
fi

cd "${current}"
exec bun run control
