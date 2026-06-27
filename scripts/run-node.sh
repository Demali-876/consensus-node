#!/usr/bin/env bash
#
# Supervised node unit — runs BOTH the runtime server (the inbound /connect
# data-plane endpoint on :NODE_PORT) and the outbound control tunnel as one unit.
#
# Background: the direct data plane needs the runtime server reachable, but the
# production supervisor historically ran only the control tunnel (run-control.sh),
# so /connect was never served. Running both here means a single PM2/systemd unit
# covers both, and one restart refreshes both from the updated `current` symlink.
#
# The unit exits as soon as EITHER child exits: the control tunnel exits on
# `update_apply` (so the whole unit restarts onto the new release), and a crash of
# either child cycles the unit too. Requires bash >= 4.3 (wait -n); production nodes
# run Linux, so that's fine.
set -uo pipefail

# `wait -n` (wake on the first child to exit) needs bash >= 4.3. That's universal on
# Linux (all production nodes); on macOS install a modern bash (brew install bash) and
# ensure it's first on PATH. Fail loudly rather than misbehave on the stock 3.2.
if [[ -z "${BASH_VERSINFO:-}" || ${BASH_VERSINFO[0]} -lt 4 || ( ${BASH_VERSINFO[0]} -eq 4 && ${BASH_VERSINFO[1]} -lt 3 ) ]]; then
  echo "run-node.sh requires bash >= 4.3 (have ${BASH_VERSION:-unknown}); on macOS: brew install bash" >&2
  exit 78
fi

install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"$HOME/.consensus/node-runtime"}"
state_dir="${CONSENSUS_STATE_DIR:-"$HOME/.consensus/node"}"
server_url="${CONSENSUS_SERVER_URL:-"https://consensus.canister.software"}"

export CONSENSUS_STATE_DIR="${state_dir}"
export CONSENSUS_SERVER_URL="${server_url}"
export CONSENSUS_NODE_INSTALL_DIR="${install_dir}"
export CONSENSUS_NODE_UPDATE_COMMAND="${CONSENSUS_NODE_UPDATE_COMMAND:-"${install_dir}/current/scripts/install-release.sh"}"

current="${install_dir}/current"
if [[ ! -d "${current}" ]]; then
  echo "No installed release at ${current}" >&2
  exit 70
fi

cd "${current}"

# Inbound: runtime server hosting /connect. Outbound: control tunnel.
bun run start   & runtime_pid=$!
bun run control & control_pid=$!

shutdown() {
  trap - EXIT INT TERM
  kill "${runtime_pid}" "${control_pid}" 2>/dev/null || true
  wait "${runtime_pid}" "${control_pid}" 2>/dev/null || true
}
trap shutdown EXIT INT TERM

# Block until whichever child exits first; its code becomes the unit's exit code so
# the supervisor restarts everything from the refreshed `current`.
wait -n
code=$?

shutdown
exit "${code}"
