#!/usr/bin/env bash
#
# Operate the Consensus node boot service on macOS.
#
#   sudo scripts/node-service.sh restart   # restart, then wait for the node to serve
#   sudo scripts/node-service.sh status
#   sudo scripts/node-service.sh start|stop
#        scripts/node-service.sh ping      # ask the orchestrator if this node is live
#        scripts/node-service.sh logs
#
# `restart` is the useful one: it relaunches the unit and then waits for the
# ORCHESTRATOR to report this node active again. A live pid only says the unit
# relaunched; only the orchestrator confirms the node reconnected and is serving.
#
# There is deliberately no "prove it started before login" command. Whether a given
# start happened pre- or post-login is not something this machine can report
# reliably after the fact, so the test that earns its keep is operational: restart
# it and confirm the node comes back and serves.
#
# On Linux, use systemctl against systemd/consensus-node.service instead.
#
set -uo pipefail

LABEL="com.consensus.node"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SERVICE="system/${LABEL}"

ONLINE_TIMEOUT_SECONDS="${CONSENSUS_ONLINE_TIMEOUT_SECONDS:-90}"
DEFAULT_SERVER_URL="https://consensus.canister.software"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This needs root (it talks to launchd's system domain):" >&2
    echo "  sudo $0 $1" >&2
    exit 77
  fi
}

service_pid() {
  launchctl print "${SERVICE}" 2>/dev/null | sed -n 's/^[[:space:]]*pid = \([0-9]*\).*/\1/p' | head -1
}

state_dir_from_plist() {
  [[ -f "${PLIST}" ]] || return 1
  /usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:CONSENSUS_STATE_DIR" "${PLIST}" 2>/dev/null
}

server_url_from_plist() {
  [[ -f "${PLIST}" ]] || { echo "${DEFAULT_SERVER_URL}"; return; }
  /usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:CONSENSUS_SERVER_URL" "${PLIST}" 2>/dev/null \
    || echo "${DEFAULT_SERVER_URL}"
}

node_id_from_state() {
  local state_dir; state_dir="$(state_dir_from_plist)" || state_dir="${HOME}/.consensus/node"
  [[ -f "${state_dir}/config.json" ]] || return 1
  /usr/bin/python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('node_id') or '')" \
    "${state_dir}/config.json" 2>/dev/null
}

# The signal that matters: does the orchestrator consider this node live?
orchestrator_status() {
  local node_id server
  node_id="$(node_id_from_state)" || return 1
  [[ -n "${node_id}" ]] || return 1
  server="$(server_url_from_plist)"
  curl -fsS --max-time 10 "${server}/node/status/${node_id}" 2>/dev/null \
    | /usr/bin/python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null
}

wait_until_online() {
  local deadline=$(( $(date +%s) + ONLINE_TIMEOUT_SECONDS )) status=""
  echo "Waiting for the orchestrator to report this node active (up to ${ONLINE_TIMEOUT_SECONDS}s)..."
  while (( $(date +%s) < deadline )); do
    status="$(orchestrator_status)" || status=""
    if [[ "${status}" == "active" ]]; then
      green "  orchestrator reports: active — the node reconnected and is serving"
      return 0
    fi
    sleep 5
  done
  warn "  orchestrator did not report 'active' within ${ONLINE_TIMEOUT_SECONDS}s (last: ${status:-unreachable})"
  echo "  Check the logs: scripts/node-service.sh logs"
  return 1
}

cmd_status() {
  need_root status
  if [[ ! -f "${PLIST}" ]]; then
    red "not installed — ${PLIST} is missing"
    echo "This node will NOT come back after a reboot until someone logs in."
    echo "Install the boot service with: sudo scripts/install-launchd.sh"
    return 1
  fi
  echo "plist: ${PLIST}"
  local pid; pid="$(service_pid)"
  if [[ -z "${pid}" || "${pid}" == "0" ]]; then
    red "state: NOT RUNNING"
    launchctl print "${SERVICE}" 2>/dev/null | grep -E "last exit|state = " | sed 's/^[[:space:]]*/       /'
    return 1
  fi
  green "state: running (pid ${pid})"
  local started; started="$(ps -o lstart= -p "${pid}" 2>/dev/null | sed 's/  */ /g;s/^ *//;s/ *$//')"
  [[ -n "${started}" ]] && echo "since: ${started}"
  local remote; remote="$(orchestrator_status)" || remote=""
  if [[ "${remote}" == "active" ]]; then
    green "node:  active on the orchestrator"
  elif [[ -n "${remote}" ]]; then
    warn "node:  orchestrator reports '${remote}'"
  else
    warn "node:  could not reach the orchestrator (or no node_id in state)"
  fi
}

cmd_restart() {
  need_root restart
  [[ -f "${PLIST}" ]] || { red "not installed — run sudo scripts/install-launchd.sh"; exit 1; }
  echo "Restarting ${SERVICE}..."
  # kickstart -k kills the running instance and starts a fresh one — the same thing
  # launchd does on a crash.
  launchctl kickstart -k "${SERVICE}" || { red "kickstart failed"; exit 1; }
  sleep 2
  local pid; pid="$(service_pid)"
  if [[ -z "${pid}" || "${pid}" == "0" ]]; then
    red "unit did not come back up"
    exit 1
  fi
  green "unit relaunched (pid ${pid})"
  echo
  wait_until_online
}

cmd_start() { need_root start; launchctl bootstrap system "${PLIST}" && launchctl enable "${SERVICE}" && cmd_status; }
cmd_stop()  { need_root stop;  launchctl bootout "${SERVICE}" && echo "stopped"; }

cmd_ping() {
  local status; status="$(orchestrator_status)" || status=""
  if [[ "${status}" == "active" ]]; then
    green "active — the orchestrator sees this node"
    return 0
  fi
  if [[ -n "${status}" ]]; then
    warn "orchestrator reports '${status}'"
    return 1
  fi
  red "could not reach the orchestrator, or no node_id in state"
  return 1
}

cmd_logs() {
  local state_dir; state_dir="$(state_dir_from_plist)" || state_dir="${HOME}/.consensus/node"
  echo "following ${state_dir} logs (ctrl-c to stop)"
  tail -f "${state_dir}/launchd.err.log" "${state_dir}/launchd.out.log"
}

case "${1:-}" in
  status)  cmd_status ;;
  restart) cmd_restart ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  ping)    cmd_ping ;;
  logs)    cmd_logs ;;
  *)
    echo "Usage: $0 <restart|status|start|stop|ping|logs>" >&2
    echo >&2
    echo "  restart  relaunch the unit, then wait for the orchestrator to see it active" >&2
    echo "  ping     ask the orchestrator whether this node is live" >&2
    exit 64
    ;;
esac
