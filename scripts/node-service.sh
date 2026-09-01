#!/usr/bin/env bash
#
# Operate and verify the Consensus node boot service on macOS.
#
#   sudo scripts/node-service.sh status    # is it loaded, running, since when
#   sudo scripts/node-service.sh restart   # force a restart of the running unit
#   sudo scripts/node-service.sh start|stop
#        scripts/node-service.sh logs      # follow the daemon log
#   sudo scripts/node-service.sh verify    # headless readiness + proof
#
# `verify` is the important one, and it is deliberately strict about what counts as
# proof. Elapsed time since boot is NOT proof: an operator (or automatic login) can
# log in seconds after boot and start the service by hand, which no time window can
# distinguish from a boot-triggered start.
#
# The evidence it actually requires is that NO console login exists on this boot
# while the service is running. If nobody has logged in and the node is up, the node
# demonstrably did not need a login. That is why the documented procedure is: reboot,
# do NOT log in, connect over SSH, run verify.
#
# On Linux, use systemctl against systemd/consensus-node.service instead.
#
set -uo pipefail

LABEL="com.consensus.node"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SERVICE="system/${LABEL}"

# How long to wait for the orchestrator to report the node online after a restart.
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

boot_epoch() {
  # The brace matters: a bare `sec = ` also matches the `usec = ` field.
  sysctl -n kern.boottime | sed -n 's/.*{ *sec *= *\([0-9]*\).*/\1/p'
}

service_pid() {
  launchctl print "${SERVICE}" 2>/dev/null | sed -n 's/^[[:space:]]*pid = \([0-9]*\).*/\1/p' | head -1
}

process_start_epoch() {
  local pid="$1" lstart
  lstart="$(ps -o lstart= -p "${pid}" 2>/dev/null | sed 's/  */ /g;s/^ *//;s/ *$//')"
  [[ -z "${lstart}" ]] && return 1
  date -j -f "%a %b %e %T %Y" "${lstart}" +%s 2>/dev/null
}

state_dir_from_plist() {
  [[ -f "${PLIST}" ]] || return 1
  /usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:CONSENSUS_STATE_DIR" "${PLIST}" 2>/dev/null
}

# Is anyone logged in at the console? Two independent signals, because this is what
# the whole proof rests on. loginwindow chowns /dev/console to the console user on
# login and hands it back to root at the login window, and `who` lists a console row
# only while such a session exists.
console_is_free() {
  local uid sessions
  uid="$(stat -f %u /dev/console 2>/dev/null)"
  sessions="$(who 2>/dev/null | awk '$2 == "console"' | wc -l | tr -d ' ')"
  [[ "${uid}" == "0" && "${sessions}" == "0" ]]
}

console_owner() {
  stat -f %Su /dev/console 2>/dev/null || echo "unknown"
}

# launchd's own run counter for the job. 1 means it has started exactly once since it
# was loaded — corroborating that the start was the boot-triggered one, not a manual
# kickstart on top of it.
service_runs() {
  launchctl print "${SERVICE}" 2>/dev/null | sed -n 's/^[[:space:]]*runs = \([0-9]*\).*/\1/p' | head -1
}

node_id_from_state() {
  local state_dir; state_dir="$(state_dir_from_plist)" || state_dir="${HOME}/.consensus/node"
  [[ -f "${state_dir}/config.json" ]] || return 1
  /usr/bin/python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('node_id') or '')" \
    "${state_dir}/config.json" 2>/dev/null
}

server_url_from_plist() {
  [[ -f "${PLIST}" ]] || { echo "${DEFAULT_SERVER_URL}"; return; }
  /usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:CONSENSUS_SERVER_URL" "${PLIST}" 2>/dev/null \
    || echo "${DEFAULT_SERVER_URL}"
}

# The end-to-end signal: does the ORCHESTRATOR consider this node live? A running
# process proves the unit started; only this proves the node is actually serving.
orchestrator_status() {
  local node_id server
  node_id="$(node_id_from_state)" || return 1
  [[ -n "${node_id}" ]] || return 1
  server="$(server_url_from_plist)"
  curl -fsS --max-time 10 "${server}/node/status/${node_id}" 2>/dev/null \
    | /usr/bin/python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null
}

wait_until_online() {
  local deadline=$(( $(date +%s) + ONLINE_TIMEOUT_SECONDS )) status
  echo "Waiting for the orchestrator to report this node online (up to ${ONLINE_TIMEOUT_SECONDS}s)..."
  while (( $(date +%s) < deadline )); do
    status="$(orchestrator_status)" || status=""
    if [[ "${status}" == "active" ]]; then
      green "  orchestrator reports: active — the node reconnected and is serving"
      return 0
    fi
    sleep 5
  done
  warn "  orchestrator did not report 'active' within ${ONLINE_TIMEOUT_SECONDS}s (last: ${status:-unreachable})"
  return 1
}

cmd_status() {
  need_root status
  if [[ ! -f "${PLIST}" ]]; then
    red "not installed — ${PLIST} is missing"
    echo "Install it with: sudo scripts/install-launchd.sh"
    return 1
  fi
  echo "plist:   ${PLIST}"
  local pid; pid="$(service_pid)"
  if [[ -z "${pid}" || "${pid}" == "0" ]]; then
    red "state:   NOT RUNNING"
    launchctl print "${SERVICE}" 2>/dev/null | grep -E "last exit|state = " | sed 's/^[[:space:]]*/         /'
    return 1
  fi
  green "state:   running (pid ${pid})"
  local started boot
  started="$(process_start_epoch "${pid}")" || return 0
  boot="$(boot_epoch)"
  echo "started: $(date -r "${started}")  — $(( started - boot ))s after boot"
}

cmd_restart() {
  need_root restart
  [[ -f "${PLIST}" ]] || { red "not installed — run sudo scripts/install-launchd.sh"; exit 1; }
  echo "Forcing a restart of ${SERVICE}..."
  # kickstart -k kills the running instance and starts a fresh one, which is what
  # launchd itself does on a crash — the closest thing to a reboot for this job.
  launchctl kickstart -k "${SERVICE}" || { red "kickstart failed"; exit 1; }
  sleep 2
  cmd_status || true
  # A live pid only says the unit relaunched. The node is not actually back until the
  # orchestrator sees its control tunnel again, so wait for that.
  echo
  wait_until_online
}

cmd_start() { need_root start; launchctl bootstrap system "${PLIST}" && launchctl enable "${SERVICE}" && cmd_status; }
cmd_stop()  { need_root stop;  launchctl bootout "${SERVICE}" && echo "stopped"; }

cmd_logs() {
  local state_dir; state_dir="$(state_dir_from_plist)" || state_dir="${HOME}/.consensus/node"
  echo "following ${state_dir}/launchd.err.log (ctrl-c to stop)"
  tail -f "${state_dir}/launchd.err.log" "${state_dir}/launchd.out.log"
}

cmd_verify() {
  need_root verify
  local failures=0 warnings=0

  echo "== Headless readiness =="

  # 1. FileVault. Nothing else matters if this is on: the machine halts at a
  #    pre-boot unlock prompt, before launchd exists.
  if fdesetup status 2>/dev/null | grep -qi "FileVault is Off"; then
    green "  [ok]   FileVault is off — the machine can boot unattended"
  else
    red   "  [FAIL] FileVault is ON. The machine stops at the pre-boot unlock screen,"
    echo  "         so NOTHING runs until a human types the password — no daemon can"
    echo  "         change that. Turn it off, or accept that only 'sudo fdesetup"
    echo  "         authrestart' gives you one unattended reboot at a time."
    failures=$((failures + 1))
  fi

  # 2. Auto-restart after power loss. Not supported on every model.
  if pmset -g 2>/dev/null | grep -qE "^\s*autorestart\s+1"; then
    green "  [ok]   autorestart is on — returns after a power cut"
  elif pmset -g 2>/dev/null | grep -qE "^\s*autorestart"; then
    warn  "  [warn] autorestart is off — a power cut leaves the machine down."
    echo  "         Fix: sudo pmset -a autorestart 1"
    warnings=$((warnings + 1))
  else
    warn  "  [warn] this Mac does not report autorestart (common on portables)"
    warnings=$((warnings + 1))
  fi

  # 3. The daemon itself.
  if [[ -f "${PLIST}" ]]; then
    green "  [ok]   LaunchDaemon installed at ${PLIST}"
  else
    red   "  [FAIL] ${PLIST} missing — run: sudo scripts/install-launchd.sh"
    failures=$((failures + 1))
  fi

  if launchctl print "${SERVICE}" >/dev/null 2>&1; then
    green "  [ok]   service is loaded in launchd's system domain"
  else
    red   "  [FAIL] service is not loaded"
    failures=$((failures + 1))
  fi

  # 4. Is it actually up?
  local pid; pid="$(service_pid)"
  if [[ -n "${pid}" && "${pid}" != "0" ]]; then
    green "  [ok]   running (pid ${pid})"
  else
    red   "  [FAIL] not running"
    launchctl print "${SERVICE}" 2>/dev/null | grep -E "last exit" | sed 's/^[[:space:]]*/         /'
    failures=$((failures + 1))
  fi

  # 5. THE PROOF. Not elapsed time — that cannot tell a boot-triggered start from a
  #    manual one after an early login. What settles it is the absence of any console
  #    login while the service is running.
  echo
  echo "== Headless proof =="
  if [[ -z "${pid}" || "${pid}" == "0" ]]; then
    red "  [unproven] nothing is running to evaluate"
    failures=$((failures + 1))
  elif console_is_free; then
    green "  [PROVEN] no console login exists on this boot, and the node is running."
    echo  "           It therefore started without anyone logging in."
    local runs; runs="$(service_runs)"
    if [[ "${runs}" == "1" ]]; then
      green "  [ok]     launchd reports runs = 1 — started once, by boot, not restarted since"
    elif [[ -n "${runs}" ]]; then
      echo  "           launchd reports runs = ${runs} (restarted since load; the proof above still holds)"
    fi
  else
    warn  "  [unproven] ${console_owner} is logged in at the console."
    echo  "           With a session present, this cannot distinguish a boot-triggered"
    echo  "           start from a manual one, and elapsed-time-since-boot is not"
    echo  "           evidence either — a login can happen seconds after boot."
    echo  "           To settle it: reboot, do NOT log in, connect over SSH, re-run."
    warnings=$((warnings + 1))
  fi

  # Supporting detail only — never presented as proof on its own.
  if [[ -n "${pid}" && "${pid}" != "0" ]]; then
    local started boot
    started="$(process_start_epoch "${pid}")"
    boot="$(boot_epoch)"
    if [[ -n "${started}" && -n "${boot}" ]]; then
      echo  "           (started $(( started - boot ))s after boot — context, not proof)"
    else
      warn  "  [warn]   could not read process start or boot time; timing context unavailable"
      warnings=$((warnings + 1))
    fi
  fi

  # 6. End to end: does the orchestrator actually see this node serving? A running
  #    process only proves the unit started.
  echo
  echo "== Orchestrator =="
  local remote; remote="$(orchestrator_status)" || remote=""
  if [[ "${remote}" == "active" ]]; then
    green "  [ok]   orchestrator reports this node active — it reconnected and is serving"
  elif [[ -n "${remote}" ]]; then
    warn  "  [warn] orchestrator reports status '${remote}' (not active)"
    warnings=$((warnings + 1))
  else
    warn  "  [warn] could not reach the orchestrator or resolve this node's id"
    warnings=$((warnings + 1))
  fi

  echo
  if (( failures > 0 )); then
    red "${failures} blocking problem(s), ${warnings} warning(s) — this node is NOT headless"
    return 1
  fi
  if (( warnings > 0 )); then
    warn "no blocking problems, ${warnings} warning(s)"
    return 0
  fi
  green "all checks passed"
}

case "${1:-}" in
  status)  cmd_status ;;
  restart) cmd_restart ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  logs)    cmd_logs ;;
  verify)  cmd_verify ;;
  *)
    echo "Usage: $0 <status|restart|start|stop|logs|verify>" >&2
    echo >&2
    echo "  verify   check headless readiness AND prove the running node started at boot" >&2
    echo "  restart  force a restart of the running unit (launchctl kickstart -k)" >&2
    exit 64
    ;;
esac
