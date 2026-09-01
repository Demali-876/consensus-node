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
# `verify` is the important one. It does not assume the node is headless because a
# plist exists — it PROVES it, by checking how long after boot the running process
# started. A process that came up seconds after boot cannot have waited for a human
# to log in. Everything else it checks is a precondition for that being possible.
#
# On Linux, use systemctl against systemd/consensus-node.service instead.
#
set -uo pipefail

LABEL="com.consensus.node"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SERVICE="system/${LABEL}"

# A process that started this soon after boot started WITH the machine, not after a
# login. Generous enough to absorb slow disks; far below any realistic human login.
BOOT_WINDOW_SECONDS="${CONSENSUS_BOOT_WINDOW_SECONDS:-180}"

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
  cmd_status
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

  # 5. THE PROOF. A process that started seconds after boot did not wait for a
  #    login. This is the only check that distinguishes "configured to be headless"
  #    from "observed to be headless".
  echo
  echo "== Headless proof =="
  if [[ -n "${pid}" && "${pid}" != "0" ]]; then
    local started boot delta
    started="$(process_start_epoch "${pid}")"
    boot="$(boot_epoch)"
    if [[ -n "${started}" && -n "${boot}" ]]; then
      delta=$(( started - boot ))
      if (( delta <= BOOT_WINDOW_SECONDS )); then
        green "  [PROVEN] started ${delta}s after boot — before any login was possible."
        echo  "           This node came up headless on the current boot."
      else
        warn  "  [unproven] started ${delta}s after boot (threshold ${BOOT_WINDOW_SECONDS}s)."
        echo  "           That is consistent with a manual start or a restart after login,"
        echo  "           not with starting at boot. Reboot and re-run this WITHOUT logging"
        echo  "           in (over SSH) to get a definitive answer."
        warnings=$((warnings + 1))
      fi
    fi
  else
    warn  "  [unproven] nothing running to measure"
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
