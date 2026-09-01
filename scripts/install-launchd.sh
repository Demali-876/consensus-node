#!/usr/bin/env bash
#
# Install the Consensus node as a macOS LaunchDaemon so it starts at boot WITHOUT a
# user login.
#
# Why a daemon and not `pm2 startup`: on macOS `pm2 startup` writes a LaunchAgent to
# ~/Library/LaunchAgents, and agents load only once a user logs in. A LaunchDaemon in
# /Library/LaunchDaemons loads at boot. Writing there requires root, which is why this
# script must be run with sudo.
#
#   sudo scripts/install-launchd.sh
#
# Uninstall:
#
#   sudo launchctl bootout system/com.consensus.node
#   sudo rm /Library/LaunchDaemons/com.consensus.node.plist
#
set -euo pipefail

LABEL="com.consensus.node"
PLIST_DEST="/Library/LaunchDaemons/${LABEL}.plist"
TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="${TEMPLATE_DIR}/launchd/${LABEL}.plist.template"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This must run as root so it can write ${PLIST_DEST}:" >&2
  echo "  sudo $0" >&2
  exit 77
fi

# Everything the daemon touches belongs to the human who invoked sudo, not to root.
target_user="${CONSENSUS_NODE_USER:-${SUDO_USER:-}}"
if [[ -z "${target_user}" || "${target_user}" == "root" ]]; then
  echo "Could not determine the operator account. Re-run via sudo from your own login," >&2
  echo "or set CONSENSUS_NODE_USER=<username>." >&2
  exit 78
fi

target_home="$(dscl . -read "/Users/${target_user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
if [[ -z "${target_home}" || ! -d "${target_home}" ]]; then
  echo "No home directory found for user ${target_user}" >&2
  exit 78
fi

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "Template not found: ${TEMPLATE}" >&2
  exit 66
fi

install_dir="${CONSENSUS_NODE_INSTALL_DIR:-"${target_home}/.consensus/node-runtime"}"
state_dir="${CONSENSUS_STATE_DIR:-"${target_home}/.consensus/node"}"
server_url="${CONSENSUS_SERVER_URL:-"https://consensus.canister.software"}"
app_name="${CONSENSUS_PM2_NAME:-consensus-node-control}"

if [[ ! -d "${install_dir}/current" ]]; then
  echo "No installed release at ${install_dir}/current — run setup first." >&2
  exit 70
fi

# Resolve interpreters as the target user: pm2 and bun usually live under their home
# (nvm, ~/.bun), which root's PATH knows nothing about.
as_user() { sudo -u "${target_user}" -H /bin/bash -lc "$1"; }

pm2_runtime="$(as_user 'command -v pm2-runtime || true')"
if [[ -z "${pm2_runtime}" ]]; then
  echo "pm2-runtime not found for ${target_user}. Run scripts/ensure-pm2.sh first." >&2
  exit 69
fi

bun_bin="$(as_user 'command -v bun || true')"
if [[ -z "${bun_bin}" ]]; then
  for candidate in "${target_home}/.bun/bin/bun" /opt/homebrew/bin/bun /usr/local/bin/bun; do
    [[ -x "${candidate}" ]] && bun_bin="${candidate}" && break
  done
fi
if [[ -z "${bun_bin}" ]]; then
  echo "bun not found for ${target_user}. Run scripts/ensure-bun.sh first." >&2
  exit 69
fi

# The daemon's PATH: the dirs holding pm2-runtime and bun, plus the system defaults.
daemon_path="$(dirname "${pm2_runtime}"):$(dirname "${bun_bin}"):/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

mkdir -p "${state_dir}"
chown "${target_user}" "${state_dir}"

# Prove, as the account the daemon will run as, that the encryption data key is
# reachable with no login session. The daemon boots before anyone logs in, so a key
# this account cannot read would strand the node — surface that now, not at 3am.
echo "Checking encryption at rest as ${target_user}..."
if ! as_user "cd '${install_dir}/current' && CONSENSUS_STATE_DIR='${state_dir}' '${bun_bin}' src/secrets-check.ts"; then
  echo >&2
  echo "The node's secrets are not readable by ${target_user} without a login." >&2
  echo "Refusing to install a boot unit that would fail on every reboot." >&2
  exit 76
fi

# `|` as the sed delimiter because every value here is a path.
tmp_plist="$(mktemp)"
trap 'rm -f "${tmp_plist}"' EXIT
sed \
  -e "s|@PM2_RUNTIME@|${pm2_runtime}|g" \
  -e "s|@INSTALL_DIR@|${install_dir}|g" \
  -e "s|@STATE_DIR@|${state_dir}|g" \
  -e "s|@SERVER_URL@|${server_url}|g" \
  -e "s|@APP_NAME@|${app_name}|g" \
  -e "s|@USER@|${target_user}|g" \
  -e "s|@HOME@|${target_home}|g" \
  -e "s|@PATH@|${daemon_path}|g" \
  -e "s|@BUN@|${bun_bin}|g" \
  "${TEMPLATE}" > "${tmp_plist}"

if grep -q '@[A-Z_]*@' "${tmp_plist}"; then
  echo "Template still contains unsubstituted tokens:" >&2
  grep -o '@[A-Z_]*@' "${tmp_plist}" | sort -u >&2
  exit 65
fi

# Fail before installing rather than leaving launchd with a plist it cannot parse.
plutil -lint "${tmp_plist}" >/dev/null

# bootout first so a re-run replaces cleanly; it fails when nothing is loaded, which
# is fine on a first install.
launchctl bootout "system/${LABEL}" 2>/dev/null || true

install -o root -g wheel -m 644 "${tmp_plist}" "${PLIST_DEST}"
launchctl bootstrap system "${PLIST_DEST}"
launchctl enable "system/${LABEL}"

echo "Installed ${PLIST_DEST}"
echo "  user:        ${target_user}"
echo "  pm2-runtime: ${pm2_runtime}"
echo "  bun:         ${bun_bin}"
echo "  install dir: ${install_dir}"
echo "  state dir:   ${state_dir}"
echo
echo "Status:  sudo scripts/node-service.sh status"
echo "Restart: sudo scripts/node-service.sh restart"
echo "Logs:    scripts/node-service.sh logs"
echo
echo "It should now start at boot with no login required. To PROVE that:"
echo "  1. reboot"
echo "  2. do NOT log in — connect over SSH instead"
echo "  3. sudo scripts/node-service.sh verify"
echo
echo "verify reports PROVEN only if the running process started within seconds of"
echo "boot, which cannot happen if it waited for a login."
