#!/usr/bin/env bash
#
# Render + install the node's Caddy site so wss://<domain>/connect terminates TLS
# with an auto-renewing Let's Encrypt cert and reverse-proxies to the runtime server.
#
# The data plane's security (node identity, MITM resistance) is the Ed25519
# responder-auth handshake INSIDE the stream, so Caddy is pure transport — it just
# terminates TLS the client's `ws` library can trust. Each node provisions its own
# cert, so this is reproducible across any number of nodes with no shared secrets.
#
# Run AFTER registration (which assigns the subdomain + public DNS), and re-run after
# any re-registration:
#
#   sudo CADDYFILE=/etc/caddy/Caddyfile NODE_PORT=9090 scripts/setup-node-tls.sh
#
set -euo pipefail

state_dir="${CONSENSUS_STATE_DIR:-"$HOME/.consensus/node"}"
config="${state_dir}/config.json"
node_port="${NODE_PORT:-9090}"
caddyfile="${CADDYFILE:-/etc/caddy/Caddyfile}"

command -v caddy >/dev/null 2>&1 || {
  echo "caddy not found — install it first: https://caddyserver.com/docs/install" >&2
  exit 1
}
[[ -f "${config}" ]] || {
  echo "node config not found at ${config} — register the node first (bun run setup)" >&2
  exit 1
}

# Read the assigned domain straight from the node config (bun is always present).
domain="$(bun -e 'try{const c=require("fs").readFileSync(process.argv[1],"utf8");process.stdout.write(String(JSON.parse(c).domain||""))}catch{process.exit(1)}' "${config}" || true)"
if [[ -z "${domain}" || "${domain}" == "null" ]]; then
  echo "no domain in ${config} — register the node first (bun run setup)" >&2
  exit 1
fi

echo "Configuring Caddy: ${domain} -> localhost:${node_port}"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
cat > "${tmp}" <<EOF
# Managed by consensus-node scripts/setup-node-tls.sh — do not edit by hand.
# Re-run the script after re-registration to update the domain.
${domain} {
	reverse_proxy localhost:${node_port}
}
EOF

caddy validate --adapter caddyfile --config "${tmp}"
install -m 0644 "${tmp}" "${caddyfile}"

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet caddy 2>/dev/null; then
  systemctl reload caddy
  echo "✓ Reloaded caddy.service"
elif caddy reload --adapter caddyfile --config "${caddyfile}" 2>/dev/null; then
  echo "✓ Reloaded Caddy"
else
  echo "✓ Wrote ${caddyfile} — reload Caddy to apply (systemctl reload caddy, or restart the service)."
fi

echo "✓ TLS configured for https://${domain} (cert issues on first request)"
