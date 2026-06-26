# Node deployment — serving the direct data plane

A worker node must expose its **runtime server** (the inbound `/connect` endpoint)
at its registered domain over **wss**, in addition to running the outbound control
tunnel. This directory holds the reproducible bring-up for that.

## What changed

- **`scripts/run-node.sh`** — one supervised unit that runs **both** the runtime
  server (`bun run start`, hosts `/connect` on `:NODE_PORT`) and the control tunnel
  (`bun run control`). It supersedes `run-control.sh` (control-only) as the process
  the supervisor runs. A single restart refreshes both from the updated `current`
  symlink, and the unit cycles if either child exits (so `update_apply` still
  restarts cleanly). `ecosystem.config.cjs`, `systemd/`, and `launchd/` all point at
  it. Requires bash ≥ 4.3 (uses `wait -n`) — standard on Linux; on macOS run
  `brew install bash`.
- **`deploy/Caddyfile`** + **`scripts/setup-node-tls.sh`** — per-node automatic
  HTTPS. Caddy terminates TLS with an auto-renewing Let's Encrypt cert for the
  node's subdomain and reverse-proxies to the runtime server.

Why Caddy/TLS lives on the node (not a central proxy or Cloudflare): registration
points the subdomain's public DNS straight at the node's own IP, and the goal is a
**direct** client→node path. Node identity + MITM resistance come from the Ed25519
responder-auth handshake **inside** the stream, so the TLS terminator is pure
transport — each node owning its own cert is reproducible and needs no shared
Cloudflare credentials.

## Bring-up (per node)

```bash
# 0. Install Caddy once: https://caddyserver.com/docs/install
# 1. Register — assigns <hex>.consensus.canister.software + public DNS (A/AAAA).
bun run setup

# 2. Provision TLS for the assigned domain → runtime server.
sudo CADDYFILE=/etc/caddy/Caddyfile scripts/setup-node-tls.sh

# 3. Run the node unit (runtime server + control) under your supervisor:
pm2 start ecosystem.config.cjs           # PM2
#   or: systemctl enable --now consensus-node     (systemd/consensus-node.service)
```

Inbound ports: open **:443** (and **:80** for HTTP-01, else Caddy uses TLS-ALPN-01
over :443). Public DNS → the node's IP is set by registration.

## Verify

```bash
curl https://<your-node-domain>/health     # runtime server reachable over TLS
# orchestrator should also list the node active:
curl https://consensus.canister.software/health
```

A cert error means TLS isn't provisioned (re-run step 2); a 502/connection-refused
means the runtime server isn't up (check the unit logs); health JSON means you're
ready for direct routing.

## Renewal & re-registration

Caddy auto-renews — no cron. If a node re-registers and gets a new domain, re-run
`scripts/setup-node-tls.sh` to update the site.
