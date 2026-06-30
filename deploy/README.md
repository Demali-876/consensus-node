# Node deployment — gateway data plane (no inbound ports)

A worker node needs **only its outbound control tunnel**. It opens no inbound
ports, terminates no TLS, and needs no public DNS of its own.

Registration assigns a permanent URL, `wss://<node-id>.consensus.canister.software/connect`.
That hostname resolves (via a wildcard record) to the **orchestrator**, which holds
the wildcard `*.consensus.canister.software` TLS cert and **bridges** an inbound
`/connect` socket onto this node's existing control tunnel as a `{kind:"data-plane"}`
stream. The node serves the request over the tunnel it already holds
(`src/clients/data-plane-stream.ts` → `serveDataConnection`). Node identity and
MITM resistance come from the Ed25519 responder-auth handshake **inside** the
stream, so the orchestrator relays bytes it cannot read.

This supersedes the previous per-node Caddy/TLS bring-up (the model where public
DNS pointed at the node's own IP). Those files (`deploy/Caddyfile`,
`scripts/setup-node-tls.sh`) are removed.

## What runs

- **`scripts/run-node.sh`** — one supervised unit running **both** the control
  tunnel (`bun run control`, which now also serves the data plane over its
  streams) and the runtime server (`bun run start`). The runtime server binds
  **loopback-only** by default (`NODE_HOST=127.0.0.1`) and just exposes local
  operator endpoints (`/health`, `/node/*`); it is not reachable from outside and
  does not need to be. A single restart refreshes both children from the updated
  `current` symlink, and the unit cycles if either exits (so `update_apply`
  restarts cleanly). `ecosystem.config.cjs`, `systemd/`, and `launchd/` all exec
  it. Requires bash ≥ 4.3 (`wait -n`) — standard on Linux; on macOS run
  `brew install bash`.

## Bring-up (per node)

```bash
# 1. Register — assigns <node-id>.consensus.canister.software + the connect URL.
bun run setup

# 2. Run the node unit (control tunnel + loopback runtime) under your supervisor:
pm2 start ecosystem.config.cjs                 # PM2
#   or: systemctl enable --now consensus-node   (systemd/consensus-node.service)
```

No inbound ports to open, no certificate to provision. Keep the outbound control
tunnel connected; that is the entire data path.

## Verify

```bash
# Local: runtime server is up on loopback (operator-only).
curl http://127.0.0.1:9090/health

# Orchestrator lists this node active (it sees the control tunnel):
curl https://consensus.canister.software/health

# End-to-end: the node is reachable through its gateway URL (served over the
# tunnel by the orchestrator — no TLS or port on this box).
curl https://<node-id>.consensus.canister.software/health
```

If the orchestrator does not list the node, the control tunnel is not connected —
check the unit logs. The gateway URL only works once the node's control tunnel is
established **and** the orchestrator's wildcard DNS/cert are in place.

## Direct mode (advanced, optional — not required)

A node that genuinely can accept inbound connections (a VPS / datacenter host) can
serve the data plane directly and skip the orchestrator relay: set `NODE_HOST=::`
(or `0.0.0.0`) so the runtime server's `/connect` route is reachable, and front it
with your own TLS terminator for the node's domain. This bypasses the gateway
bottleneck for that node. Full direct routing also needs orchestrator-side support
(pointing the node's subdomain at its IP and handing clients that domain), which is
not wired yet — until then, every node is reached through the gateway.
