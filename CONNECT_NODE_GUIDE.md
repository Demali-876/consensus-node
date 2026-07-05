# Connect a Node to the Consensus Network

**This guide is AI Generatate and is pending human review.**

This guide connects one machine as a Consensus worker node using the supported
gateway data-plane deployment. In this mode the node does not need public inbound
ports, DNS, or TLS. It keeps an outbound encrypted control tunnel to the
Consensus server, and the orchestrator bridges client traffic onto that tunnel.

## Prerequisites

1. Use a machine that can stay online continuously.
2. Make sure the machine has a public IPv4 address. IPv6 is optional.
3. Allow outbound HTTPS and WSS traffic to `https://consensus.canister.software`.
4. Have these values ready:
   - A contact email address you can verify during setup.
   - An EVM payout address.
   - A Solana payout address.
   - An ICP payout address.
5. Install Bun `1.3.0` or newer.

```bash
bun --version
```

If `bun` is not installed, install it first and reopen your shell before
continuing.

On macOS, install a modern Bash before using PM2 supervision:

```bash
brew install bash
```

Linux distributions normally include a Bash version new enough for the node
supervisor.

## 1. Get the node source

```bash
git clone https://github.com/Demali-876/consensus-node.git
cd consensus-node
bun install
```

If you already have this repository, update it and install dependencies:

```bash
cd consensus-node
git pull
bun install
```

## 2. Choose state and install directories

The default state directory is:

```txt
~/.consensus/node
```

The default runtime install directory is:

```txt
~/.consensus/node-runtime
```

Use the defaults unless you have a reason to change them. If you need a custom
state directory, export it before running setup:

```bash
export CONSENSUS_STATE_DIR="$HOME/.consensus/node"
```

The state directory stores the node identity key, registration config,
join authorization, setup progress, logs, and downloaded release artifacts. Do
not delete it after registration.

## 3. Run the interactive setup wizard

Start the setup wizard:

```bash
bun run setup
```

Answer the prompts in this order:

1. `Continue with node setup?` - enter `y`.
2. `Consensus server URL` - press Enter to use `https://consensus.canister.software`.
3. `Runtime install directory` - press Enter to use `~/.consensus/node-runtime`.
4. If PM2 is missing, `Install PM2 and any missing macOS dependencies now?` -
   enter `y`.
5. Review the approved release that setup prints.
6. `Download and install this approved release?` - enter `y`.
7. Wait while setup downloads the approved release, verifies its SHA-256, installs
   production dependencies, and moves the `current` symlink.
8. Wait while setup detects public IPv4, optional IPv6, and region.
9. Wait while encrypted evaluation runs. Passing eval writes
   `join-auth.json` into the state directory.
10. `Contact email` - enter the email address for this node.
11. Check that inbox for the verification code.
12. `Email verification code` - enter the code from the email.
13. `EVM address` - enter the EVM payout address.
14. `Solana address` - enter the Solana payout address.
15. `ICP address` - enter the ICP payout address.
16. `Node local port` - press Enter to use `9090`, unless you need another local
    operator port.
17. Wait while setup submits registration to `/node/join`.
18. `Start the PM2 supervised control tunnel now?` - enter `y`.

When setup succeeds, it writes the registered node configuration to:

```txt
~/.consensus/node/config.json
```

The installed production runtime is:

```txt
~/.consensus/node-runtime/current
```

## 4. Confirm that PM2 is running the node

Check the process:

```bash
pm2 status consensus-node-control
```

Follow logs:

```bash
pm2 logs consensus-node-control
```

The PM2 unit runs:

```txt
~/.consensus/node-runtime/current/scripts/run-node.sh
```

That script starts both:

1. `bun run start` - local runtime server on `127.0.0.1:9090` by default.
2. `bun run control` - outbound encrypted control tunnel to the Consensus server.

If either child exits, PM2 restarts the whole unit from the current installed
release.

## 5. Verify local health

Check the local operator health endpoint:

```bash
curl http://127.0.0.1:9090/health
```

A registered runtime should return JSON with:

```json
{
  "status": "healthy",
  "registered": true,
  "node_id": "...",
  "domain": "..."
}
```

The `node_id` and `domain` values are also in:

```bash
cat ~/.consensus/node/config.json
```

## 6. Verify registration integrity with the server

Run verification from the installed runtime:

```bash
cd ~/.consensus/node-runtime/current
CONSENSUS_SERVER_URL=https://consensus.canister.software \
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
bun run verify
```

This signs the local release manifest with the node identity key and asks the
server to verify it against the registered node.

## 7. Verify gateway reachability

Find the node domain in `~/.consensus/node/config.json`, then replace
`<node-domain>` below:

```bash
curl https://<node-domain>/health
```

This works only after the control tunnel is connected and the orchestrator
gateway is active for the node's wildcard hostname.

## 8. Make PM2 survive reboots

Generate the startup command:

```bash
pm2 startup
```

PM2 prints one command that must be run with elevated privileges. Run exactly the
command PM2 prints, then save the process list:

```bash
pm2 save
```

After a reboot, confirm the node came back:

```bash
pm2 status consensus-node-control
curl http://127.0.0.1:9090/health
```

## 9. Normal operations

Restart the node:

```bash
pm2 restart consensus-node-control
```

Stop the node:

```bash
pm2 stop consensus-node-control
```

Start it again:

```bash
CONSENSUS_NODE_INSTALL_DIR="$HOME/.consensus/node-runtime" \
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
CONSENSUS_SERVER_URL=https://consensus.canister.software \
"$HOME/.consensus/node-runtime/current/scripts/start-pm2.sh"
```

Check whether the server requires a newer approved release:

```bash
cd ~/.consensus/node-runtime/current
CONSENSUS_SERVER_URL=https://consensus.canister.software \
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
bun run update
```

Download and verify the required artifact if instructed:

```bash
cd ~/.consensus/node-runtime/current
CONSENSUS_SERVER_URL=https://consensus.canister.software \
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
bun run update -- --download
```

Production updates are server-directed over the control tunnel. PM2 restarts the
node from the updated `current` symlink when an update is applied.

## Manual flow, if setup cannot be used

Use the setup wizard when possible. The manual flow is:

1. Install dependencies:

```bash
bun install
```

2. Run encrypted eval:

```bash
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run eval
```

3. Start email verification:

```bash
curl -sS -X POST https://consensus.canister.software/node/email/start \
  -H 'content-type: application/json' \
  -d '{"email":"ops@example.com"}'
```

4. Verify the email code from the response:

```bash
curl -sS -X POST https://consensus.canister.software/node/email/verify \
  -H 'content-type: application/json' \
  -d '{"email":"ops@example.com","verification_id":"<verification-id>","code":"<email-code>"}'
```

5. Register the node with the email verification token:

```bash
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
CONSENSUS_SERVER_URL=https://consensus.canister.software \
CONSENSUS_NODE_IPV4="<public-ipv4>" \
CONSENSUS_NODE_IPV6="<public-ipv6-or-omit-this-variable>" \
CONSENSUS_NODE_PORT=9090 \
CONSENSUS_NODE_CONTACT="ops@example.com" \
CONSENSUS_EMAIL_VERIFICATION_TOKEN="<email-verification-token>" \
CONSENSUS_EVM_ADDRESS="<evm-address>" \
CONSENSUS_SOLANA_ADDRESS="<solana-address>" \
CONSENSUS_ICP_ADDRESS="<icp-address>" \
bun run register
```

If the node has no IPv6 address, remove the `CONSENSUS_NODE_IPV6=...` line.

6. Keep the control tunnel open:

```bash
CONSENSUS_STATE_DIR="$HOME/.consensus/node" \
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run control
```

For production, prefer the PM2 setup above instead of leaving `bun run control`
attached to a terminal.

## Troubleshooting

- `Missing node id. Register the node before starting control mode.`:
  registration did not complete. Rerun `bun run setup` and do not skip the
  registration step unless `~/.consensus/node/config.json` already contains
  `node_id`.
- `Missing join authorization`: encrypted eval did not pass or
  `join-auth.json` is not in the state directory. Rerun setup or `bun run eval`.
- `Join authorization expired`: rerun encrypted eval, then register again.
- Local health is down: check `pm2 logs consensus-node-control` and confirm
  nothing else is using port `9090`.
- Local health says `"registered": false`: registration did not write
  `node_id` into the state config. Rerun setup.
- Gateway URL does not respond: confirm PM2 is running, local health is healthy,
  and the control logs show a successful tunnel connection.
- Do not open inbound firewall ports for the normal gateway deployment. Only use
  `NODE_HOST=0.0.0.0` or `NODE_HOST=::` for advanced direct-mode experiments.
