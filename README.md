# Consensus Node

Verifiable Bun worker node runtime for the Consensus network.

This package is intentionally separate from `instance/`, which remains as a reference
implementation while this runtime is built from scratch.

## Development

```bash
bun install
bun run start
```

Default local API:

```txt
http://localhost:9090
```

State defaults to:

```txt
~/.consensus/node
```

Override with:

```bash
CONSENSUS_STATE_DIR=/path/to/state bun run start
```

## Join Flow

First run encrypted eval against the public server tunnel. A passing eval writes
`join-auth.json` into the node state directory.

```bash
CONSENSUS_STATE_DIR=~/.consensus/node \
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run eval
```

Then register the node with the join authorization:

```bash
CONSENSUS_SERVER_URL=https://consensus.canister.software \
CONSENSUS_NODE_IPV6=... \
CONSENSUS_NODE_IPV4=... \
CONSENSUS_NODE_PORT=9090 \
CONSENSUS_NODE_TEST_ENDPOINT=https://your-node.example.com/health \
CONSENSUS_NODE_REGION=us-east-1 \
CONSENSUS_NODE_CONTACT=ops@example.com \
CONSENSUS_EVM_ADDRESS=0x... \
CONSENSUS_SOLANA_ADDRESS=... \
CONSENSUS_ICP_ADDRESS=... \
bun run register
```

After registration, keep the outbound control tunnel open:

```bash
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run control
```

Verify the registered node code and manifest:

```bash
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run verify
```

The verification payload signs the node release manifest with the node Ed25519
identity. The server checks that signature against the registered node key and,
when an admin-required manifest is set, compares version, platform, commit,
routes hash, and tarball SHA.

Check whether this node matches the required server release:

```bash
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run update
```

If the server requires a newer release and the manifest includes a verified
artifact URL, download it into the node state directory:

```bash
CONSENSUS_SERVER_URL=https://consensus.canister.software \
bun run update -- --download
```

## Release Build

Version bumps are explicit commits. Normal commits do not publish releases.

```bash
bun run version:bump -- patch
git add package.json
git commit -m "Bump node version"
```

Build a node artifact and matching server admin manifest payload:

```bash
bun run release -- \
  --version 0.1.0-alpha.0 \
  --commit "$(git rev-parse HEAD)" \
  --platform darwin-arm64 \
  --download-url https://consensus.canister.software/releases/consensus-node-0.1.0-alpha.0-darwin-arm64.tgz
```

The command writes the tarball, manifest, and `/admin/manifest` payload into
`dist/`. Upload the tarball to the `download_url`, then post the admin payload
to the Pi server with `x-admin-key`.

GitHub releases are manual. Run the `Release` workflow from GitHub Actions when
you want to publish a real node artifact. If no version is provided in the
workflow form, it uses the committed `package.json` version. The workflow does
not run on ordinary commits.

## Server-Directed Updates

The Consensus server decides when a node should update. It sends
`update_prepare` over the encrypted control tunnel; the node downloads and
verifies the release artifact, then replies `update_ready`. The server drains the
node from routing and sends `update_apply` only when the router sees the node as
idle.

On apply, the node acknowledges, closes its control tunnel, and exits. In
production, run the node under a process manager. If
`CONSENSUS_NODE_UPDATE_COMMAND` is set, the node runs it before exiting with:

```txt
CONSENSUS_NODE_UPDATE_ID
CONSENSUS_NODE_ARTIFACT_PATH
CONSENSUS_NODE_TARGET_VERSION
```

That command should install the verified artifact and let the process manager
restart the node.

The default installer contract is:

```bash
export CONSENSUS_NODE_INSTALL_DIR="$HOME/.consensus/node-runtime"
export CONSENSUS_NODE_UPDATE_COMMAND="$CONSENSUS_NODE_INSTALL_DIR/current/scripts/install-release.sh"
```

`scripts/install-release.sh` unpacks the verified tarball into
`$CONSENSUS_NODE_INSTALL_DIR/releases/`, installs production dependencies with
the lockfile, and atomically moves the `current` symlink. `scripts/run-control.sh`
always starts `bun run control` from that `current` release.

For the first install, download a release tarball and run:

```bash
CONSENSUS_NODE_ARTIFACT_PATH=/path/to/consensus-node.tgz \
CONSENSUS_NODE_TARGET_VERSION=0.1.0-alpha.0 \
scripts/install-release.sh
```

Then run the node under a process manager using the templates in `launchd/` or
`systemd/`. On macOS, copy `launchd/com.consensus.node.plist`, replace the
`${HOME}` placeholders with the absolute home path, then load it with
`launchctl`.
