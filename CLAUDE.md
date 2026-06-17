# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Canonical cross-repo reference:** the architecture + cross-repo contracts live in `consensus-docs` → https://docs.consensus.canister.software/protocol/architecture/ ([source](https://github.com/canister-software/consensus-docs/blob/main/src/content/docs/protocol/architecture.md)). Read it before changing the tunnel handshake/frames/messages (`src/tunnel/`, `src/crypto/`) or the routing-ticket format — those must stay compatible with `consensus` (`server/features/node-tunnel/`). Related repos: [`consensus`](https://github.com/Demali-876/consensus) (orchestrator), [`consensus-client`](https://github.com/Demali-876/consensus-client) (SDK + CLI), [`consensus-docs`](https://github.com/canister-software/consensus-docs) (docs).

## Project

Verifiable Bun worker node runtime for the Consensus network. Written from scratch (the `instance/` directory in the wider monorepo is a reference implementation, not used here). Runtime: Bun ≥1.2, TypeScript strict, ESM, `moduleResolution: "Bundler"`. Source is run directly with `bun src/<entry>.ts` — there is no build step for local development; `tsc` is used only for type-checking (`bun run typecheck`).

## Commands

Each top-level lifecycle phase has its own entry file under `src/` and a matching `bun run` script:

- `bun run start` — local Fastify API on `:9090` (`src/instance.ts`).
- `bun run setup` — interactive join wizard (recommended path; orchestrates eval → register → verify).
- `bun run eval` — encrypted eval over the tunnel; passing eval writes `join-auth.json` into the state dir.
- `bun run register` — submit join payload (requires `join-auth.json` from a prior eval).
- `bun run control` — long-lived encrypted control tunnel with exponential reconnect; **this is the production foreground process** (PM2 runs it via `scripts/run-control.sh`).
- `bun run verify` — server-side check that the registered node key signs the local manifest.
- `bun run update` / `bun run update -- --download` — compare local manifest to server `/update/latest`; optional verified download.
- `bun run release -- --version X --commit … --platform … --download-url …` — produce tarball + admin manifest in `dist/`.
- `bun run version:bump -- patch|minor|major` — explicit version bump commit (ordinary commits do NOT publish).
- `bun run typecheck` — `tsc --noEmit`.

Tests are individual Bun scripts, not a unified test runner. Run a single test with its named script:

```
bun run test:secure-channel
bun run test:handshake
bun run test:eval-client
bun run test:control-client
bun run test:register
bun run test:benchmarks
bun run test:streams
bun run test:update-reply-to
```

## Required environment

Most subcommands read configuration from env vars; defaults are not inferred from a config file. Common ones:

- `CONSENSUS_SERVER_URL` — base HTTPS URL; the tunnel URL is derived by swapping scheme to `wss` and path to `/node/tunnel`. `CONSENSUS_TUNNEL_URL` overrides explicitly.
- `CONSENSUS_STATE_DIR` — defaults to `~/.consensus/node`. Holds `config.json`, `keys/`, `release-manifest.json`, `join-auth.json`, `setup-progress.json`, `downloads/`.
- `CONSENSUS_NODE_INSTALL_DIR` — production install root (`~/.consensus/node-runtime` by default). Contains `releases/<version>/` and a `current` symlink.
- `CONSENSUS_NODE_UPDATE_COMMAND` — installer command run on apply; falls back to `scripts/install-release.sh` from the local repo or from `<install-dir>/current/`.
- Registration extras: `CONSENSUS_NODE_IPV4`, `CONSENSUS_NODE_IPV6`, `CONSENSUS_NODE_PORT`, `CONSENSUS_NODE_CONTACT`, `CONSENSUS_EMAIL_VERIFICATION_TOKEN`, `CONSENSUS_EVM_ADDRESS`, `CONSENSUS_SOLANA_ADDRESS`, `CONSENSUS_ICP_ADDRESS`.

## Architecture

The codebase is organized around **lifecycle entrypoints** at `src/*.ts` that compose helpers from the subdirectories below. Read entries in this order to get the big picture: `instance.ts` → `eval.ts` → `register.ts` → `control.ts` → `update.ts`.

### Encrypted tunnel (`src/tunnel/`, `src/crypto/`)

All non-trivial server interaction goes through a single WebSocket-based tunnel protocol:

- `tunnel/handshake.ts` — versioned JSON handshake (`consensus-node-tunnel` / version 1). Init is signed with the node's Ed25519 identity (`crypto/identity.ts`); both sides do an X25519 exchange and derive ChaCha20-Poly1305 keys via HKDF over a SHA-256 transcript hash (`crypto/secure-channel.ts`). The transcript is the canonical-JSON serialization (`crypto/canonical-json.ts`) of the init message without its `signature` field.
- `tunnel/frames.ts` + `tunnel/messages.ts` — binary frame format and the discriminated-union message types (`MESSAGE_TYPE`). After handshake, every message is encrypted as one frame and parsed back into a `TunnelMessage`.
- `tunnel/tunnel-client.ts` + `tunnel/connect.ts` — single client that supports both modes via the `TUNNEL_MODE` ("eval" | "control") parameter on the init message.

When working with tunnel logic, prefer extending `MESSAGE_TYPE` and the `TunnelMessage` union over inventing parallel transports. The handshake signing payload deliberately excludes `signature` and runs through `canonicalJson` — do not bypass that path.

### Lifecycle clients (`src/clients/`)

`eval-client.ts` and `control-client.ts` are thin wrappers over `connectEncryptedTunnel` that own per-mode state machines:

- **Eval client** opens an eval tunnel, runs benchmark/integrity actions on demand from the server, and writes `join-auth.json` when the server emits `JOIN_READY`. Eval consumes the encrypted authorization; it does not require port-forwarding or a public benchmark endpoint.
- **Control client** is the production long-running loop. It sends heartbeats, executes `proxy_request` and `stream_*` messages, multiplexes a "public tunnel" frame format (5-byte type+stream_id header) across server-driven streams, and owns the `update_prepare` → `update_ready` → `update_apply` flow. On apply it closes the WS with code `1012`, then exits with code `0` so the supervisor restarts via the `current` symlink.

`src/control.ts` wraps `startControlClient` in an exponential-backoff reconnect loop (capped at ~30 s + jitter); do not move retry logic into the client itself.

### Server-directed updates

`src/update.ts` defines the manifest comparison (`compareManifests` checks version, platform, commit, routes_hash, tarball_sha256) and `downloadAndVerify` (SHA-256 against the manifest before writing into `state/downloads/` with mode `0600`). `control-client.ts` reuses both helpers for the over-the-tunnel apply flow. The control client looks for the installer command in this order: `CONSENSUS_NODE_UPDATE_COMMAND` → `./scripts/install-release.sh` (cwd) → `<install-dir>/current/scripts/install-release.sh`.

### Runtime services (`src/runtime/`)

Hosted by `runtime/server.ts` (Fastify + `@fastify/websocket`) and the same eval actions exposed through the tunnel:

- `runtime/eval.ts` dispatches `EvalAction` values (`capabilities`, `integrity`, `benchmark_*`) used by both the local HTTP API and the eval tunnel.
- `runtime/benchmarks/` — SHA-256 CPU throughput, ChaCha20-Poly1305 throughput, event loop, memory, system info. Add new suites under `benchmarks/suites/` and wire them into `benchmarks/index.ts` + `runtime/eval.ts`.
- `runtime/proxy-command.ts` (one-shot HTTP proxy) and `runtime/proxy-session.ts` / `proxy-worker.ts` (multiplexed proxy streams).
- `runtime/capabilities.ts` — declared `NodeCapability` set, sent in heartbeats and join payload.

### Node state and identity (`src/node/`, `src/crypto/identity.ts`)

`node/state.ts` owns all on-disk layout under `CONSENSUS_STATE_DIR` and is the only place that should touch those paths. `crypto/identity.ts` lazily creates the Ed25519 keypair under `keys/` with mode `0600`; the same key signs handshakes, manifests (`node/manifest.ts`), and integrity payloads (`node/integrity.ts`). Treat the Ed25519 public key as the node's stable identity — registration binds it to a `node_id`.

### Release + supervision

`src/release.ts` builds a tarball, signs a `ReleaseManifest` (`src/types.ts`), and emits an `/admin/manifest` payload that the Consensus server consumes to gate updates. GitHub Actions' `Release` workflow is manual.

In production:
- `ecosystem.config.cjs` configures PM2 to run `<install-dir>/current/scripts/run-control.sh` (which itself execs `bun run control`).
- `scripts/install-release.sh` is the default installer: unpacks the verified tarball into `releases/<version>/`, installs prod deps with the lockfile, atomically moves the `current` symlink, then prunes old releases per `CONSENSUS_NODE_RELEASE_RETENTION` (default 3) — while protecting the release that is mid-update.
- `scripts/ensure-pm2.sh` and `scripts/start-pm2.sh` bootstrap PM2 on macOS (Homebrew → Node → PM2). `launchd/` and `systemd/` templates exist for non-PM2 deployments.

The wrapper still tolerates the legacy exit code `75` from older releases. New code should exit with `0` (the supervisor handles the restart) and close with WS code `1012` so the server distinguishes update shutdowns from crashes.

## Conventions

- Logs go through `src/log.ts`'s `log.info/warn/error(scope, event, fields)` — one JSON line per call. Avoid `console.log` outside of CLI-output paths in `eval.ts`, `update.ts`, `verify.ts`, `release.ts`.
- Signed payloads (handshake, manifest, integrity) MUST round-trip through `canonicalJson` before signing/verifying.
- Sensitive files (`keys/*`, `join-auth.json`, downloaded artifacts, `setup-progress.json`) are written with mode `0600`. Preserve that when adding new on-disk state.
- Version bumps are explicit commits using `bun run version:bump`; do not change `package.json` `version` by hand as part of unrelated changes.
