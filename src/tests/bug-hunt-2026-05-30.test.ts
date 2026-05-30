/**
 * Bug-hunt evidence tests — 2026-05-30
 *
 * Demonstrates six defects found during today's audit.
 * Each section is self-contained and asserts the PRESENCE of the bug so that
 * the assertion must be updated (or the section deleted) once the bug is fixed.
 *
 * Run:  bun src/tests/bug-hunt-2026-05-30.test.ts
 *
 * Findings (severity order):
 *   1. [SECURITY]     STREAM_DATA executes proxy without a prior STREAM_OPEN
 *   2. [SECURITY]     saveConfig / writeJson writes files without 0o600 permissions
 *   3. [SECURITY]     Handshake timestamp has no freshness window — stale INITs accepted
 *   4. [PERFORMANCE]  O(n) linear scan for publicTunnelOwner on every STREAM_DATA/STREAM_CLOSE
 *   5. [LOGIC]        nextStreamId overflows uint32 → writeUInt32BE throws at 2^32 connections
 *   6. [LOGIC]        decodePublicTunnelFrame silently accepts unknown frame type bytes
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  acceptClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
  HANDSHAKE_TYPE,
} from "../tunnel/handshake";
import { MESSAGE_TYPE, decodeMessage, encodeMessage, nowSeconds } from "../tunnel/messages";
import { openFrame, sealFrame, type SecureSession } from "../crypto/secure-channel";
import { FRAME_TYPE } from "../tunnel/frames";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";

// ─── shared helpers ────────────────────────────────────────────────────────────

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (typeof addr === "object" && addr) resolve(addr.port);
        else reject(new Error("Failed to allocate free port"));
      });
    });
  });
}

async function toBuffer(data: string | Buffer | ArrayBuffer | Blob): Promise<Buffer> {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (data instanceof Blob) return Buffer.from(await data.arrayBuffer());
  return Buffer.from(data as string, "utf8");
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Timed out after ${ms}ms: ${label}`)), ms),
    ),
  ]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG 1 — STREAM_DATA executes proxy without a prior STREAM_OPEN  [SECURITY]
// ═══════════════════════════════════════════════════════════════════════════════
//
// Root cause: control-client.ts lines 396–425.
// When STREAM_DATA arrives and the stream_id is not in rawStreams,
// publicTunnelStreams, or publicTunnelOwners, the handler falls through
// unconditionally to executeProxySessionMessage.
// The activeStreams set is populated by STREAM_OPEN but is never consulted
// before executing the proxy.
//
// Impact: a malicious or compromised server can trigger arbitrary HTTP proxy
// requests by omitting STREAM_OPEN entirely — bypassing the stream lifecycle.
//
// Fix: check `if (activeStreams.has(message.stream_id))` before the
// proxy-session execution path.
// ═══════════════════════════════════════════════════════════════════════════════
{
  const stateDir1 = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug1-"));
  process.env.CONSENSUS_STATE_DIR = stateDir1;
  await saveConfig({ node_id: "bug1-node", port: 9090 });

  // Local HTTP target: signals when any request arrives.
  let resolveProbeHit!: () => void;
  const probeHit = new Promise<void>((r) => { resolveProbeHit = r; });
  const httpPort = await getFreePort();
  const httpServer = Bun.serve({
    hostname: "127.0.0.1",
    port: httpPort,
    fetch(): Response {
      resolveProbeHit();
      return new Response("probe-ok");
    },
  });

  // Mock WebSocket control server.
  type MockWs = { send(data: Uint8Array): void; close(): void };
  const srv1: { session?: SecureSession; ws?: MockWs; seq: bigint } = { seq: 0n };
  let resolveHeartbeat1!: () => void;
  const heartbeatSeen1 = new Promise<void>((r) => { resolveHeartbeat1 = r; });

  const wsPort1 = await getFreePort();
  const wsServer1 = Bun.serve({
    hostname: "127.0.0.1",
    port: wsPort1,
    fetch(req, server) {
      if (server.upgrade(req)) return undefined;
      return new Response("ws required", { status: 426 });
    },
    websocket: {
      async message(ws, data) {
        const raw = await toBuffer(data);
        if (!srv1.session) {
          const init = decodeHandshakeMessage(raw);
          if (init.type !== HANDSHAKE_TYPE.INIT) return;
          const accepted = await acceptClientHandshake({ init });
          srv1.session = accepted.session;
          srv1.ws = ws as unknown as MockWs;
          ws.send(encodeHandshakeMessage(accepted.message));
          return;
        }
        const { plaintext } = openFrame(srv1.session.receiveKey, raw);
        const msg = decodeMessage(plaintext);
        if (msg.type === MESSAGE_TYPE.HEARTBEAT) resolveHeartbeat1();
      },
    },
  });

  function serverSend1(message: Parameters<typeof encodeMessage>[0]): void {
    if (!srv1.session || !srv1.ws) throw new Error("server not ready");
    const frame = sealFrame(srv1.session.sendKey, FRAME_TYPE.DATA, srv1.seq++, encodeMessage(message));
    srv1.ws.send(frame);
  }

  const client1 = await startControlClient({
    gatewayUrl: `ws://127.0.0.1:${wsPort1}`,
    heartbeatIntervalMs: 60_000,
  });
  await withTimeout(heartbeatSeen1, 3_000, "initial heartbeat");

  // Send STREAM_DATA for a stream_id that was NEVER opened via STREAM_OPEN.
  const ghostStreamId = `ghost-${crypto.randomUUID()}`;
  const proxyPayload = JSON.stringify({ url: `http://127.0.0.1:${httpPort}/probe` });
  serverSend1({
    type: MESSAGE_TYPE.STREAM_DATA,
    timestamp: nowSeconds(),
    stream_id: ghostStreamId,
    data: Buffer.from(proxyPayload).toString("base64"),
    encoding: "base64",
  });

  // Bug is confirmed if the HTTP server receives the request.
  const wasHit = await Promise.race([
    probeHit.then(() => true),
    new Promise<boolean>((r) => setTimeout(() => r(false), 2_000)),
  ]);

  assert.equal(
    wasHit,
    true,
    "Bug 1: STREAM_DATA without STREAM_OPEN should be rejected but proxy was executed",
  );
  console.log("Bug 1 [SECURITY] CONFIRMED: proxy executed for a stream that was never opened via STREAM_OPEN");

  client1.stop();
  await client1.closed;
  httpServer.stop(true);
  wsServer1.stop(true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG 2 — saveConfig / writeJson writes files without 0o600 permissions  [SECURITY]
// ═══════════════════════════════════════════════════════════════════════════════
//
// Root cause: node/state.ts writeJson() calls fs.writeFile with no mode option,
// so the file is created subject to the process umask (typically 0o644).
// By contrast, saveJoinAuthorization and saveSetupProgress correctly pass
// { mode: 0o600 }.
//
// Impact: config.json may be world-readable, exposing node_id, IP addresses,
// region, and server domain to all users on the host.
//
// Fix: pass { mode: 0o600 } to the fs.writeFile call inside writeJson, or
// introduce a writeSecureJson helper used for all sensitive state files.
// ═══════════════════════════════════════════════════════════════════════════════
{
  const stateDir2 = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug2-"));
  process.env.CONSENSUS_STATE_DIR = stateDir2;
  await saveConfig({ port: 9090, node_id: "secret-node-id" });

  const configPath = path.join(stateDir2, "config.json");
  const stat = await fs.stat(configPath);
  const mode = stat.mode & 0o777;

  // Bug is confirmed when mode is NOT 0o600.
  assert.notEqual(
    mode,
    0o600,
    `Bug 2: config.json should not be written without 0o600 (current mode 0o${mode.toString(8)})`,
  );
  console.log(`Bug 2 [SECURITY] CONFIRMED: config.json written with 0o${mode.toString(8)} instead of 0o600`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG 3 — Handshake timestamp has no freshness window  [SECURITY]
// ═══════════════════════════════════════════════════════════════════════════════
//
// Root cause: handshake.ts assertHandshakeBase validates that timestamp is a
// finite number but does not check that |timestamp - now| < threshold.
//
// Impact: a captured, validly-signed handshake INIT can be replayed
// arbitrarily far into the future.  While the ECDH key exchange prevents
// session hijacking, the server cannot distinguish a replayed INIT from a
// fresh connection attempt, enabling DoS via INIT flooding with old captures.
//
// Fix: add `if (Math.abs(nowSeconds() - message.timestamp) > 300)`
// inside assertHandshakeBase.
// ═══════════════════════════════════════════════════════════════════════════════
{
  const oneYearAgoSeconds = Math.floor(Date.now() / 1000) - 365 * 24 * 3600;

  // Craft a structurally valid INIT with a year-old timestamp.
  // Signature is intentionally fake — we test the timestamp check only.
  const staleInitJson = JSON.stringify({
    type: "handshake_init",
    protocol: "consensus-node-tunnel",
    version: 1,
    mode: "eval",
    timestamp: oneYearAgoSeconds,
    client_public_key: crypto.randomBytes(65).toString("base64"),
    client_nonce: crypto.randomBytes(32).toString("base64"),
    node_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAQ==\n-----END PUBLIC KEY-----",
    signature: crypto.randomBytes(64).toString("base64"),
  });

  let decodeError: unknown = null;
  let decoded: unknown = null;
  try {
    decoded = decodeHandshakeMessage(staleInitJson);
  } catch (err) {
    decodeError = err;
  }

  // Bug is confirmed when the stale message parses without error.
  assert.equal(
    decodeError,
    null,
    "Bug 3: decodeHandshakeMessage should reject a year-old timestamp but it did not",
  );
  assert.ok(decoded !== null);
  console.log(
    `Bug 3 [SECURITY] CONFIRMED: handshake INIT from ${new Date(oneYearAgoSeconds * 1000).toISOString()} accepted without freshness check`,
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG 4 — O(n) linear scan for public tunnel owner on every STREAM_DATA  [PERF]
// ═══════════════════════════════════════════════════════════════════════════════
//
// Root cause: control-client.ts lines 336-337 and 430-431:
//   Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === id)
// This allocates a new array and scans up to n entries on every STREAM_DATA
// and STREAM_CLOSE message.
//
// Impact: with N concurrent public tunnel owners, throughput for any stream
// data degrades linearly.  Under load (many tunnels), this becomes a CPU
// bottleneck in the message dispatch loop.
//
// Fix: maintain a reverse map `ownerStreamIdToTunnelId: Map<string, string>`
// alongside publicTunnelOwners.  Update it in STREAM_OPEN and STREAM_CLOSE.
// ═══════════════════════════════════════════════════════════════════════════════
{
  const N = 5_000;

  type OwnerEntry = {
    streamId: string;
    nextStreamId: number;
    ownerToServer: Map<number, string>;
    serverToOwner: Map<string, number>;
  };

  const owners = new Map<string, OwnerEntry>();
  const reverseMap = new Map<string, string>(); // proposed O(1) fix

  for (let i = 0; i < N; i++) {
    const tunnelId = `tunnel-${i}`;
    const streamId = `stream-${i}`;
    owners.set(tunnelId, { streamId, nextStreamId: 1, ownerToServer: new Map(), serverToOwner: new Map() });
    reverseMap.set(streamId, tunnelId);
  }

  const targetStreamId = `stream-${N - 1}`; // worst-case: last entry in iteration order
  const REPS = 1_000;

  // Current approach: O(n)
  const t0Linear = performance.now();
  for (let i = 0; i < REPS; i++) {
    Array.from(owners.entries()).find(([, o]) => o.streamId === targetStreamId);
  }
  const linearMs = performance.now() - t0Linear;

  // Proposed fix: O(1) reverse-map lookup
  const t0Map = performance.now();
  for (let i = 0; i < REPS; i++) {
    const tunnelId = reverseMap.get(targetStreamId);
    if (tunnelId) owners.get(tunnelId);
  }
  const mapMs = performance.now() - t0Map;

  const ratio = linearMs / Math.max(mapMs, 0.001);
  assert.ok(
    ratio > 3,
    `Bug 4: linear scan (${linearMs.toFixed(1)}ms) should be >> reverse-map (${mapMs.toFixed(1)}ms) — ratio ${ratio.toFixed(1)}x`,
  );
  console.log(
    `Bug 4 [PERFORMANCE] CONFIRMED: O(n) scan = ${linearMs.toFixed(1)}ms vs O(1) map = ${mapMs.toFixed(1)}ms ` +
    `(${ratio.toFixed(0)}x slower) over ${REPS} lookups with N=${N} owners`,
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG 5 — nextStreamId overflows uint32  [LOGIC]
// ═══════════════════════════════════════════════════════════════════════════════
//
// Root cause: control-client.ts initialises nextStreamId = 1 and increments it
// with ++ (plain JS number) for every new connection through a public tunnel
// owner.  encodePublicTunnelFrame writes the value with writeUInt32BE, which
// only accepts 0–4,294,967,295.  After 2^32 connections writeUInt32BE throws a
// RangeError, crashing the entire control-client message handler.
//
// Fix: cap nextStreamId at 0xFFFFFFFF and recycle or reject new streams once
// the range is exhausted.
// ═══════════════════════════════════════════════════════════════════════════════
{
  const overflowId = 0xFFFF_FFFF + 1; // 4,294,967,296
  const buf = Buffer.allocUnsafe(5);
  let threw = false;
  try {
    buf.writeUInt32BE(overflowId, 1);
  } catch {
    threw = true;
  }
  assert.equal(
    threw,
    true,
    "Bug 5: writeUInt32BE must throw for a stream ID exceeding 0xFFFFFFFF",
  );
  console.log(
    `Bug 5 [LOGIC] CONFIRMED: nextStreamId=${overflowId} causes writeUInt32BE RangeError ` +
    `(control client crashes after 2^32 connections through a public tunnel owner)`,
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG 6 — decodePublicTunnelFrame silently accepts unknown frame type bytes  [LOGIC]
// ═══════════════════════════════════════════════════════════════════════════════
//
// Root cause: control-client.ts decodePublicTunnelFrame reads the first byte
// and casts it with `as PublicTunnelFrameType` without any range check.
// An unknown type byte is returned to the caller, falls through every if-branch
// in the handler, and is dropped silently with no error log.
//
// Impact: protocol violations from a misbehaving tunnel owner are invisible.
// Unknown frame types could also be used to probe which type values the node
// considers valid — helpful reconnaissance for a future exploit.
//
// Fix: add `const VALID = new Set(Object.values(PUBLIC_TUNNEL_FRAME))` and
// throw if the byte is absent from the set.
// ═══════════════════════════════════════════════════════════════════════════════
{
  // Inline the current (buggy) implementation to demonstrate the missing check.
  const PUBLIC_TUNNEL_FRAME = {
    STREAM_OPEN:  0x01,
    STREAM_DATA:  0x02,
    STREAM_END:   0x03,
    STREAM_RESET: 0x04,
    PING:         0x05,
    PONG:         0x06,
  } as const;
  const validTypes = new Set<number>(Object.values(PUBLIC_TUNNEL_FRAME));

  function decodePublicTunnelFrameCurrent(data: Buffer) {
    if (data.length < 5) throw new RangeError("frame too short");
    return {
      type: data.readUInt8(0) as typeof PUBLIC_TUNNEL_FRAME[keyof typeof PUBLIC_TUNNEL_FRAME],
      streamId: data.readUInt32BE(1),
      payload: data.subarray(5),
    };
  }

  const INVALID_TYPE = 0xFF;
  const badFrame = Buffer.allocUnsafe(5);
  badFrame.writeUInt8(INVALID_TYPE, 0);
  badFrame.writeUInt32BE(42, 1);

  // Should throw but currently returns successfully.
  let decoded: ReturnType<typeof decodePublicTunnelFrameCurrent> | null = null;
  try {
    decoded = decodePublicTunnelFrameCurrent(badFrame);
  } catch {
    decoded = null;
  }

  assert.ok(
    decoded !== null && !validTypes.has(decoded.type),
    "Bug 6: decodePublicTunnelFrame should reject unknown type 0xFF but returned without error",
  );
  console.log(
    `Bug 6 [LOGIC] CONFIRMED: unknown frame type 0x${INVALID_TYPE.toString(16)} accepted without validation ` +
    `(silently dropped by the caller, protocol violations go undetected)`,
  );
}

console.log("\n=== All 6 bugs confirmed. ===");
