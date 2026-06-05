/**
 * Daily Security Bug Hunt — 2026-06-05
 *
 * Three confirmed bugs, ranked by severity:
 *
 *  Bug 1 – CRITICAL  SSRF via proxy (proxy-command.ts:9, proxy-worker.ts:16)
 *    target_url is passed directly to fetch() with zero host/scheme validation.
 *    Any tunnel peer can force the node to probe localhost or LAN services.
 *
 *  Bug 2 – HIGH  Unbounded stream creation → memory DoS (control-client.ts:196)
 *    activeStreams.add(stream_id) has no upper bound.  A malicious gateway can
 *    open thousands of "proxy-session" streams and exhaust node memory.
 *
 *  Bug 3 – HIGH  Unbounded pending request queue (tunnel-client.ts:116)
 *    TunnelClient.request() pushes to this.pending with no size cap.
 *    Each unanswered request holds a live setTimeout for requestTimeoutMs.
 *    100 concurrent requests → 100 timers → linear memory growth with no brake.
 *
 * Each section below:
 *   1. Confirms the bug is real and exploitable today.
 *   2. States what a fix should enforce.
 */

import assert from "node:assert/strict";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";

import { executeProxyCommand } from "../runtime/proxy-command";
import {
  MESSAGE_TYPE,
  nowSeconds,
  encodeMessage,
  decodeMessage,
} from "../tunnel/messages";
import {
  acceptClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
} from "../tunnel/handshake";
import {
  sealFrame,
  openFrame,
  generateHandshakeKeyPair,
  deriveSecureSession,
  randomHandshakeNonce,
  type SecureSession,
} from "../crypto/secure-channel";
import { FRAME_TYPE } from "../tunnel/frames";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";
import { TunnelClient } from "../tunnel/tunnel-client";

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (typeof addr === "object" && addr) resolve(addr.port);
        else reject(new Error("port allocation failed"));
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

// ─────────────────────────────────────────────────────────────────────────────
// Bug 1: SSRF — proxy fetches any URL with no host/scheme validation
//
// Root cause:  proxy-command.ts:9
//   const response = await fetch(message.target_url, { ... });
//
// Impact:  A gateway-controlled peer sends PROXY_REQUEST with
//   target_url = "http://127.0.0.1:<port>/admin" and the node fetches it.
//   This exposes every service listening on loopback, LAN, and cloud-metadata
//   endpoints (169.254.169.254) to the gateway operator.
//
// Fix:  Parse the URL; reject non-http(s) schemes; resolve the hostname and
//   block RFC-1918, loopback (127.0.0.0/8), and link-local (169.254.0.0/16).
// ─────────────────────────────────────────────────────────────────────────────
{
  console.log("=== Bug 1: SSRF in executeProxyCommand ===");
  console.log("EXPECTED: requests to loopback/private hosts should be rejected");
  console.log("ACTUAL:   all URLs accepted — proof below\n");

  // Stand up a fake "internal" HTTP service that should be unreachable to
  // anyone outside localhost.
  const internalServer = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      return new Response(
        JSON.stringify({ secret: "db-password-12345", env: "production" }),
        { headers: { "content-type": "application/json" } },
      );
    },
  });

  try {
    const result = await executeProxyCommand({
      type: MESSAGE_TYPE.PROXY_REQUEST,
      id: "ssrf-test",
      timestamp: nowSeconds(),
      // A real attacker supplies this URL through the encrypted tunnel.
      target_url: `http://127.0.0.1:${internalServer.port}/internal/secrets`,
      method: "GET",
    });

    // The call succeeds — that IS the bug.
    // A hardened proxy would throw or return status 403 before reaching fetch().
    assert.equal(result.status, 200,
      "SSRF: proxy reached loopback service without any URL validation");

    const body = JSON.parse(
      Buffer.from(result.body ?? "", "base64").toString("utf8"),
    );
    assert.equal(body.secret, "db-password-12345",
      "SSRF: sensitive internal data exfiltrated via proxy");

    console.log(
      `[CONFIRMED] Proxy fetched http://127.0.0.1:${internalServer.port} → ` +
      `status=${result.status}, leaked secret="${body.secret}"\n`,
    );
  } finally {
    internalServer.stop();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bug 2: Unbounded stream creation — memory DoS
//
// Root cause:  control-client.ts:196
//   if (message.target === "proxy-session") {
//     activeStreams.add(message.stream_id);  // ← no size check
//     return;
//   }
//
// Impact:  A malicious gateway floods the node with STREAM_OPEN messages for
//   "proxy-session".  Each message adds one string to a Set with no eviction.
//   Heartbeats confirm the count; the node OOMs silently.
//
// Fix:  Enforce a MAX_ACTIVE_STREAMS limit (e.g. 500).  Reject new
//   STREAM_OPEN messages with an error when the cap is reached.
// ─────────────────────────────────────────────────────────────────────────────
{
  console.log("=== Bug 2: Unbounded stream creation in control client ===");
  console.log("EXPECTED: active stream count should be capped at a safe maximum");
  console.log("ACTUAL:   streams accumulate without limit — proof below\n");

  process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
    path.join(os.tmpdir(), "consensus-security-test-"),
  );
  await saveConfig({ node_id: "security-test-node", port: 9090 });

  const STREAM_FLOOD_COUNT = 200;
  let serverSession: SecureSession | undefined;
  let serverSeq = 0n;
  let streamsInjected = false;

  let resolveStreamCount!: (n: number) => void;
  const streamCountSeen = new Promise<number>((r) => {
    resolveStreamCount = r;
  });

  // Server-side helper: seal a tunnel message and push it to the client.
  function serverSend(ws: { send: (d: Uint8Array) => void }, message: unknown) {
    const payload = encodeMessage(message as Parameters<typeof encodeMessage>[0]);
    const frame = sealFrame(serverSession!.sendKey, FRAME_TYPE.DATA, serverSeq++, payload);
    ws.send(frame);
  }

  const streamServer = Bun.serve({
    hostname: "127.0.0.1",
    port: await getFreePort(),
    fetch(request, server) {
      if (server.upgrade(request)) return undefined;
      return new Response("websocket required", { status: 426 });
    },
    websocket: {
      async message(ws, data) {
        const raw = await toBuffer(data as string | Buffer);

        // First message: crypto handshake init (unencrypted).
        if (!serverSession) {
          const init = decodeHandshakeMessage(raw);
          const accepted = await acceptClientHandshake({ init });
          serverSession = accepted.session;
          ws.send(encodeHandshakeMessage(accepted.message));
          return;
        }

        // Subsequent messages: encrypted tunnel frames.
        const opened = openFrame(serverSession.receiveKey, raw);
        const msg = decodeMessage(opened.plaintext);

        if (msg.type !== MESSAGE_TYPE.HEARTBEAT) return;

        const activeStreams: number = (msg as Record<string, unknown>).active_streams as number ?? 0;

        if (!streamsInjected) {
          // First heartbeat (active_streams=0): flood the client with stream opens.
          streamsInjected = true;
          for (let i = 0; i < STREAM_FLOOD_COUNT; i++) {
            serverSend(ws, {
              type: MESSAGE_TYPE.STREAM_OPEN,
              timestamp: nowSeconds(),
              stream_id: `flood-stream-${i}`,
              target: "proxy-session",
            });
          }
          return;
        }

        // Second heartbeat should reflect all injected streams.
        if (activeStreams >= STREAM_FLOOD_COUNT) {
          resolveStreamCount(activeStreams);
        }
      },
    },
  });

  const control = await startControlClient({
    gatewayUrl: `ws://127.0.0.1:${streamServer.port}`,
    heartbeatIntervalMs: 400,
  });

  const observed = await Promise.race([
    streamCountSeen,
    new Promise<number>((_, reject) =>
      setTimeout(
        () => reject(new Error("timed out waiting for flooded stream heartbeat")),
        10_000,
      ),
    ),
  ]);

  assert.ok(
    observed >= STREAM_FLOOD_COUNT,
    `Bug 2: expected active_streams >= ${STREAM_FLOOD_COUNT}, got ${observed}`,
  );

  console.log(
    `[CONFIRMED] Control client accepted ${observed} streams with no upper bound.\n` +
    `            Heartbeat reported active_streams=${observed}; no rejection occurred.\n`,
  );

  control.stop();
  await control.closed.catch(() => undefined);
  streamServer.stop(true);
}

// ─────────────────────────────────────────────────────────────────────────────
// Bug 3: Unbounded pending request queue — timer/memory leak
//
// Root cause:  tunnel-client.ts:116
//   this.pending.set(id, { resolve, reject, timer });  // ← no max size check
//
// Impact:  Each unanswered request occupies an entry in the Map and holds a
//   live setTimeout for `requestTimeoutMs` (default 30 s).
//   An attacker (or a slow/broken gateway) that never replies allows callers
//   to accumulate N requests × 30 s of live timers simultaneously.
//   100 inflight requests = 100 timer handles + 100 Promise closures = memory
//   and file-descriptor pressure that grows linearly with no circuit-breaker.
//
// Fix:  Add a MAX_PENDING constant (e.g. 50).  In request(), check
//   `if (this.pending.size >= MAX_PENDING) reject(new Error("overloaded"))`.
// ─────────────────────────────────────────────────────────────────────────────
{
  console.log("=== Bug 3: Unbounded pending request queue in TunnelClient ===");
  console.log("EXPECTED: request() should reject immediately when queue is full");
  console.log("ACTUAL:   pending Map grows without bound — proof below\n");

  // Build a real SecureSession so sealFrame() inside TunnelClient works.
  const clientKeys = await generateHandshakeKeyPair();
  const serverKeys = await generateHandshakeKeyPair();
  const clientNonce = randomHandshakeNonce();
  const serverNonce = randomHandshakeNonce();

  const session = await deriveSecureSession({
    role: "client",
    privateKey: clientKeys.privateKey,
    peerPublicKeyRaw: serverKeys.publicKeyRaw,
    clientNonce,
    serverNonce,
  });

  // A mock WebSocket that is permanently OPEN and silently discards outbound
  // frames.  The server never replies, so every request() call stays pending.
  const mockWs = {
    readyState: 1, // WebSocket.OPEN — prevents waitForOpen() from blocking
    send: (_data: unknown) => { /* deliberately dropped */ },
    close: () => {},
    addEventListener: (_event: string, _handler: unknown) => {},
    removeEventListener: (_event: string, _handler: unknown) => {},
  } as unknown as WebSocket;

  const client = new TunnelClient({
    url: "ws://mock-never-responds",
    socket: mockWs,
    session,
    mode: "control",
    requestTimeoutMs: 60_000, // long timeout keeps requests in the queue
  });

  await client.connect(); // sends HELLO (discarded by mock)

  const FLOOD_COUNT = 100;

  // Fire FLOOD_COUNT requests without awaiting any of them.
  // Each pushes into this.pending and registers a 60-second setTimeout.
  for (let i = 0; i < FLOOD_COUNT; i++) {
    void client.request({
      type: MESSAGE_TYPE.PING,
      timestamp: nowSeconds(),
      id: `pending-flood-${i}`,
    }).catch(() => undefined); // suppress unhandled-rejection noise on cleanup
  }

  // Inspect the private pending Map via cast — this is intentional in a test.
  type TunnelClientInternal = TunnelClient & { pending: Map<string, unknown> };
  const pendingSize = (client as unknown as TunnelClientInternal).pending.size;

  assert.equal(
    pendingSize,
    FLOOD_COUNT,
    `Bug 3: expected ${FLOOD_COUNT} entries in pending queue, got ${pendingSize}`,
  );

  console.log(
    `[CONFIRMED] ${pendingSize} requests queued simultaneously with no size limit.\n` +
    `            Each holds a live 60-second setTimeout — ${pendingSize} timers running.\n`,
  );

  // Cleanup: close client so all timers are cleared via rejectAll().
  client.close(1000, "test complete");
}

console.log("=== Summary ===");
console.log("Bug 1 CONFIRMED  CRITICAL  SSRF — proxy-command.ts:9 / proxy-worker.ts:16");
console.log("Bug 2 CONFIRMED  HIGH      Unbounded streams — control-client.ts:196");
console.log("Bug 3 CONFIRMED  HIGH      Unbounded pending queue — tunnel-client.ts:116");
