/**
 * Daily bug-hunt — 2026-05-16
 *
 * Three bugs found, fixed, and proven here:
 *
 *   Bug 1  /benchmark/cpu — unbounded iterations DoS
 *          body.iterations was used directly in the SHA-256 loop with no
 *          integerParam() clamping.  Every other benchmark used integerParam().
 *          An attacker sending iterations=1_000_000_000 stalls the Bun event
 *          loop indefinitely.  body.data also had no size cap, amplifying
 *          the CPU work per request.
 *          Fix: integerParam(body.iterations, 1_000, 1, 200_000) + 4 KB data cap.
 *
 *   Bug 2  control-client STREAM_DATA processed without STREAM_OPEN guard
 *          When STREAM_DATA arrived for a stream_id that was not in rawStreams
 *          the code fell through directly to executeProxySessionMessage()
 *          without checking activeStreams.has(stream_id).  A server could
 *          trigger proxy execution for arbitrary / already-closed streams.
 *          Fix: reject STREAM_DATA with ERROR(stream_not_open) if stream_id
 *          is absent from activeStreams.
 *
 *   Bug 3  Handshake timestamp not validated — replay DoS
 *          assertHandshakeBase verified that timestamp is a finite number but
 *          never checked clock skew.  A captured INIT message signed by a
 *          valid node key could be replayed indefinitely, forcing the server
 *          to perform expensive ECDH key derivation without ever producing a
 *          usable session.
 *          Fix: reject timestamps outside ±300 s of the current clock.
 */

import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  acceptClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
  HANDSHAKE_TYPE,
} from "../tunnel/handshake";
import {
  MESSAGE_TYPE,
  decodeMessage,
  encodeMessage,
  nowSeconds,
  type TunnelMessage,
} from "../tunnel/messages";
import { openFrame, sealFrame, type SecureSession } from "../crypto/secure-channel";
import { FRAME_TYPE } from "../tunnel/frames";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";
import { buildServer } from "../runtime/server";

// ---------------------------------------------------------------------------
// Shared state-dir (isolates all filesystem side-effects)
// ---------------------------------------------------------------------------

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-bug-hunt-2026-05-16-"),
);
await saveConfig({ node_id: "node-bug-hunt-2026-05-16", port: 9090 });

// ============================================================================
// Bug 1 — /benchmark/cpu: unbounded iterations + unbounded data size
// ============================================================================

{
  const app = await buildServer();
  await app.ready();

  // --- 1a: iterations must be clamped to MAX_CPU_ITERATIONS (200_000) -------
  // Before fix: body.iterations used directly → loop runs 999_999 times →
  //             event loop stalls for ~200 ms per request (scales to hours
  //             with 10^9 iterations).
  // After fix:  integerParam clamps to 200_000; returned iterations field
  //             reflects the clamped value.

  const overIterResp = await app.inject({
    method: "POST",
    url: "/benchmark/cpu",
    headers: { "content-type": "application/json" },
    payload: { iterations: 999_999, data: "a" },
  });

  assert.equal(overIterResp.statusCode, 200, "CPU benchmark must succeed with valid input");

  const overIterBody = overIterResp.json<{ success: boolean; iterations: number }>();
  assert.ok(
    overIterBody.iterations <= 200_000,
    `iterations must be clamped to ≤200_000, got ${overIterBody.iterations}` +
    ` — unbounded body.iterations is a single-threaded event-loop DoS vector`,
  );

  // --- 1b: data field must be bounded (MAX_CPU_DATA_BYTES = 4_096) ----------
  // Before fix: body.data accepted at any length → 100 KB input × many
  //             iterations = large amplified memory + CPU cost per request.
  // After fix:  400 error when data.length > 4_096.

  const largeDataResp = await app.inject({
    method: "POST",
    url: "/benchmark/cpu",
    headers: { "content-type": "application/json" },
    payload: { iterations: 1, data: "x".repeat(5_000) },
  });

  assert.equal(
    largeDataResp.statusCode,
    400,
    `CPU benchmark must reject data longer than 4_096 chars, ` +
    `got HTTP ${largeDataResp.statusCode} — oversized data amplifies per-request CPU work`,
  );

  await app.close();
  console.log("bug1 (cpu-benchmark-dos) ok");
}

// ============================================================================
// Bug 2 — STREAM_DATA processed without STREAM_OPEN guard
// ============================================================================

{
  type ServerWs = { send(data: Buffer | Uint8Array): void; close(code?: number, reason?: string): void };

  const serverState: {
    session?: SecureSession;
    ws?: ServerWs;
    sendSeq: bigint;
    heartbeatSeen: boolean;
  } = { sendSeq: 0n, heartbeatSeen: false };

  let resolveHeartbeat!: () => void;
  const heartbeatPromise = new Promise<void>((r) => { resolveHeartbeat = r; });

  let resolveNodeResponse!: (msg: TunnelMessage) => void;
  let rejectNodeResponse!: (e: Error) => void;
  const nodeResponsePromise = new Promise<TunnelMessage>((res, rej) => {
    resolveNodeResponse = res;
    rejectNodeResponse = rej;
  });

  function serverSend(message: TunnelMessage): void {
    if (!serverState.session || !serverState.ws) throw new Error("no server session");
    const frame = sealFrame(
      serverState.session.sendKey,
      FRAME_TYPE.DATA,
      serverState.sendSeq++,
      encodeMessage(message),
    );
    serverState.ws.send(frame);
  }

  const wsPort = await getFreePort();
  const wsServer = Bun.serve({
    hostname: "127.0.0.1",
    port: wsPort,
    fetch(request, server) {
      if (server.upgrade(request)) return undefined;
      return new Response("websocket required", { status: 426 });
    },
    websocket: {
      async message(ws, data) {
        const raw = await toBuffer(data);

        if (!serverState.session) {
          const init = decodeHandshakeMessage(raw);
          if (init.type !== HANDSHAKE_TYPE.INIT) {
            throw new Error(`Expected handshake init, got ${init.type}`);
          }
          const accepted = await acceptClientHandshake({ init });
          serverState.session = accepted.session;
          serverState.ws = ws as unknown as ServerWs;
          ws.send(encodeHandshakeMessage(accepted.message));
          return;
        }

        const { plaintext } = openFrame(serverState.session.receiveKey, raw);
        const message = decodeMessage(plaintext);

        if (message.type === MESSAGE_TYPE.HELLO) return;

        if (!serverState.heartbeatSeen && message.type === MESSAGE_TYPE.HEARTBEAT) {
          serverState.heartbeatSeen = true;
          resolveHeartbeat();
          return;
        }

        if (serverState.heartbeatSeen) {
          resolveNodeResponse(message);
        }
      },
    },
  });

  const nodeId2 = "node-stream-guard-test";
  await saveConfig({ node_id: nodeId2, port: 9090 });

  const connected = await startControlClient({
    gatewayUrl: `ws://127.0.0.1:${wsServer.port}`,
    heartbeatIntervalMs: 60_000,
  });

  await Promise.race([
    heartbeatPromise,
    new Promise<never>((_, rej) =>
      setTimeout(() => rej(new Error("Heartbeat not received within 3 s")), 3_000),
    ),
  ]);

  // Send STREAM_DATA for a stream_id that was NEVER opened via STREAM_OPEN.
  // Payload is invalid JSON so executeProxySessionMessage returns immediately
  // (no real network call), making the test fast in both pre- and post-fix code.
  const orphanStreamId = crypto.randomUUID();
  const badPayload = Buffer.from("not-valid-json").toString("base64");
  serverSend({
    type: MESSAGE_TYPE.STREAM_DATA,
    timestamp: nowSeconds(),
    stream_id: orphanStreamId,
    data: badPayload,
    encoding: "base64",
  });

  const nodeResponse = await Promise.race([
    nodeResponsePromise,
    new Promise<never>((_, rej) =>
      setTimeout(() => rej(new Error("No response from node within 3 s")), 3_000),
    ),
  ]);

  // Before fix: node runs executeProxySessionMessage → sends STREAM_DATA back
  //             (proxy code executed for an unknown stream).
  // After fix:  node sends ERROR(stream_not_open) before touching proxy code.
  assert.equal(
    nodeResponse.type,
    MESSAGE_TYPE.ERROR,
    `Expected ERROR for unopened stream, got "${nodeResponse.type}" — ` +
    `STREAM_DATA processed without STREAM_OPEN guard: proxy code ran for unknown stream_id`,
  );
  if (nodeResponse.type === MESSAGE_TYPE.ERROR) {
    assert.equal(
      nodeResponse.code,
      "stream_not_open",
      `Error code must be "stream_not_open", got "${nodeResponse.code}"`,
    );
  }

  connected.stop();
  wsServer.stop(true);
  console.log("bug2 (stream-data-without-open-guard) ok");
}

// ============================================================================
// Bug 3 — Handshake timestamp not validated (replay DoS)
// ============================================================================

{
  // Construct syntactically valid INIT messages with stale / far-future
  // timestamps.  decodeHandshakeMessage → assertHandshakeMessage →
  // assertHandshakeInit → assertHandshakeBase is where the fix lives.
  // Signature correctness is irrelevant here; we are testing the timestamp
  // guard specifically (which fires before signature verification).

  const stubB64 = (s: string) => Buffer.from(s).toString("base64");

  const baseInit = {
    type: "handshake_init",
    protocol: "consensus-node-tunnel",
    version: 1,
    mode: "eval",
    client_public_key: stubB64("stub-ec-public-key"),
    client_nonce: stubB64("stub-nonce-value-16"),
    node_public_key_pem: "-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----",
    signature: stubB64("stub-signature"),
  };

  // --- 3a: stale timestamp (>300 s in the past) ----------------------------
  // Before fix: no skew check → decodeHandshakeMessage returns successfully.
  // After fix:  TypeError thrown with "timestamp" in the message.

  assert.throws(
    () => decodeHandshakeMessage(JSON.stringify({ ...baseInit, timestamp: nowSeconds() - 601 })),
    /timestamp/i,
    "Stale INIT (>5 min old) must be rejected — missing check enables replay DoS against ECDH",
  );

  // --- 3b: far-future timestamp (>300 s ahead) ------------------------------
  assert.throws(
    () => decodeHandshakeMessage(JSON.stringify({ ...baseInit, timestamp: nowSeconds() + 601 })),
    /timestamp/i,
    "Far-future INIT must be rejected — prevents clock-skew manipulation attacks",
  );

  // --- 3c: fresh timestamp must still be accepted ---------------------------
  // The structural parse should succeed; signature invalidity is a separate
  // concern checked by verifyClientHandshake(), not decodeHandshakeMessage().
  assert.doesNotThrow(
    () => decodeHandshakeMessage(JSON.stringify({ ...baseInit, timestamp: nowSeconds() })),
    "Fresh handshake INIT must not be rejected by the timestamp guard",
  );

  console.log("bug3 (handshake-timestamp-replay) ok");
}

// ============================================================================
// Helpers
// ============================================================================

async function toBuffer(data: string | Buffer | ArrayBuffer | Blob): Promise<Buffer> {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (data instanceof Blob) return Buffer.from(await data.arrayBuffer());
  return Buffer.from(data as string, "utf8");
}

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
