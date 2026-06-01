/**
 * LOGIC / SECURITY BUG: STREAM_DATA handler falls through to
 * executeProxySessionMessage() for any stream_id that does not appear in
 * rawStreams, publicTunnelOwners, or publicTunnelStreams — regardless of
 * whether that stream was ever opened with a STREAM_OPEN message.
 *
 * Proxy-session streams are added to the generic `activeStreams` Set when
 * STREAM_OPEN arrives, but the STREAM_DATA handler never consults activeStreams
 * before reaching the fallthrough branch.  Any STREAM_DATA whose stream_id
 * does not match the other, map-checked categories silently executes an HTTP
 * proxy request via executeProxySessionMessage().
 *
 * Concrete impact
 * ───────────────
 * The server can trigger arbitrary outbound HTTP requests from the node
 * without going through the normal STREAM_OPEN → STREAM_DATA lifecycle.
 * A stream that was already closed but whose stream_id is still unknown to
 * the maps will also be processed.
 *
 * Fix: track proxy-session stream IDs in a dedicated Set and guard the
 * fallthrough branch:
 *
 *   const proxySessionStreams = new Set<string>();
 *   // in STREAM_OPEN handler:
 *   if (message.target === "proxy-session") {
 *     proxySessionStreams.add(message.stream_id);
 *     activeStreams.add(message.stream_id);
 *     return;
 *   }
 *   // in STREAM_DATA fallthrough:
 *   if (!proxySessionStreams.has(message.stream_id)) {
 *     await sendStreamClose(message.stream_id, "unknown stream");
 *     return;
 *   }
 *
 * Test contract
 * ─────────────
 * The test sends STREAM_DATA with a stream_id that was NEVER opened and
 * asserts that the node does NOT execute the HTTP proxy request.
 *   • CURRENTLY FAILS  (the fallthrough bug triggers the HTTP hit)
 *   • WILL PASS after the proxySessionStreams guard is added
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
} from "../tunnel/messages";
import { openFrame, sealFrame, type SecureSession } from "../crypto/secure-channel";
import { FRAME_TYPE } from "../tunnel/frames";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";

const nodeId = "node-stream-lifecycle-test";
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-lifecycle-test-"),
);
await saveConfig({ node_id: nodeId, port: 9090 });

// ── Mock HTTP server that records inbound probe requests ─────────────────────

let resolveHttpHit!: (url: string) => void;
const httpHit = new Promise<string>((r) => {
  resolveHttpHit = r;
});

const httpPort = await getFreePort();
const httpServer = Bun.serve({
  hostname: "127.0.0.1",
  port: httpPort,
  fetch(req) {
    resolveHttpHit(req.url);
    return new Response("probe-ok");
  },
});

// ── Mock WebSocket control server ─────────────────────────────────────────────

type ServerWs = {
  send(data: Buffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
};

const serverState: {
  session?: SecureSession;
  ws?: ServerWs;
  sendSeq: bigint;
} = { sendSeq: 0n };

let resolveHeartbeat!: () => void;
const heartbeatSeen = new Promise<void>((r) => {
  resolveHeartbeat = r;
});

function serverSend(message: Parameters<typeof encodeMessage>[0]): void {
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
          throw new Error(`Expected INIT, got ${init.type}`);
        }
        const accepted = await acceptClientHandshake({ init });
        serverState.session = accepted.session;
        serverState.ws = ws as unknown as ServerWs;
        ws.send(encodeHandshakeMessage(accepted.message));
        return;
      }
      const { plaintext } = openFrame(serverState.session.receiveKey, raw);
      const message = decodeMessage(plaintext);
      if (message.type === MESSAGE_TYPE.HEARTBEAT) resolveHeartbeat();
    },
  },
});

const connected = await startControlClient({
  gatewayUrl: `ws://127.0.0.1:${wsServer.port}`,
  heartbeatIntervalMs: 60_000,
});

await heartbeatSeen;

// ── Send STREAM_DATA for a ghost stream_id (no STREAM_OPEN was ever sent) ─────
// A correct implementation must reject this and NOT make any outbound HTTP call.
// The bug causes it to fall through to executeProxySessionMessage() which then
// fetches the probe URL.

const ghostStreamId = crypto.randomUUID();

const probeRequest = JSON.stringify({
  id: "lifecycle-probe",
  url: `http://127.0.0.1:${httpPort}/probe`,
  method: "GET",
});

serverSend({
  type: MESSAGE_TYPE.STREAM_DATA,
  timestamp: nowSeconds(),
  stream_id: ghostStreamId,
  data: Buffer.from(probeRequest, "utf8").toString("base64"),
  encoding: "base64",
});

// Wait up to 1 s for the (buggy) HTTP hit to arrive.
// Correct behaviour: no hit within that window → gotHit = false → test passes.
// Buggy behaviour:   hit arrives quickly          → gotHit = true  → test fails.
const gotHit = await Promise.race([
  httpHit.then(() => true),
  new Promise<boolean>((r) => setTimeout(() => r(false), 1_000)),
]);

assert.equal(
  gotHit,
  false,
  `BUG (stream-lifecycle): STREAM_DATA for stream_id "${ghostStreamId}" ` +
  `(no prior STREAM_OPEN) triggered an HTTP proxy request. ` +
  `The STREAM_DATA handler must check that the stream_id was opened as a ` +
  `proxy-session stream before calling executeProxySessionMessage().`,
);

// ── Verify that a PROPERLY OPENED proxy-session stream still works ────────────
// This ensures the fix does not regress normal operation.

let resolveHttpHit2!: (url: string) => void;
const httpHit2 = new Promise<string>((r) => {
  resolveHttpHit2 = r;
});

// Override the http server handler for the second probe
const httpPort2 = await getFreePort();
const httpServer2 = Bun.serve({
  hostname: "127.0.0.1",
  port: httpPort2,
  fetch(req) {
    resolveHttpHit2(req.url);
    return new Response("probe2-ok");
  },
});

const realStreamId = crypto.randomUUID();

// Open the stream first
serverSend({
  type: MESSAGE_TYPE.STREAM_OPEN,
  timestamp: nowSeconds(),
  stream_id: realStreamId,
  target: "proxy-session",
});

await new Promise<void>((r) => setTimeout(r, 50)); // brief settle

// Now send data for the opened stream
const probeRequest2 = JSON.stringify({
  id: "lifecycle-probe-2",
  url: `http://127.0.0.1:${httpPort2}/probe2`,
  method: "GET",
});

serverSend({
  type: MESSAGE_TYPE.STREAM_DATA,
  timestamp: nowSeconds(),
  stream_id: realStreamId,
  data: Buffer.from(probeRequest2, "utf8").toString("base64"),
  encoding: "base64",
});

const hitUrl2 = await Promise.race([
  httpHit2,
  new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error("Opened proxy-session stream did not process STREAM_DATA within 2 s")),
      2_000,
    ),
  ),
]);

assert.ok(
  hitUrl2.includes("/probe2"),
  `A properly-opened proxy-session stream must still process STREAM_DATA after the fix`,
);

// ── Teardown ─────────────────────────────────────────────────────────────────
connected.stop();
wsServer.stop(true);
httpServer.stop(true);
httpServer2.stop(true);

console.log("stream-lifecycle ok");

// ── Helpers ───────────────────────────────────────────────────────────────────

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
