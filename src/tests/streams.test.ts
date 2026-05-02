/**
 * Proves that raw TCP sockets opened via STREAM_OPEN are destroyed when the
 * control tunnel WebSocket closes.  Before the fix, the onClose handler in
 * control-client.ts never iterated rawStreams, so sockets leaked until the
 * remote side timed them out.  With the fix, destroy() is called on every
 * socket in rawStreams, which causes the TCP server-side socket to receive a
 * close event within milliseconds.
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
} from "../tunnel/handshake";
import { MESSAGE_TYPE, decodeMessage, encodeMessage, nowSeconds } from "../tunnel/messages";
import { openFrame, sealFrame, type SecureSession } from "../crypto/secure-channel";
import { FRAME_TYPE } from "../tunnel/frames";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";

const nodeId = "node-streams-test";
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-streams-test-"));
await saveConfig({ node_id: nodeId, port: 9090 });

// ---- TCP target server ----------------------------------------------------
// Accepts one connection, then tracks whether the client destroys it.

let resolveTcpConnected!: (socket: net.Socket) => void;
const tcpConnected = new Promise<net.Socket>((r) => { resolveTcpConnected = r; });
let resolveTcpClosed!: () => void;
const tcpClosed = new Promise<void>((r) => { resolveTcpClosed = r; });

const tcpPort = await getFreePort();
const tcpServer = net.createServer((socket) => {
  socket.on("error", () => undefined); // suppress RST noise
  socket.on("close", () => resolveTcpClosed());
  resolveTcpConnected(socket);
});
await new Promise<void>((r) => tcpServer.listen(tcpPort, "127.0.0.1", () => r()));

// ---- Mock WebSocket control server ----------------------------------------

type ServerWs = {
  send(data: Buffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
};

const serverState: {
  session?: SecureSession;
  ws?: ServerWs;
  sendSeq: bigint;
} = { sendSeq: 0n };

let resolveHeartbeatSeen!: () => void;
const heartbeatSeen = new Promise<void>((r) => { resolveHeartbeatSeen = r; });

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
        const accepted = await acceptClientHandshake({ init });
        serverState.session = accepted.session;
        serverState.ws = ws as unknown as ServerWs;
        ws.send(encodeHandshakeMessage(accepted.message));
        return;
      }
      const { plaintext } = openFrame(serverState.session.receiveKey, raw);
      const message = decodeMessage(plaintext);
      if (message.type === MESSAGE_TYPE.HEARTBEAT) resolveHeartbeatSeen();
    },
  },
});

// ---- Connect the control client -------------------------------------------

const connected = await startControlClient({
  gatewayUrl: `ws://127.0.0.1:${wsServer.port}`,
  heartbeatIntervalMs: 60_000,
});

// Wait until the handshake + initial heartbeat are both complete so the
// message handler is fully registered before we send STREAM_OPEN.
await heartbeatSeen;

// ---- Server sends STREAM_OPEN pointing at our local TCP server ------------

const streamId = crypto.randomUUID();
serverSend({
  type: MESSAGE_TYPE.STREAM_OPEN,
  timestamp: nowSeconds(),
  stream_id: streamId,
  target: JSON.stringify({ kind: "raw-tunnel", host: "127.0.0.1", port: tcpPort }),
});

// Wait for the TCP connection to appear (proves the client handled STREAM_OPEN)
const _tcpSocket = await Promise.race([
  tcpConnected,
  new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error("TCP connection not established within 2 s")), 2_000),
  ),
]);

// ---- Close the WebSocket from the server side -----------------------------
// Before the fix: rawStreams sockets are never destroyed → tcpClosed never
// resolves → the race below returns false → assertion fails.
// After the fix:  destroy() is called → TCP server sees 'close' → resolves.

serverState.ws!.close(1001, "test closing");

const socketWasCleaned = await Promise.race([
  tcpClosed.then(() => true),
  new Promise<boolean>((r) => setTimeout(() => r(false), 1_500)),
]);

assert.equal(
  socketWasCleaned,
  true,
  "Raw TCP socket must be destroyed when the control tunnel closes (resource-leak fix)",
);

// ---- Teardown -------------------------------------------------------------
connected.stop();
tcpServer.close();
wsServer.stop(true);

console.log("streams ok");

// ---------------------------------------------------------------------------

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
