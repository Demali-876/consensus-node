import assert from "node:assert/strict";
import net from "node:net";
import {
  acceptClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
} from "../tunnel/handshake";
import { MESSAGE_TYPE, decodeMessage } from "../tunnel/messages";
import { openFrame, type SecureSession } from "../crypto/secure-channel";
import { startEvalClient } from "../clients/eval-client";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// startEvalClient loads the node identity; keep that off the operator's real state.
const stateRoot = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-eval-client-"));
process.env.CONSENSUS_STATE_DIR = stateRoot;
process.env.CONSENSUS_NODE_SECRET_KEY = crypto.randomBytes(32).toString("base64");

const state: { serverSession?: SecureSession } = {};
let helloSeenResolve: (() => void) | null = null;
const helloSeen = new Promise<void>((resolve) => {
  helloSeenResolve = resolve;
});

const server = Bun.serve({
  hostname: "127.0.0.1",
  port: await getFreePort(),
  fetch(request, server) {
    if (server.upgrade(request)) return undefined;
    return new Response("websocket required", { status: 426 });
  },
  websocket: {
    async message(ws, data) {
      const raw = await toBuffer(data);
      if (!state.serverSession) {
        const init = decodeHandshakeMessage(raw);
        assert.equal(init.type, "handshake_init");
        const accepted = await acceptClientHandshake({ init });
        state.serverSession = accepted.session;
        ws.send(encodeHandshakeMessage(accepted.message));
        return;
      }

      const opened = openFrame(state.serverSession.receiveKey, raw);
      const message = decodeMessage(opened.plaintext);
      assert.equal(message.type, MESSAGE_TYPE.HELLO);
      assert.equal(message.mode, "eval");
      helloSeenResolve?.();
    },
  },
});

const connected = await startEvalClient({
  gatewayUrl: `ws://127.0.0.1:${server.port}`,
  candidateId: "candidate-e2e",
});

await helloSeen;
const session = state.serverSession;
assert.ok(session);
assert.equal(connected.sessionId, session.sessionId);

connected.client.close();
server.stop(true);

console.log("eval-client ok");

async function toBuffer(data: string | Buffer): Promise<Buffer> {
  if (Buffer.isBuffer(data)) return data;
  return Buffer.from(data, "utf8");
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = net.createServer();
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", () => {
      const address = socket.address();
      socket.close(() => {
        if (typeof address === "object" && address) resolve(address.port);
        else reject(new Error("Failed to allocate free port"));
      });
    });
  });
}

await fs.rm(stateRoot, { recursive: true, force: true });
