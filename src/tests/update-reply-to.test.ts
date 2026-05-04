/**
 * Proves two reply_to bugs in the update message handlers in control-client.ts.
 *
 * Bug 1 — UPDATE_PREPARE failure, no message.id:
 *   The success path uses `reply_to: message.id ?? message.update_id`, but the
 *   failure path only uses `reply_to: message.id` with no fallback.  When the
 *   server omits `id` (using update_id as the only correlation key) and the
 *   prepare step fails, the node sends UPDATE_FAILED with reply_to=undefined.
 *   TunnelClient.resolvePending skips messages without reply_to, so the
 *   server-side request() times out after 30 s instead of failing fast.
 *
 * Bug 2 — UPDATE_APPLY rejection (update_not_prepared), missing reply_to:
 *   When the node receives UPDATE_APPLY for an un-prepared update it sends back
 *   UPDATE_FAILED with code "update_not_prepared" but NO reply_to field at all.
 *   The ACK sent on the happy path correctly sets reply_to, making the omission
 *   inconsistent.  Same result: server request() times out rather than
 *   resolving immediately with the error.
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
  type UpdateFailedMessage,
} from "../tunnel/messages";
import { openFrame, sealFrame, type SecureSession } from "../crypto/secure-channel";
import { FRAME_TYPE } from "../tunnel/frames";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";
import { routesHash } from "../node/manifest";
import type { ReleaseManifest } from "../types";

const nodeId = "node-update-reply-test";
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-update-reply-test-"),
);
await saveConfig({ node_id: nodeId, port: 9090 });

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
const heartbeatSeen = new Promise<void>((r) => {
  resolveHeartbeatSeen = r;
});

const receivedUpdateFailed: UpdateFailedMessage[] = [];
const updateFailedResolvers: Array<() => void> = [];

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
          throw new Error(`Expected handshake init, received ${init.type}`);
        }
        const accepted = await acceptClientHandshake({ init });
        serverState.session = accepted.session;
        serverState.ws = ws as unknown as ServerWs;
        ws.send(encodeHandshakeMessage(accepted.message));
        return;
      }
      const { plaintext } = openFrame(serverState.session.receiveKey, raw);
      const message = decodeMessage(plaintext);
      if (message.type === MESSAGE_TYPE.HEARTBEAT) {
        resolveHeartbeatSeen();
      }
      if (message.type === MESSAGE_TYPE.UPDATE_FAILED) {
        receivedUpdateFailed.push(message);
        updateFailedResolvers.shift()?.();
      }
    },
  },
});

const connected = await startControlClient({
  gatewayUrl: `ws://127.0.0.1:${wsServer.port}`,
  heartbeatIntervalMs: 60_000,
});

await heartbeatSeen;

// ---------------------------------------------------------------------------
// Bug 1: UPDATE_PREPARE failure must fall back to update_id for reply_to
// ---------------------------------------------------------------------------
// The manifest has a different version (triggering the download path) but no
// download_url, so downloadAndVerify throws synchronously with "Required
// manifest does not include download_url".
//
// Before fix: reply_to === undefined  (message.id absent, no fallback)
// After fix:  reply_to === updateId1  (fallback to update_id like success path)

const prepareFailed = new Promise<void>((r) => updateFailedResolvers.push(r));
const updateId1 = "update-prepare-no-id-test";
const differentManifest: ReleaseManifest = {
  product: "consensus-node",
  version: "999.0.0-bugtest",
  artifact: "npm-tarball",
  platform: "linux-x64",
  commit: "deadbeef",
  routes_hash: routesHash(),
  capabilities: [],
  // No download_url → downloadAndVerify throws without network I/O
};

serverSend({
  type: MESSAGE_TYPE.UPDATE_PREPARE,
  timestamp: nowSeconds(),
  // Deliberately omit id — update_id is the only correlation key
  update_id: updateId1,
  manifest: differentManifest,
});

await Promise.race([
  prepareFailed,
  new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error("Bug 1: UPDATE_FAILED not received within 3 s")),
      3_000,
    ),
  ),
]);

const failed1 = receivedUpdateFailed.find((m) => m.update_id === updateId1);
assert.ok(failed1, "Bug 1: UPDATE_FAILED for the prepare must be received");
assert.equal(
  failed1.reply_to,
  updateId1,
  `Bug 1 (UPDATE_PREPARE failure): reply_to must fall back to update_id ` +
    `"${updateId1}" when message.id is absent — got: ${JSON.stringify(failed1.reply_to)}`,
);

// ---------------------------------------------------------------------------
// Bug 2: UPDATE_APPLY rejection (update_not_prepared) must set reply_to
// ---------------------------------------------------------------------------
// We send UPDATE_APPLY without any prior UPDATE_PREPARE.  The node should
// immediately return UPDATE_FAILED with code "update_not_prepared".
//
// Before fix: reply_to field is entirely absent → resolvePending skips it
// After fix:  reply_to === applyMsgId  (same pattern as the ACK sent on success)

const applyRejected = new Promise<void>((r) => updateFailedResolvers.push(r));
const updateId2 = "apply-no-prepare-update-id";
const applyMsgId = "apply-no-prepare-msg-id";

serverSend({
  type: MESSAGE_TYPE.UPDATE_APPLY,
  timestamp: nowSeconds(),
  id: applyMsgId,
  update_id: updateId2,
});

await Promise.race([
  applyRejected,
  new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error("Bug 2: UPDATE_FAILED not received within 3 s")),
      3_000,
    ),
  ),
]);

const failed2 = receivedUpdateFailed.find((m) => m.update_id === updateId2);
assert.ok(failed2, "Bug 2: UPDATE_FAILED for the apply rejection must be received");
assert.equal(
  failed2.code,
  "update_not_prepared",
  "Bug 2: UPDATE_FAILED code must be update_not_prepared",
);
assert.equal(
  failed2.reply_to,
  applyMsgId,
  `Bug 2 (UPDATE_APPLY rejection): reply_to must be message.id ` +
    `"${applyMsgId}" — got: ${JSON.stringify(failed2.reply_to)}`,
);

// ---- Teardown -------------------------------------------------------------
connected.stop();
wsServer.stop(true);

console.log("update-reply-to ok");

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
