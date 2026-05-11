/**
 * Daily bug hunt: 2026-05-11
 *
 * Four bugs found during manual code review, ordered by severity:
 *
 * BUG-1 [SECURITY-CRITICAL] src/update.ts:90
 *   The tarball_sha256 integrity check is guarded by `manifest.tarball_sha256 &&`,
 *   making it entirely optional. A manifest with no tarball_sha256 accepts any
 *   binary at download_url without integrity verification — a supply-chain attack
 *   vector. A compromised CDN or MITM can substitute a malicious binary and the
 *   node will install it silently.
 *   Fix: require tarball_sha256 to be present; throw if it is absent.
 *
 * BUG-2 [SECURITY-MEDIUM] src/tunnel/handshake.ts
 *   assertHandshakeBase() validates that timestamp is a finite number but never
 *   checks whether it is recent. acceptClientHandshake() therefore accepts any
 *   signed handshake init regardless of age. An attacker who captures a valid
 *   signed INIT (e.g. from a passive network tap before TLS, or a compromised
 *   log) can replay it later to open a session under the victim node's identity.
 *   Fix: reject handshakes with |timestamp − now| > MAX_HANDSHAKE_AGE_SECONDS.
 *
 * BUG-3 [PROTOCOL-MEDIUM] src/tunnel/tunnel-client.ts
 *   handleRawMessage() receives the PING frame's plaintext but never decodes it
 *   to extract PingMessage.id, so pongMessage() always returns { type:"pong" }
 *   without a reply_to field. If the server sends pings with IDs and uses
 *   request() to track RTT, the returned PONGs can never be correlated.
 *   Fix: decode the ping payload and populate reply_to in the pong response.
 *
 * BUG-4 [DOS-LOW] src/tunnel/frames.ts
 *   decodeFrame validates raw.length === HEADER + ciphertextLength + TAG (which
 *   prevents out-of-bounds reads), but ciphertextLength is a uint32 with no
 *   upper bound. A server can send a single 4 GB frame and force the client to
 *   hold the full buffer in memory. There is no guard that caps frame size.
 *   Fix: add MAX_FRAME_CIPHERTEXT_BYTES (e.g. 1 MB) and throw if exceeded.
 */

import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "../crypto/canonical-json";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import {
  generateHandshakeKeyPair,
  openFrame,
  randomHandshakeNonce,
  sealFrame,
  type SecureSession,
} from "../crypto/secure-channel";
import {
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
  acceptClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import {
  FRAME_TYPE,
  FRAME_VERSION,
  decodeFrame,
} from "../tunnel/frames";
import {
  MESSAGE_TYPE,
  TUNNEL_MODE,
  decodeMessage,
  encodeMessage,
  nowSeconds,
} from "../tunnel/messages";
import { downloadAndVerify } from "../update";
import { saveConfig } from "../node/state";
import { startControlClient } from "../clients/control-client";

// ---------------------------------------------------------------------------
// Shared isolated state directory for all sub-tests in this file
// ---------------------------------------------------------------------------
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-bughunt-2026-05-11-"),
);
await saveConfig({ port: 9090, node_id: "bug-hunt-node" });

// ===========================================================================
// BUG-1 [SECURITY-CRITICAL] — tarball_sha256 integrity check is optional
// ===========================================================================

// Serve a fake (potentially malicious) binary over HTTP. The manifest intentionally
// omits tarball_sha256. downloadAndVerify SHOULD throw because it cannot verify
// the artifact, but currently it succeeds and writes the file unconditionally.
const fakeArtifact = Buffer.from("fake-malicious-binary-content", "utf8");
const artifactServer = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch() {
    return new Response(fakeArtifact, { status: 200 });
  },
});

const noSha256Manifest = {
  product: "consensus-node" as const,
  version: "9.9.9-bughunt",
  artifact: "npm-tarball" as const,
  platform: "linux-x64",
  commit: "deadbeef",
  routes_hash: "sha256:0000",
  capabilities: [] as never[],
  download_url: `http://127.0.0.1:${artifactServer.port}/artifact.tgz`,
  // tarball_sha256 deliberately absent — should trigger a rejection
};

const bug1Result = await downloadAndVerify(noSha256Manifest).then(
  () => null,     // null means it succeeded — the bug is present
  (e: unknown) => e, // error means the fix is in place
);
artifactServer.stop(true);

assert.ok(
  bug1Result instanceof Error,
  `BUG-1 (SECURITY-CRITICAL): downloadAndVerify must refuse to install a manifest ` +
    `that has no tarball_sha256 — there is nothing to verify the artifact against. ` +
    `Currently it downloads and writes the artifact anyway, enabling silent ` +
    `supply-chain compromise via a tampered CDN or MITM. ` +
    `Got: ${bug1Result === null ? "resolved successfully — bug is PRESENT" : String(bug1Result)}`,
);

// ===========================================================================
// BUG-2 [SECURITY-MEDIUM] — handshake timestamp never validated for freshness
// ===========================================================================

// Build a legitimately signed HandshakeInitMessage whose timestamp is 10 minutes
// in the past. The signature is cryptographically valid — only the age is wrong.
// acceptClientHandshake SHOULD reject it, but currently accepts it.
const identity = await loadOrCreateIdentity();
const ecdhKeyPair = await generateHandshakeKeyPair();
const clientNonce = randomHandshakeNonce();

const staleTimestamp = nowSeconds() - 600; // 10 minutes ago
const unsignedStale: Omit<HandshakeInitMessage, "signature"> = {
  type:                  HANDSHAKE_TYPE.INIT,
  protocol:              HANDSHAKE_PROTOCOL,
  version:               HANDSHAKE_VERSION,
  mode:                  TUNNEL_MODE.CONTROL,
  timestamp:             staleTimestamp,
  client_public_key:     ecdhKeyPair.publicKeyRaw.toString("base64"),
  client_nonce:          clientNonce.toString("base64"),
  node_public_key_pem:   identity.publicKeyPem,
};

const staleInit: HandshakeInitMessage = {
  ...unsignedStale,
  signature: signUtf8(identity.privateKeyPem, canonicalJson(unsignedStale)),
};

const bug2Result = await acceptClientHandshake({ init: staleInit }).then(
  () => null,       // null = accepted the stale handshake — bug is present
  (e: unknown) => e, // error = correctly rejected it — fix is in place
);

assert.ok(
  bug2Result instanceof Error,
  `BUG-2 (SECURITY-MEDIUM): acceptClientHandshake must reject a handshake whose ` +
    `timestamp is ${nowSeconds() - staleTimestamp} seconds old (threshold: ≤60 s). ` +
    `The signature is cryptographically valid; only the timestamp is stale. ` +
    `Without a freshness check, a captured signed INIT can be replayed indefinitely ` +
    `to open sessions under the victim node's identity. ` +
    `Got: ${bug2Result === null ? "resolved successfully — bug is PRESENT" : String(bug2Result)}`,
);

// ===========================================================================
// BUG-3 [PROTOCOL-MEDIUM] — PONG response omits reply_to
// ===========================================================================

// Full integration test: connect a real control client to a mock WS server,
// send a PING frame whose plaintext payload carries a PingMessage with an id,
// capture the client's PONG, and assert that pong.reply_to === ping.id.
//
// Current behaviour: pongMessage() is constructed without reading the ping payload
// at all, so reply_to is always undefined. The server can never correlate PONGs.

const pongServerState: {
  session?: SecureSession;
  ws?: { send(data: Buffer | Uint8Array): void; close(): void };
  sendSeq: bigint;
} = { sendSeq: 0n };

let resolvePong!: (msg: ReturnType<typeof decodeMessage>) => void;
const pongReceived = new Promise<ReturnType<typeof decodeMessage>>(
  (r) => { resolvePong = r; },
);

let resolveHeartbeat!: () => void;
const heartbeatSeen = new Promise<void>((r) => { resolveHeartbeat = r; });

const pongWsPort = await getFreePort();
const pongWsServer = Bun.serve({
  hostname: "127.0.0.1",
  port: pongWsPort,
  fetch(req, srv) {
    if (srv.upgrade(req)) return undefined;
    return new Response("ws required", { status: 426 });
  },
  websocket: {
    async message(ws, data) {
      const raw = await toBuffer(data);

      if (!pongServerState.session) {
        const init = decodeHandshakeMessage(raw);
        if (init.type !== HANDSHAKE_TYPE.INIT) {
          throw new Error(`Expected handshake_init, got ${init.type}`);
        }
        const accepted = await acceptClientHandshake({ init });
        pongServerState.session = accepted.session;
        pongServerState.ws = ws as unknown as typeof pongServerState.ws;
        ws.send(encodeHandshakeMessage(accepted.message));
        return;
      }

      const { frame, plaintext } = openFrame(pongServerState.session.receiveKey, raw);

      if (frame.type === FRAME_TYPE.PONG) {
        resolvePong(decodeMessage(plaintext));
        return;
      }

      const msg = decodeMessage(plaintext);
      if (msg.type === MESSAGE_TYPE.HEARTBEAT) resolveHeartbeat();
    },
  },
});

// Give the control client a fresh node_id so it can start cleanly.
await saveConfig({ port: 9090, node_id: "ping-pong-test" });
const pongConnected = await startControlClient({
  gatewayUrl: `ws://127.0.0.1:${pongWsPort}`,
  heartbeatIntervalMs: 60_000,
});

// Wait for the initial heartbeat so the message handler is fully live.
await Promise.race([
  heartbeatSeen,
  new Promise<never>((_, rej) =>
    setTimeout(() => rej(new Error("Heartbeat not seen within 3 s")), 3_000),
  ),
]);

// Craft a PING frame with a PingMessage whose id we expect back in reply_to.
const pingId = crypto.randomUUID();
const pingMsg = { type: MESSAGE_TYPE.PING as const, timestamp: nowSeconds(), id: pingId };
const pingFrame = sealFrame(
  pongServerState.session!.sendKey,
  FRAME_TYPE.PING,
  pongServerState.sendSeq++,
  encodeMessage(pingMsg),
);
pongServerState.ws!.send(pingFrame);

const pong = await Promise.race([
  pongReceived,
  new Promise<never>((_, rej) =>
    setTimeout(() => rej(new Error("PONG not received within 2 s")), 2_000),
  ),
]);

assert.equal(pong.type, MESSAGE_TYPE.PONG, "BUG-3: expected a PONG message type");

assert.equal(
  (pong as { reply_to?: string }).reply_to,
  pingId,
  `BUG-3 (PROTOCOL-MEDIUM): PONG.reply_to must equal the ping id "${pingId}". ` +
    `handleRawMessage never decodes the PING frame's plaintext payload, so ` +
    `pongMessage() is always constructed without reply_to, breaking any ` +
    `server-side RTT measurement that correlates PONGs via reply_to. ` +
    `Got reply_to=${JSON.stringify((pong as Record<string, unknown>).reply_to)}`,
);

pongConnected.stop();
pongWsServer.stop(true);

// ===========================================================================
// BUG-4 [DOS-LOW] — no maximum frame size in decodeFrame
// ===========================================================================

// decodeFrame accepts a ciphertextLength up to u32::MAX (≈4 GB). The length
// check (raw.length === HEADER + ciphertextLength + TAG) prevents buffer
// over-reads, but a server is free to send legitimately oversized frames and
// force the node to hold the full buffer in memory. There is no upper bound.
//
// We pick 1 MB as the maximum safe ciphertext size. Any larger frame should be
// rejected immediately before any memory allocation for the payload occurs.

const MAX_SAFE_CIPHERTEXT_BYTES = 1 * 1024 * 1024; // 1 MB
const oversizedCiphertextLength = MAX_SAFE_CIPHERTEXT_BYTES + 1;

// Build a syntactically valid frame buffer that claims an oversized ciphertext.
const HEADER_SIZE = 26;
const TAG_SIZE = 16;
const oversizedHeader = Buffer.allocUnsafe(HEADER_SIZE);
oversizedHeader.writeUInt8(FRAME_VERSION, 0);
oversizedHeader.writeUInt8(FRAME_TYPE.DATA, 1);
oversizedHeader.writeBigUInt64BE(0n, 2);             // sequence
Buffer.alloc(12).copy(oversizedHeader, 10);           // nonce placeholder
oversizedHeader.writeUInt32BE(oversizedCiphertextLength, 22);

// Allocate the full body so raw.length === expectedLength — passes the existing
// length check and exercises the missing size-cap check.
const oversizedRaw = Buffer.concat([
  oversizedHeader,
  Buffer.alloc(oversizedCiphertextLength + TAG_SIZE),
]);

const bug4Result = (() => {
  try {
    decodeFrame(oversizedRaw);
    return null;  // accepted — bug is present
  } catch (e) {
    return e;     // threw — fix is in place
  }
})();

assert.ok(
  bug4Result instanceof Error,
  `BUG-4 (DOS-LOW): decodeFrame must reject frames whose ciphertext exceeds ` +
    `${(MAX_SAFE_CIPHERTEXT_BYTES / 1024).toFixed(0)} KB. ` +
    `Currently any size up to u32::MAX (4 294 967 295 bytes ≈ 4 GB) is accepted, ` +
    `allowing a misbehaving or compromised server to force the node to hold a ` +
    `4 GB buffer in memory and crash from OOM. ` +
    `Got: ${bug4Result === null ? "accepted (bug is PRESENT)" : String(bug4Result)}`,
);

// ---------------------------------------------------------------------------

console.log("bug-hunt-2026-05-11 complete");

// ---------------------------------------------------------------------------
// Helpers
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
