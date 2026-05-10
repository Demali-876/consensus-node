/**
 * Daily security/performance bug hunt — three findings.
 *
 * Bug 1 — CPU benchmark DoS (benchmarks.ts /benchmark/cpu)
 *   Every other benchmark route passes user-supplied iteration counts through
 *   integerParam() which clamps them to a safe maximum (25 000).  The /cpu
 *   route used body.iterations raw, letting any caller pin the CPU with
 *   iterations=1_000_000_000.  body.data was also unbounded, so a 1 MB payload
 *   multiplied by even the clamped 25 K iterations = 25 GB of hash input.
 *   Fix: apply integerParam to iterations and slice data to MAX_DATA_BYTES.
 *
 * Bug 2 — Handshake accepts stale timestamps (handshake.ts)
 *   assertHandshakeBase checked that timestamp was a finite number but never
 *   verified it was within an acceptable window of the current time.  A
 *   validly-signed handshake message from hours ago passed all checks, enabling
 *   a confused-deputy / replay scenario at the session-setup layer.
 *   Fix: add a ±MAX_CLOCK_DRIFT_SECONDS window check in acceptClientHandshake.
 *
 * Bug 3 — No maximum frame payload size (frames.ts)
 *   decodeFrame read a uint32 ciphertextLength from the header (up to 4 GB)
 *   with no upper-bound guard.  The only protection was raw.length !== expected,
 *   which fires after the unchecked length has already been used to compute
 *   expectedLength.  A proper MAX_FRAME_PAYLOAD check should reject oversized
 *   frames before touching anything else.
 *   Fix: introduce MAX_FRAME_PAYLOAD = 16 MB and reject early.
 */
import assert from "node:assert/strict";
import Fastify from "fastify";
import { registerBenchmarkRoutes } from "../runtime/benchmarks";
import { canonicalJson } from "../crypto/canonical-json";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import {
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
  acceptClientHandshake,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import { decodeFrame, FRAME_TYPE, FRAME_VERSION, MAX_FRAME_PAYLOAD } from "../tunnel/frames";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-security-test-"),
);

// ---------------------------------------------------------------------------
// Bug 1 — CPU benchmark: iterations clamped, data truncated
// ---------------------------------------------------------------------------

const app = Fastify({ logger: false });
await registerBenchmarkRoutes(app);
await app.ready();

// 1a: Iterations above max must be clamped to 25 000.
//     Before fix: body.iterations was used raw — sending 10 M caused the node
//     to hash 10 M times (several seconds of blocked CPU per request).
{
  const res = await app.inject({
    method: "POST",
    url: "/benchmark/cpu",
    payload: { iterations: 10_000_000, data: "benchmark-payload" },
  });
  assert.equal(res.statusCode, 200, "POST /benchmark/cpu must succeed");
  const body = res.json();
  assert.ok(
    body.iterations <= 25_000,
    `Bug 1a: iterations must be clamped to ≤25 000 — got ${body.iterations}`,
  );
}

// 1b: Oversized data must be truncated before hashing.
//     Before fix: Buffer.from(body.data, "utf8") used the full string, so a
//     1 MB data argument × 25 K iterations = 25 GB of SHA-256 input.
{
  const bigData = "x".repeat(100_000); // 100 KB
  const res = await app.inject({
    method: "POST",
    url: "/benchmark/cpu",
    payload: { iterations: 10, data: bigData },
  });
  assert.equal(res.statusCode, 200, "POST /benchmark/cpu must succeed with large data");
  const body = res.json();
  assert.ok(
    typeof body.data_bytes === "number" && body.data_bytes <= 1024,
    `Bug 1b: data must be truncated to ≤1 024 bytes — got data_bytes=${body.data_bytes}`,
  );
}

await app.close();

// ---------------------------------------------------------------------------
// Bug 2 — Handshake: stale timestamp rejected
// ---------------------------------------------------------------------------

// Craft a validly-signed handshake init whose timestamp is 2 hours in the past.
// The signature is genuine (we sign it with the node's real key) so only the
// age check distinguishes this from a fresh message.
const identity = await loadOrCreateIdentity();
const keyPair   = await generateHandshakeKeyPair();
const nonce     = randomHandshakeNonce();

const staleTimestamp = nowSeconds() - 7_200; // 2 hours ago
const unsigned = {
  type:               HANDSHAKE_TYPE.INIT,
  protocol:           HANDSHAKE_PROTOCOL,
  version:            HANDSHAKE_VERSION,
  mode:               TUNNEL_MODE.EVAL,
  timestamp:          staleTimestamp,
  client_public_key:  keyPair.publicKeyRaw.toString("base64"),
  client_nonce:       nonce.toString("base64"),
  node_public_key_pem: identity.publicKeyPem,
};
const signature  = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
const staleInit  = { ...unsigned, signature } as Parameters<typeof acceptClientHandshake>[0]["init"];

const staleError = await acceptClientHandshake({ init: staleInit })
  .then(() => null, (e: unknown) => e);

assert.ok(
  staleError instanceof Error,
  "Bug 2: stale handshake must be rejected — acceptClientHandshake should throw",
);
assert.match(
  (staleError as Error).message,
  /timestamp/i,
  "Bug 2: rejection error must mention 'timestamp'",
);

// A fresh handshake must still be accepted normally.
const freshKeyPair = await generateHandshakeKeyPair();
const freshNonce   = randomHandshakeNonce();
const freshUnsigned = {
  type:               HANDSHAKE_TYPE.INIT,
  protocol:           HANDSHAKE_PROTOCOL,
  version:            HANDSHAKE_VERSION,
  mode:               TUNNEL_MODE.EVAL,
  timestamp:          nowSeconds(),
  client_public_key:  freshKeyPair.publicKeyRaw.toString("base64"),
  client_nonce:       freshNonce.toString("base64"),
  node_public_key_pem: identity.publicKeyPem,
};
const freshSig   = signUtf8(identity.privateKeyPem, canonicalJson(freshUnsigned));
const freshInit  = { ...freshUnsigned, signature: freshSig } as Parameters<typeof acceptClientHandshake>[0]["init"];
const freshServer = await acceptClientHandshake({ init: freshInit });
assert.ok(freshServer.session.sessionId, "a fresh handshake must still be accepted");

// ---------------------------------------------------------------------------
// Bug 3 — Frame decoder: oversized payload rejected early
// ---------------------------------------------------------------------------

// MAX_FRAME_PAYLOAD must be exported so consuming code can reason about limits.
assert.ok(
  typeof MAX_FRAME_PAYLOAD === "number" && MAX_FRAME_PAYLOAD > 0,
  "Bug 3: MAX_FRAME_PAYLOAD must be exported from frames.ts",
);

// Build a minimal syntactically-valid header that claims a payload of
// MAX_FRAME_PAYLOAD + 1 bytes.  We do NOT allocate the ciphertext —
// the fix must reject the frame before raw.length is even consulted.
const HEADER_SIZE = 26;
const TAG_SIZE    = 16;
const oversize    = Buffer.allocUnsafe(HEADER_SIZE + TAG_SIZE); // no ciphertext
oversize.writeUInt8(FRAME_VERSION, 0);
oversize.writeUInt8(FRAME_TYPE.DATA, 1);
oversize.writeBigUInt64BE(0n, 2);           // sequence
oversize.fill(0, 10, 22);                   // nonce (12 bytes)
oversize.writeUInt32BE(MAX_FRAME_PAYLOAD + 1, 22); // claim too-large ciphertext
oversize.fill(0, HEADER_SIZE);              // tag (16 bytes)

assert.throws(
  () => decodeFrame(oversize),
  /payload too large/i,
  "Bug 3: frame header claiming >MAX_FRAME_PAYLOAD bytes must throw 'payload too large'",
);

// A frame just at the limit (MAX_FRAME_PAYLOAD bytes of ciphertext) must
// still be rejected via the existing length-mismatch check, not the new guard.
const atLimit = Buffer.allocUnsafe(HEADER_SIZE + TAG_SIZE);
atLimit.writeUInt8(FRAME_VERSION, 0);
atLimit.writeUInt8(FRAME_TYPE.DATA, 1);
atLimit.writeBigUInt64BE(0n, 2);
atLimit.fill(0, 10, 22);
atLimit.writeUInt32BE(MAX_FRAME_PAYLOAD, 22);
atLimit.fill(0, HEADER_SIZE);
assert.throws(
  () => decodeFrame(atLimit),
  /frame length/i,
  "frame at exactly MAX_FRAME_PAYLOAD must be rejected for length mismatch (not payload-too-large)",
);

console.log("security ok");
