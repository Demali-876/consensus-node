/**
 * SECURITY BUG: assertHandshakeBase() in handshake.ts validates that the
 * timestamp field is a finite number, but never checks it falls within an
 * acceptable clock-skew window.  A captured INIT message (which carries a
 * valid Ed25519 signature) can be replayed hours or days later and the server
 * will accept it unconditionally.
 *
 * Attack scenario
 * ──────────────
 * 1. Attacker captures a legitimate handshake_init from a registered node.
 * 2. Attacker replays it to the server at any later time.
 * 3. Server verifies the Ed25519 signature (still valid), generates a fresh
 *    ECDH key pair, and returns handshake_accept.
 * 4. The real node never receives the accept, creating a phantom session that
 *    consumes server-side ECDH computation and connection state.
 * 5. With enough replays the server's open-connection limit can be exhausted
 *    (replay-based DoS).
 *
 * Fix: add a clock-skew guard in assertHandshakeBase(), for example:
 *
 *   const MAX_CLOCK_SKEW = 300; // ±5 minutes
 *   const skew = Math.abs(message.timestamp - nowSeconds());
 *   if (skew > MAX_CLOCK_SKEW) {
 *     throw new TypeError(`Handshake timestamp is stale (${skew}s off)`);
 *   }
 *
 * Test contract
 * ─────────────
 * These assertions describe the CORRECT behaviour:
 *   • CURRENTLY FAIL on the unpatched code  (bug is present)
 *   • WILL PASS after the timestamp check is added (bug is fixed)
 */
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { canonicalJson } from "../crypto/canonical-json";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import {
  acceptClientHandshake,
  HANDSHAKE_TYPE,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_VERSION,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-hs-ts-test-"),
);

const identity = await loadOrCreateIdentity();

async function buildHandshakeWithAge(ageSeconds: number): Promise<HandshakeInitMessage> {
  const keyPair = await generateHandshakeKeyPair();
  const clientNonce = randomHandshakeNonce();
  const unsigned = {
    type: HANDSHAKE_TYPE.INIT as typeof HANDSHAKE_TYPE.INIT,
    protocol: HANDSHAKE_PROTOCOL,
    version: HANDSHAKE_VERSION,
    mode: TUNNEL_MODE.CONTROL,
    timestamp: nowSeconds() - ageSeconds,
    client_public_key: keyPair.publicKeyRaw.toString("base64"),
    client_nonce: clientNonce.toString("base64"),
    node_public_key_pem: identity.publicKeyPem,
  };
  const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
  return { ...unsigned, signature };
}

// ── Sanity check: a fresh handshake (10 s old) must always be accepted ───────

const freshInit = await buildHandshakeWithAge(10);
const freshServer = await acceptClientHandshake({ init: freshInit });
assert.ok(freshServer.session, "A 10-second-old handshake should be accepted");

// ── Bug #1a: stale past timestamp must be REJECTED ───────────────────────────
// Expected: acceptClientHandshake() throws with a "stale" / "timestamp" error.
// Actual (bug): accepts without error — timestamp is only validated as a finite
// number, not checked against the current clock.

const staleInit = await buildHandshakeWithAge(7200); // 2 hours old
let staleError: unknown = null;
try {
  await acceptClientHandshake({ init: staleInit });
} catch (err) {
  staleError = err;
}

assert.ok(
  staleError !== null,
  `BUG (handshake-timestamp): acceptClientHandshake() accepted a ` +
  `${nowSeconds() - staleInit.timestamp}-second-old INIT without error. ` +
  `assertHandshakeBase() must reject messages outside the ±300 s clock-skew ` +
  `window to prevent replay-based DoS attacks.`,
);

// ── Bug #1b: far-future timestamp must also be REJECTED ──────────────────────

const futureInit = await buildHandshakeWithAge(-600); // 10 minutes in the future
let futureError: unknown = null;
try {
  await acceptClientHandshake({ init: futureInit });
} catch (err) {
  futureError = err;
}

assert.ok(
  futureError !== null,
  `BUG (handshake-timestamp): acceptClientHandshake() accepted a future-dated ` +
  `INIT (timestamp ${futureInit.timestamp - nowSeconds()}s ahead of now). ` +
  `Future timestamps indicate clock manipulation and must also be rejected.`,
);

console.log("handshake-timestamp ok");
