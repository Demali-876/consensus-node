/**
 * BUG: Handshake timestamp is never checked for freshness
 *
 * assertHandshakeBase (handshake.ts) verifies that `timestamp` is a finite
 * number but never rejects messages whose timestamp is outside a reasonable
 * clock-skew window.  A captured, validly-signed handshake init can be
 * replayed at any time in the future and the server will still derive session
 * keys and accept the connection.
 *
 * Fix: assertHandshakeBase should throw when
 *   Math.abs(nowSeconds() - message.timestamp) > MAX_CLOCK_SKEW_SECONDS
 * (e.g. 300 s / 5 minutes).
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { canonicalJson } from "../crypto/canonical-json";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import {
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
  acceptClientHandshake,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";

// Isolated state dir so the test does not touch real keys.
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-replay-test-"),
);

const identity = await loadOrCreateIdentity();

// ---- Build a validly-signed init message with a timestamp 1 hour in the past ----

const staleKeyPair = await generateHandshakeKeyPair();
const staleNonce   = randomHandshakeNonce();

const STALE_AGE_SECONDS = 3_600; // 1 hour — far outside any reasonable clock skew

const staleUnsigned = {
  type:                HANDSHAKE_TYPE.INIT,
  protocol:            HANDSHAKE_PROTOCOL    as typeof HANDSHAKE_PROTOCOL,
  version:             HANDSHAKE_VERSION     as typeof HANDSHAKE_VERSION,
  mode:                TUNNEL_MODE.EVAL,
  timestamp:           nowSeconds() - STALE_AGE_SECONDS,
  client_public_key:   staleKeyPair.publicKeyRaw.toString("base64"),
  client_nonce:        staleNonce.toString("base64"),
  node_public_key_pem: identity.publicKeyPem,
  candidate_id:        "replay-test-stale",
};

// Produce a valid signature over the stale payload — exactly what a real
// client would create, just with a past timestamp.
const staleSignature = signUtf8(identity.privateKeyPem, canonicalJson(staleUnsigned));

const staleInit: HandshakeInitMessage = {
  ...staleUnsigned,
  signature: staleSignature,
};

// ---- Attempt to accept the replayed message ----

let threwTimestampError = false;

try {
  await acceptClientHandshake({ init: staleInit });
} catch (err) {
  const msg = err instanceof Error ? err.message : String(err);
  // Only count errors that are actually about timestamp/staleness.
  if (/timestamp|stale|expired|replay|clock/i.test(msg)) {
    threwTimestampError = true;
  } else {
    throw err; // unexpected error — surface it
  }
}

// BUG: the call above succeeds silently.
// Once the fix lands, threwTimestampError should be true.
assert.equal(
  threwTimestampError,
  false, // document current (broken) behavior — change to true after fix
  "Unexpected: acceptClientHandshake already rejects stale timestamps",
);

console.log(
  `BUG CONFIRMED — handshake-replay: acceptClientHandshake accepted a ` +
  `message whose timestamp is ${STALE_AGE_SECONDS} seconds old (${STALE_AGE_SECONDS / 60} min). ` +
  "Fix: reject when |now - timestamp| > 300 s in assertHandshakeBase.",
);
