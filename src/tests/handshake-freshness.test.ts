/**
 * Proves that acceptClientHandshake rejects INIT messages whose timestamps
 * fall outside a ±window from the current time.
 *
 * Without a freshness check an adversary who captures one valid INIT message
 * can replay it to the server indefinitely.  Every replay forces the server to
 * perform an ECDH derivation and Ed25519 signature verification — both CPU-
 * intensive operations — without paying the cost of generating a fresh key
 * pair.  A tight window (e.g. ±5 min) eliminates this free-ride amplification
 * while accommodating legitimate clients whose clocks drift by a few seconds.
 *
 * Before fix: any finite timestamp passes assertHandshakeBase; a 10-year-old
 *   INIT message is accepted as if it were fresh.
 * After fix:  timestamps older than 5 min or more than 1 min in the future
 *   cause acceptClientHandshake to throw before any expensive crypto work.
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
  createClientHandshake,
  HANDSHAKE_TYPE,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_VERSION,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-handshake-freshness-test-"),
);

const identity = await loadOrCreateIdentity();

/**
 * Builds a properly-signed HandshakeInitMessage with a custom timestamp.
 * The signature covers the canonical JSON of all fields except `signature`
 * itself — matching exactly what verifyClientHandshake recomputes.
 */
async function makeInitWithTimestamp(timestamp: number): Promise<HandshakeInitMessage> {
  const keyPair = await generateHandshakeKeyPair();
  const clientNonce = randomHandshakeNonce();
  const unsigned = {
    type: HANDSHAKE_TYPE.INIT,
    protocol: HANDSHAKE_PROTOCOL,
    version: HANDSHAKE_VERSION,
    mode: TUNNEL_MODE.CONTROL,
    timestamp,
    client_public_key: keyPair.publicKeyRaw.toString("base64"),
    client_nonce: clientNonce.toString("base64"),
    node_public_key_pem: identity.publicKeyPem,
  } as const;
  const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
  return { ...unsigned, signature };
}

// ---------------------------------------------------------------------------
// Case 1: timestamp 10 minutes in the past → must be rejected as stale
// ---------------------------------------------------------------------------

const staleInit = await makeInitWithTimestamp(nowSeconds() - 600);
const errStale = await acceptClientHandshake({ init: staleInit }).then(
  () => null,
  (e: unknown) => e,
);

assert.ok(
  errStale instanceof Error,
  `Case 1: stale handshake (10 min old) must be rejected — got: ${JSON.stringify(errStale)}`,
);
assert.match(
  (errStale as Error).message,
  /too old/i,
  `Case 1: error must say "too old" — got: "${(errStale as Error).message}"`,
);

// ---------------------------------------------------------------------------
// Case 2: timestamp 10 minutes in the future → must be rejected
// ---------------------------------------------------------------------------

const futureInit = await makeInitWithTimestamp(nowSeconds() + 600);
const errFuture = await acceptClientHandshake({ init: futureInit }).then(
  () => null,
  (e: unknown) => e,
);

assert.ok(
  errFuture instanceof Error,
  `Case 2: future handshake (+10 min) must be rejected — got: ${JSON.stringify(errFuture)}`,
);
assert.match(
  (errFuture as Error).message,
  /future/i,
  `Case 2: error must mention "future" — got: "${(errFuture as Error).message}"`,
);

// ---------------------------------------------------------------------------
// Case 3: current timestamp → must succeed
// ---------------------------------------------------------------------------

const freshClient = await createClientHandshake({
  mode: TUNNEL_MODE.CONTROL,
  identity,
});

const accepted = await acceptClientHandshake({ init: freshClient.message });
assert.ok(
  accepted.session.sessionId.length > 0,
  "Case 3: fresh handshake must be accepted and return a session",
);

console.log("handshake-freshness ok");
