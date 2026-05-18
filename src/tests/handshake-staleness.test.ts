/**
 * Evidence test: missing timestamp validation in handshake messages.
 *
 * VULNERABILITY SUMMARY
 * ─────────────────────
 * assertHandshakeBase() (src/tunnel/handshake.ts) checks that the `timestamp`
 * field is a finite number, but never verifies that it falls within a
 * reasonable window of the current wall-clock time.
 *
 * Consequences:
 *   1. Replay attack — a captured handshake_init (valid signature, fresh
 *      ephemeral key) remains "valid" indefinitely.  An interceptor can
 *      replay it hours or days later; the server will accept it and derive
 *      a new session, potentially associating the session with the original
 *      node identity.
 *
 *   2. Clock-skew confusion — a client whose clock is badly wrong (e.g.
 *      year 2000) silently connects; there is no way for the server to
 *      detect drift.
 *
 * The fix is to add a recency check (e.g. |now - timestamp| ≤ 300 s) inside
 * assertHandshakeBase so that both decodeHandshakeMessage and acceptClientHandshake
 * reject messages outside that window.
 *
 * HOW THE TESTS WORK
 * ──────────────────
 * 1. A real handshake_init message is created with a valid signature.
 * 2. Its timestamp is overwritten to be 1 hour in the past (or future).
 * 3. decodeHandshakeMessage is called; it must throw for out-of-window messages.
 *
 * CURRENT RESULT:  FAIL — stale / future timestamps are accepted silently.
 * AFTER FIX:       PASS — an error is thrown for out-of-window timestamps.
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  createClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
} from "../tunnel/handshake";
import { loadOrCreateIdentity } from "../crypto/identity";
import { TUNNEL_MODE } from "../tunnel/messages";

// Isolated state directory so this test does not touch ~/.consensus
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-staleness-test-"),
);

const identity = await loadOrCreateIdentity();

// Build a structurally valid, correctly signed handshake_init
const handshake = await createClientHandshake({
  mode: TUNNEL_MODE.EVAL,
  identity,
  candidateId: "staleness-test",
  releaseVersion: "0.0.0-test",
});

// ── Case 1: timestamp 1 hour in the past ─────────────────────────────────────

const staleMessage = {
  ...handshake.message,
  timestamp: Math.floor(Date.now() / 1000) - 3600,
};

let threwStale = false;
try {
  decodeHandshakeMessage(encodeHandshakeMessage(staleMessage));
} catch {
  threwStale = true;
}

assert.equal(
  threwStale,
  true,
  "STALENESS BUG: decodeHandshakeMessage accepted a handshake_init with a " +
    "timestamp 1 hour in the past — replayed handshake messages go undetected; " +
    "add a recency check (|now − timestamp| ≤ 300 s) in assertHandshakeBase",
);

// ── Case 2: timestamp 1 hour in the future ────────────────────────────────────

const futureMessage = {
  ...handshake.message,
  timestamp: Math.floor(Date.now() / 1000) + 3600,
};

let threwFuture = false;
try {
  decodeHandshakeMessage(encodeHandshakeMessage(futureMessage));
} catch {
  threwFuture = true;
}

assert.equal(
  threwFuture,
  true,
  "STALENESS BUG: decodeHandshakeMessage accepted a handshake_init with a " +
    "timestamp 1 hour in the future — pre-generated tokens can be used long " +
    "after creation; the same recency window should reject large future drift",
);

// ── Case 3: a fresh timestamp must still be accepted ─────────────────────────
// Sanity-check: once the fix is applied, a legitimate message must not break.

let freshThrew = false;
try {
  decodeHandshakeMessage(encodeHandshakeMessage(handshake.message));
} catch {
  freshThrew = true;
}

assert.equal(
  freshThrew,
  false,
  "A fresh handshake_init (current timestamp) must still decode without error",
);

console.log("handshake-staleness ok");
