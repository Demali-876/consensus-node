/**
 * Daily bug-hunt report — 2026-05-03
 *
 * Finding 1 (Security)   — src/tunnel/handshake.ts
 *   Handshake timestamp is never checked for staleness. A validly-signed
 *   HandshakeInitMessage from the past is accepted unconditionally, opening an
 *   unbounded replay-attack window.
 *
 * Finding 2 (Correctness) — src/runtime/eval.ts:66, src/runtime/benchmarks.ts:65
 *   The crypto-benchmark round-trip verification checks only opened[0] against
 *   payload[0]. Any cipher failure that corrupts bytes 1..N passes silently,
 *   defeating the purpose of the check.
 *
 * Finding 3 (Performance) — src/runtime/eval.ts:39, src/runtime/benchmarks.ts:37
 *   crypto.createHash("sha256").update(data).digest("hex") produces a 64-char
 *   hex string that is immediately discarded. The string allocation and 32-byte
 *   hex-encoding loop are pure overhead. Changing to .digest() (returns a
 *   Buffer) removes that cost and raises the benchmark's reported
 *   hashes_per_second closer to actual hardware throughput.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { canonicalJson } from "../crypto/canonical-json";
import { signUtf8, loadOrCreateIdentity } from "../crypto/identity";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import {
  verifyClientHandshake,
  acceptClientHandshake,
  HANDSHAKE_TYPE,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_VERSION,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-bug-report-"),
);

// =============================================================================
// Finding 1: Handshake replay attack — stale timestamp not validated
// =============================================================================
//
// assertHandshakeBase() (handshake.ts:277) validates that timestamp is a finite
// number but never checks Math.abs(nowSeconds() - timestamp) < MAX_SKEW. Any
// HandshakeInitMessage that was validly signed in the past can be replayed
// hours or days later and the server will derive a fresh encrypted session from
// it without complaint.
//
// Immediate risk: an old signed init can be re-submitted to force the server
// into expensive crypto.subtle.deriveBits work (DoS) or to probe behavior with
// a known-old ephemeral key set.
//
// Fix: add a staleness guard in assertHandshakeBase, e.g.
//   const MAX_SKEW_SECONDS = 300;
//   if (Math.abs(nowSeconds() - message.timestamp) > MAX_SKEW_SECONDS) {
//     throw new TypeError("Handshake timestamp is stale or too far in the future");
//   }
// =============================================================================

console.log("Finding 1: handshake timestamp staleness not validated");
{
  const identity = await loadOrCreateIdentity();
  const keyPair  = await generateHandshakeKeyPair();
  const nonce    = randomHandshakeNonce();

  // Build a message identical to what createClientHandshake would produce,
  // except the timestamp is 25 hours in the past.
  const staleTimestamp = nowSeconds() - 25 * 60 * 60;

  const unsigned = {
    type:               HANDSHAKE_TYPE.INIT  as typeof HANDSHAKE_TYPE.INIT,
    protocol:           HANDSHAKE_PROTOCOL,
    version:            HANDSHAKE_VERSION,
    mode:               TUNNEL_MODE.EVAL,
    timestamp:          staleTimestamp,
    client_public_key:  keyPair.publicKeyRaw.toString("base64"),
    client_nonce:       nonce.toString("base64"),
    node_public_key_pem: identity.publicKeyPem,
  };

  // Sign using the same logic as createClientHandshake (canonical JSON without
  // the signature field).
  const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
  const staleInit: HandshakeInitMessage = { ...unsigned, signature };

  // 1a — The signature itself is cryptographically valid (expected).
  assert.ok(
    verifyClientHandshake(staleInit),
    "signature is valid (expected — crypto is correct)",
  );

  // 1b — The server accepts the message despite the 25-hour-old timestamp.
  //      This is the bug: no staleness rejection occurs.
  let serverAccepted = false;
  try {
    await acceptClientHandshake({ init: staleInit });
    serverAccepted = true;
  } catch {
    serverAccepted = false;
  }

  const ageHours = Math.floor((nowSeconds() - staleTimestamp) / 3600);
  assert.ok(
    serverAccepted,
    `BUG CONFIRMED: ${ageHours}h-old handshake init was accepted without rejection`,
  );

  console.log(
    `  CONFIRMED — ${ageHours}h-old init accepted; replay window is unbounded`,
  );
  console.log(
    "  fix: check Math.abs(nowSeconds() - message.timestamp) > MAX_SKEW_SECONDS in assertHandshakeBase()",
  );
}

// =============================================================================
// Finding 2: Crypto benchmark verifies only the first decrypted byte
// =============================================================================
//
// Both src/runtime/eval.ts (cryptoBenchmark) and src/runtime/benchmarks.ts
// (/benchmark/crypto route) use this guard after decrypt:
//
//   if (opened.length !== payload.length || opened[0] !== payload[0]) {
//     throw new Error("ChaCha20-Poly1305 … verification failed");
//   }
//
// Because only index 0 is compared, any silent corruption of bytes [1..N]
// goes undetected. The benchmarks would continue reporting success and
// high throughput numbers even if the cipher were silently broken.
//
// Fix: replace the partial check with a constant-time or full equality check:
//   import { timingSafeEqual } from "node:crypto";
//   if (opened.length !== payload.length || !timingSafeEqual(opened, payload)) { … }
// =============================================================================

console.log("\nFinding 2: crypto benchmark verifies only opened[0]");
{
  const payloadSize = 4096;
  const payload = Buffer.alloc(payloadSize, 0xab); // all bytes 0xAB

  // Simulate a decrypt result whose first byte is correct but every other
  // byte has been zeroed — e.g., a broken cipher or wrong key stream offset.
  const silentlyCorrupted = Buffer.alloc(payloadSize, 0x00);
  silentlyCorrupted[0] = 0xab; // first byte matches; the rest do not

  // Current check from eval.ts / benchmarks.ts:
  const currentCheckPasses =
    silentlyCorrupted.length === payload.length &&
    silentlyCorrupted[0] === payload[0];

  // A correct full-equality check:
  const fullCheckPasses = silentlyCorrupted.equals(payload);

  assert.ok(
    currentCheckPasses,
    "BUG CONFIRMED: single-byte check passes for massively corrupted output",
  );
  assert.ok(
    !fullCheckPasses,
    "full equality check correctly rejects the corrupted buffer (as expected)",
  );

  const corruptedCount = payloadSize - 1;
  console.log(
    `  CONFIRMED — ${corruptedCount}/${payloadSize} bytes corrupted; current check sees nothing`,
  );
  console.log(
    "  fix: replace opened[0] !== payload[0] with !timingSafeEqual(opened, payload) in eval.ts:66 and benchmarks.ts:65",
  );
}

// =============================================================================
// Finding 3 (Performance): .digest("hex") overhead on a discarded string
// =============================================================================
//
// cpuBenchmark (eval.ts:39) and /benchmark/cpu (benchmarks.ts:37) both do:
//
//   crypto.createHash("sha256").update(data).digest("hex");
//
// The return value is never stored or used. .digest("hex") allocates a new
// 64-character string and performs 32 byte-to-hex-pair conversions on every
// iteration. Switching to .digest() returns a Buffer with no string encoding,
// avoiding that allocation and the associated GC pressure.
//
// The practical impact: hashes_per_second reported by the benchmark is lower
// than the node's actual SHA-256 capability, which can cause the node to
// receive a lower benchmark_score from the network.
//
// Fix: s/.digest("hex")/.digest()/ in eval.ts:39 and benchmarks.ts:37
// =============================================================================

console.log("\nFinding 3: digest(\"hex\") overhead on discarded result");
{
  const data = "consensus-node-eval";
  const ITERATIONS = 40_000;

  // Warmup — let the JIT settle on both paths.
  for (let i = 0; i < 3_000; i++) {
    crypto.createHash("sha256").update(data).digest("hex");
    crypto.createHash("sha256").update(data).digest();
  }

  // Measure: current code — .digest("hex")
  const t0 = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    crypto.createHash("sha256").update(data).digest("hex");
  }
  const msHex = performance.now() - t0;

  // Measure: proposed fix — .digest() returns Buffer directly
  const t1 = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    crypto.createHash("sha256").update(data).digest();
  }
  const msBuffer = performance.now() - t1;

  const overheadPct = ((msHex - msBuffer) / msBuffer) * 100;
  const hashesPerSecHex = Math.round((ITERATIONS / msHex) * 1000);
  const hashesPerSecBuf = Math.round((ITERATIONS / msBuffer) * 1000);

  console.log(`  digest("hex") : ${msHex.toFixed(1).padStart(7)} ms  →  ${hashesPerSecHex.toLocaleString().padStart(12)} hashes/sec`);
  console.log(`  digest()      : ${msBuffer.toFixed(1).padStart(7)} ms  →  ${hashesPerSecBuf.toLocaleString().padStart(12)} hashes/sec`);
  console.log(`  hex overhead  : ${overheadPct >= 0 ? "+" : ""}${overheadPct.toFixed(1)}%`);

  // The result is always discarded — any positive overhead is pure waste.
  // We don't hard-assert timing (CI machines vary) but record it for evidence.
  if (overheadPct > 0) {
    console.log(
      `  CONFIRMED — ${overheadPct.toFixed(1)}% slower; reported hashes/sec is understated`,
    );
  } else {
    // This branch would mean the JIT eliminated the allocation entirely —
    // still worth fixing for correctness and clarity.
    console.log(
      "  JIT eliminated the allocation in this run — fix still recommended for clarity",
    );
  }
  console.log(
    '  fix: change .digest("hex") → .digest() in eval.ts:39 and benchmarks.ts:37',
  );
}

console.log("\ndaily-bug-report ok");
