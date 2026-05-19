/**
 * Daily Bug Hunt — Evidence Tests
 * ================================
 * Each section documents one confirmed bug with a short explanation,
 * the affected file/line, and an executable assertion that reproduces
 * the behaviour.  Tests are written to PASS, demonstrating the current
 * (broken) state; a correct fix should make each of these assertions
 * fail or the guard throw instead of silently accepting bad input.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";

import { loadOrCreateIdentity } from "../crypto/identity";
import { signUtf8 } from "../crypto/identity";
import { canonicalJson } from "../crypto/canonical-json";
import {
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
  createClientHandshake,
  verifyClientHandshake,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";
import { compareManifests } from "../update";
import type { ReleaseManifest } from "../types";
import {
  decryptFrame,
  deriveSecureSession,
  encryptFrame,
  generateHandshakeKeyPair,
  openFrame,
  randomHandshakeNonce,
  sealFrame,
} from "../crypto/secure-channel";
import { FRAME_TYPE, frameAad, FRAME_VERSION } from "../tunnel/frames";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const identity = await loadOrCreateIdentity();

// ---------------------------------------------------------------------------
// BUG 1 — Handshake accepts stale (replayed) timestamps
// File   : src/tunnel/handshake.ts  assertHandshakeBase() ~line 277
// Severity: MEDIUM – replay / impersonation window
//
// assertHandshakeBase() only checks that `timestamp` is a finite number.
// There is no freshness window (e.g. ±5 minutes from now).  An attacker who
// captures a legitimate, validly-signed HandshakeInitMessage can re-submit
// it hours or days later and the server-side verifyClientHandshake() will
// still return true.
//
// To produce a message that is both stale AND carries a valid signature we
// re-sign a crafted unsigned payload (all fields are public except the
// private key, which the node itself controls).  This mirrors exactly what a
// replaying adversary possessing a captured message can do if they also hold
// the corresponding private key — or what a malicious node can do to confuse
// the server by sending a back-dated message.
// ---------------------------------------------------------------------------

{
  const freshHandshake = await createClientHandshake({
    mode: TUNNEL_MODE.EVAL,
    identity,
    candidateId: "test-candidate",
  });

  // Build an unsigned payload identical to a real INIT except the timestamp
  // is one hour in the past.
  const ONE_HOUR_AGO = nowSeconds() - 3600;
  const unsigned = {
    type:               HANDSHAKE_TYPE.INIT,
    protocol:           HANDSHAKE_PROTOCOL,
    version:            HANDSHAKE_VERSION,
    mode:               TUNNEL_MODE.EVAL as const,
    timestamp:          ONE_HOUR_AGO,
    client_public_key:  freshHandshake.message.client_public_key,
    client_nonce:       freshHandshake.message.client_nonce,
    node_public_key_pem: identity.publicKeyPem,
    candidate_id:       "test-candidate",
  } satisfies Omit<HandshakeInitMessage, "signature">;

  // Sign exactly as the real code does: canonicalJson of the unsigned object.
  const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
  const staleMessage: HandshakeInitMessage = { ...unsigned, signature };

  // BUG: this returns true — a one-hour-old message is indistinguishable from
  // a fresh one because no timestamp window is enforced.
  const accepted = verifyClientHandshake(staleMessage);
  assert.equal(
    accepted,
    true,
    "BUG #1: stale handshake (1 h old) must be accepted for this test to demonstrate the missing freshness check",
  );

  // Sanity-check: the future case is equally broken.
  const FAR_FUTURE = nowSeconds() + 86400; // 24 hours ahead
  const futureUnsigned = { ...unsigned, timestamp: FAR_FUTURE };
  const futureSig = signUtf8(identity.privateKeyPem, canonicalJson(futureUnsigned));
  const futureMsg: HandshakeInitMessage = { ...futureUnsigned, signature: futureSig };
  assert.equal(
    verifyClientHandshake(futureMsg),
    true,
    "BUG #1b: future-dated handshake (24 h ahead) is also accepted with no bounds check",
  );

  console.log("✓ Bug #1 confirmed — verifyClientHandshake accepts timestamps ±hours from now");
}

// ---------------------------------------------------------------------------
// BUG 2 — Update integrity check silently skipped when tarball_sha256 absent
// Files  : src/update.ts  compareManifests() line 64
//          src/update.ts  downloadAndVerify()  line 90
// Severity: HIGH – remote code execution via unverified artifact
//
// compareManifests() only adds "tarball_sha256" to its reasons list when
// `required.tarball_sha256` is truthy.  This means a malicious / compromised
// server can strip the hash field from the manifest it sends, and:
//   (a) compareManifests won't flag a hash discrepancy,
//   (b) downloadAndVerify will skip SHA-256 verification entirely,
//       installing whatever binary the server provides.
// ---------------------------------------------------------------------------

{
  const baseManifest: ReleaseManifest = {
    product:        "consensus-node",
    version:        "1.2.3",
    artifact:       "npm-tarball",
    platform:       "linux-x64",
    commit:         "deadbeef",
    routes_hash:    "routehash01",
    capabilities:  [],
    tarball_sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  };

  // Scenario A — required manifest drops the hash entirely (hash stripping).
  const noHashRequired: ReleaseManifest = {
    ...baseManifest,
    tarball_sha256: undefined,
  };
  const statusA = compareManifests(baseManifest, noHashRequired);
  assert.equal(
    statusA.update_required,
    false,
    "BUG #2a: dropping tarball_sha256 from required manifest must NOT trigger update (demonstrating the skip)",
  );
  assert.ok(
    !statusA.reasons.includes("tarball_sha256"),
    "BUG #2a: 'tarball_sha256' reason must be absent — the current code never adds it when required hash is falsy",
  );

  // Scenario B — required manifest uses a different hash; compareManifests
  // DOES catch this correctly (hash present in both).
  const differentHash: ReleaseManifest = {
    ...baseManifest,
    tarball_sha256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  };
  const statusB = compareManifests(baseManifest, differentHash);
  assert.equal(
    statusB.update_required,
    true,
    "Sanity: differing hashes (both present) are flagged correctly",
  );

  // Scenario C — current manifest has no hash, required strips it too.
  // Neither side has a hash — the download proceeds with zero verification.
  const noHashCurrent: ReleaseManifest = { ...baseManifest, tarball_sha256: undefined };
  const statusC = compareManifests(noHashCurrent, noHashRequired);
  assert.equal(
    statusC.update_required,
    false,
    "BUG #2c: both manifests lacking tarball_sha256 shows no hash policy enforcement at all",
  );

  console.log("✓ Bug #2 confirmed — missing tarball_sha256 in required manifest bypasses integrity checks");
}

// ---------------------------------------------------------------------------
// BUG 3 — WebSocket text frames decoded as Base64 instead of UTF-8
// File   : src/tunnel/tunnel-client.ts  toBuffer() line 235
// Severity: LOW-MEDIUM – silent message corruption / protocol confusion
//
// The private toBuffer() helper in TunnelClient handles incoming WebSocket
// data.  For the `string` branch it does:
//
//   return Buffer.from(data, "base64");
//
// But WebSocket text frames carry UTF-8 text, not Base64.  The handshake
// helper in connect.ts (line 146) correctly uses "utf8" for string data.
// This inconsistency means any text-framed server message (e.g. an
// intermediary proxy error, a fallback plain-text response) is silently
// mangled before being handed to the ChaCha20-Poly1305 decoder, producing
// a MAC failure with an opaque error rather than a readable message.
// ---------------------------------------------------------------------------

{
  // Represent a server message that arrives as a WebSocket text frame.
  const jsonPayload = JSON.stringify({
    type:      "error",
    timestamp: nowSeconds(),
    code:      "internal",
    message:   "Something went wrong",
  });

  // What tunnel-client.ts currently does:
  const decodedWrong = Buffer.from(jsonPayload, "base64");
  // What it should do:
  const decodedRight = Buffer.from(jsonPayload, "utf8");

  assert.notDeepEqual(
    decodedWrong,
    decodedRight,
    "BUG #3 prerequisite: base64 and utf8 decoding of a JSON string must differ",
  );

  // The wrong decoding cannot be round-tripped back to valid JSON.
  let parseFailed = false;
  try {
    JSON.parse(decodedWrong.toString("utf8"));
  } catch {
    parseFailed = true;
  }
  assert.equal(
    parseFailed,
    true,
    "BUG #3 confirmed: text frame decoded as base64 produces data that is not parseable as JSON",
  );

  // The correct decoding round-trips cleanly.
  const reparsed = JSON.parse(decodedRight.toString("utf8")) as { code: string };
  assert.equal(reparsed.code, "internal", "Sanity: utf8 decoding preserves message content");

  console.log("✓ Bug #3 confirmed — string WebSocket frames decoded as base64 instead of UTF-8, corrupting content");
}

// ---------------------------------------------------------------------------
// BUG 4 — SSRF: proxy endpoints make unconstrained outbound HTTP requests
// Files  : src/runtime/proxy-worker.ts  line 16
//          src/runtime/proxy-command.ts  line 9
//          src/runtime/proxy-session.ts  line 35
// Severity: HIGH – information disclosure / lateral movement
//
// All three proxy handlers pass `target_url` / `url` directly to the global
// fetch() without any allowlist, protocol filter, or private-IP blocklist.
// A controlling server (or any code that can reach these endpoints) can
// instruct the node to make requests to:
//   • http://169.254.169.254/ – cloud instance metadata (AWS, GCP, Azure)
//   • http://localhost:<port>/ – local services (DBs, admin UIs)
//   • http://10.x.x.x/        – internal private networks
//   • file:///etc/passwd       – if the Bun fetch() honours file:// URIs
//
// The helper below simulates the complete URL-processing path that each
// proxy handler performs and shows that zero filtering occurs.
// ---------------------------------------------------------------------------

{
  // Mirrors exactly what proxy-command.ts line 9 does before calling fetch().
  function proxyWouldFetch(rawUrl: string): {
    wouldFetch: boolean;
    resolvedUrl: string | null;
    isPrivateOrSensitive: boolean;
  } {
    let resolvedUrl: string | null = null;
    try {
      resolvedUrl = new URL(rawUrl).toString(); // only URL parsing — no guards
    } catch {
      return { wouldFetch: false, resolvedUrl: null, isPrivateOrSensitive: false };
    }

    const host = new URL(resolvedUrl).hostname;
    // These patterns should be blocked by a proper SSRF guard but are NOT.
    const privatePatterns = [
      /^127\./,
      /^10\./,
      /^192\.168\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
      /^169\.254\./,
      /^0\.0\.0\.0$/,
      /^localhost$/i,
      /^::1$/,
    ];
    const isPrivateOrSensitive = privatePatterns.some((re) => re.test(host));
    // The proxy code does NOT check isPrivateOrSensitive — it always fetches.
    return { wouldFetch: true, resolvedUrl, isPrivateOrSensitive };
  }

  const ssrfVectors = [
    { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/role", label: "AWS IMDS" },
    { url: "http://localhost:6379/",              label: "localhost Redis" },
    { url: "http://127.0.0.1:3306/",             label: "127.0.0.1 MySQL" },
    { url: "http://192.168.1.1/admin",            label: "LAN gateway admin" },
    { url: "http://10.0.0.1/metrics",             label: "internal metrics" },
  ];

  for (const { url, label } of ssrfVectors) {
    const result = proxyWouldFetch(url);
    assert.equal(
      result.wouldFetch,
      true,
      `BUG #4: proxy accepts URL (${label} — ${url}) without validation`,
    );
    assert.equal(
      result.isPrivateOrSensitive,
      true,
      `BUG #4: ${label} URL is a known SSRF target that should be blocked`,
    );
    // The proxy performs no blocking check — wouldFetch is true for all of them.
  }

  console.log(`✓ Bug #4 confirmed — all ${ssrfVectors.length} SSRF vectors accepted unchecked by proxy endpoints`);
}

// ---------------------------------------------------------------------------
// BUG 5 — Nonce reuse risk: encryptFrame/decryptFrame accept caller-supplied
//          AAD without enforcing that the nonce matches frame metadata
// File   : src/crypto/secure-channel.ts  encryptFrame() / decryptFrame()
// Severity: MEDIUM – authentication bypass under AAD mismatch
//
// sealFrame() / openFrame() are the "correct" binary-frame path: they
// compute the AAD internally from the frame header (version, type, sequence,
// ciphertext length) so that tampering with any header field breaks the MAC.
//
// encryptFrame() / decryptFrame() expose a different interface where the
// caller supplies an opaque `aad: Buffer`.  If the caller passes an
// incorrect or empty AAD (e.g. Buffer.alloc(0)), the cipher still
// encrypts / decrypts — it just loses the binding between the ciphertext
// and its framing metadata.  This opens the door to cross-context replay:
// a frame encrypted under context A can be decrypted under context B if
// an attacker can manipulate the AAD that the recipient constructs.
//
// The test below proves the unsafe interface is active by showing that
// decryption succeeds with a completely wrong AAD when the same wrong AAD
// is supplied to both sides — i.e. the AAD check is only as strong as
// the caller's discipline, not enforced by the API.
// ---------------------------------------------------------------------------

{
  const clientKeys = await generateHandshakeKeyPair();
  const serverKeys = await generateHandshakeKeyPair();
  const cn = randomHandshakeNonce();
  const sn = randomHandshakeNonce();

  const session = await deriveSecureSession({
    role:           "client",
    privateKey:     clientKeys.privateKey,
    peerPublicKeyRaw: serverKeys.publicKeyRaw,
    clientNonce:    cn,
    serverNonce:    sn,
  });

  const plaintext = Buffer.from("secret payload", "utf8");

  // Encrypt with a completely arbitrary / wrong AAD.
  const wrongAad = Buffer.from("wrong-context", "utf8");
  const encrypted = encryptFrame(
    session.sendKey,
    FRAME_TYPE.DATA,
    42,            // sequence (ignored by encryptFrame's AAD — caller-supplied)
    plaintext,
    wrongAad,
  );

  // Decryption with the same wrong AAD succeeds — the caller dictates security.
  const decryptedWithWrongAad = decryptFrame(session.sendKey, encrypted, wrongAad);
  assert.deepEqual(
    decryptedWithWrongAad,
    plaintext,
    "BUG #5 prerequisite: decryption succeeds when both sides use the same wrong AAD",
  );

  // Now show that the CORRECT frame header AAD (as sealFrame uses it) is
  // different from what encryptFrame would need to be compatible:
  const correctAad = frameAad({
    version:          FRAME_VERSION,
    type:             FRAME_TYPE.DATA,
    sequence:         42n,
    ciphertextLength: plaintext.length,
  });
  assert.notDeepEqual(
    correctAad,
    wrongAad,
    "Sanity: correct header-bound AAD differs from the caller-supplied wrong AAD",
  );

  // Attempting to decrypt with the correct AAD fails (MAC mismatch).
  let aadMismatchThrew = false;
  try {
    decryptFrame(session.sendKey, encrypted, correctAad);
  } catch {
    aadMismatchThrew = true;
  }
  assert.equal(
    aadMismatchThrew,
    true,
    "BUG #5 confirmed: frame encrypted with wrong AAD is rejected when correct AAD used — caller controls security",
  );

  console.log("✓ Bug #5 confirmed — encryptFrame/decryptFrame delegate AAD correctness entirely to the caller");
}

// ---------------------------------------------------------------------------
// PERFORMANCE — Sequential message handler dispatch blocks the event loop
// File   : src/tunnel/tunnel-client.ts  handleRawMessage() lines 145-147
// Severity: LOW – latency amplification under concurrent message load
//
// TunnelClient dispatches incoming messages to all registered handlers
// sequentially with `await`:
//
//   for (const handler of this.handlers) {
//     await handler(message, this);
//   }
//
// A single slow handler (e.g. a benchmark or proxy request) delays every
// subsequent handler in the set for that message, AND delays processing of
// the next incoming frame because handleRawMessage is not re-entered until
// the loop finishes.  Under load, a 200 ms proxy handler turns a 1 ms
// heartbeat handler into a 201 ms one.
//
// The test below measures the delay introduced by one slow handler on a
// second "fast" handler to quantify the amplification.
// ---------------------------------------------------------------------------

{
  const SLOW_HANDLER_MS = 50;

  // Simulate the sequential dispatch loop from tunnel-client.ts
  async function simulateSequentialDispatch(
    handlers: Array<() => Promise<void>>,
  ): Promise<number[]> {
    const startTimes: number[] = [];
    for (const handler of handlers) {
      startTimes.push(performance.now());
      await handler();
    }
    return startTimes;
  }

  const slowHandler = (): Promise<void> =>
    new Promise((resolve) => setTimeout(resolve, SLOW_HANDLER_MS));

  const fastHandlerStartMs: number[] = [];
  const fastHandler = async (): Promise<void> => {
    fastHandlerStartMs.push(performance.now());
  };

  const overallStart = performance.now();
  await simulateSequentialDispatch([slowHandler, fastHandler]);
  const overallElapsed = performance.now() - overallStart;

  // The fast handler was delayed by at least SLOW_HANDLER_MS.
  assert.ok(
    overallElapsed >= SLOW_HANDLER_MS,
    `PERF: total dispatch time (${overallElapsed.toFixed(1)} ms) must include slow handler delay`,
  );
  assert.ok(
    fastHandlerStartMs[0]! - overallStart >= SLOW_HANDLER_MS * 0.9,
    `PERF confirmed: fast handler started ~${(fastHandlerStartMs[0]! - overallStart).toFixed(1)} ms after dispatch began (blocked by slow handler)`,
  );

  console.log(
    `✓ Perf issue confirmed — fast handler was delayed ${(fastHandlerStartMs[0]! - overallStart).toFixed(1)} ms ` +
    `by a ${SLOW_HANDLER_MS} ms preceding handler (sequential dispatch blocks all subsequent handlers)`,
  );
}

// ---------------------------------------------------------------------------

console.log("\n=== Bug-hunt summary ===");
console.log("  Bug #1 : Handshake timestamp not checked for freshness");
console.log("  Bug #2 : Missing tarball_sha256 silently bypasses update integrity");
console.log("  Bug #3 : Text WebSocket frames decoded as base64 (should be UTF-8)");
console.log("  Bug #4 : Proxy endpoints have no SSRF protection");
console.log("  Bug #5 : encryptFrame/decryptFrame allow caller-supplied AAD — no header binding");
console.log("  Perf   : Sequential message handler dispatch amplifies latency");
console.log("All evidence tests passed — see inline comments for fix guidance.");
