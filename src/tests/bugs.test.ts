/**
 * Bug hunt – 2026-05-17
 *
 * Four confirmed bugs, each with a regression test that proves the issue
 * exists without requiring network access or external services.
 *
 * Bug A – SSRF: proxy endpoints accept any target_url, including localhost
 *   proxy-command.ts calls fetch(message.target_url) with no URL validation.
 *   proxy-worker.ts does the same for POST /proxy.  A caller with tunnel
 *   access (or HTTP access to /proxy) can reach 127.0.0.1, 169.254.169.254,
 *   or any host reachable from the node, leaking internal data.
 *
 * Bug B – Silent SHA-256 skip on software updates
 *   downloadAndVerify (update.ts:90) checks integrity only when
 *   manifest.tarball_sha256 is truthy.  A compromised update server can omit
 *   the field to deliver an unsigned artifact without triggering any error.
 *   The download silently succeeds even if the bytes are entirely wrong.
 *
 * Bug C – Handshake timestamp never validated for staleness
 *   assertHandshakeBase (handshake.ts:277) confirms timestamp is a finite
 *   number but never compares it against Date.now().  A correctly signed
 *   HandshakeInitMessage with a timestamp 1 hour in the past is accepted
 *   without complaint, enabling replay-based resource exhaustion.
 *
 * Bug D – canonical-json sortValue has no recursion depth limit
 *   sortValue (canonical-json.ts) recurses into every nested object with no
 *   guard.  A deeply-nested payload (e.g. from eval params or a malformed
 *   handshake field) overflows the call stack and crashes the process.
 */

import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { canonicalJson } from "../crypto/canonical-json";
import { downloadAndVerify } from "../update";
import { executeProxyCommand } from "../runtime/proxy-command";
import {
  acceptClientHandshake,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
} from "../tunnel/handshake";
import {
  generateHandshakeKeyPair,
  randomHandshakeNonce,
} from "../crypto/secure-channel";
import { signUtf8, loadOrCreateIdentity } from "../crypto/identity";
import { MESSAGE_TYPE, TUNNEL_MODE, nowSeconds } from "../tunnel/messages";
import type { ReleaseManifest } from "../types";

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "bugs-test-"),
);

// ─────────────────────────────────────────────────────────────────────────────
// Bug A – SSRF: proxy reaches internal localhost servers without restriction
// ─────────────────────────────────────────────────────────────────────────────
// Expected (fixed) behaviour: requests to private / loopback addresses are
//   rejected before the outbound fetch is made.
// Actual (buggy) behaviour:   the fetch proceeds and returns data from the
//   internal server.

const INTERNAL_SECRET = "internal-metadata-token-abc123";

const internalServer = Bun.serve({
  port: 0, // OS picks a free port
  fetch() {
    return new Response(
      JSON.stringify({ secret: INTERNAL_SECRET }),
      { headers: { "content-type": "application/json" } },
    );
  },
});

const ssrfResponse = await executeProxyCommand({
  type: MESSAGE_TYPE.PROXY_REQUEST,
  id: "ssrf-test",
  timestamp: nowSeconds(),
  target_url: `http://127.0.0.1:${internalServer.port}/internal`,
  method: "GET",
});

internalServer.stop(true);

// This assertion PASSES, proving the bug: the proxy successfully reached an
// internal service that should have been blocked.
assert.equal(
  ssrfResponse.status,
  200,
  "Bug A: SSRF – proxy must block requests to loopback addresses, " +
    `but got HTTP ${ssrfResponse.status} from http://127.0.0.1:${internalServer.port}`,
);
const ssrfBody = JSON.parse(
  Buffer.from(ssrfResponse.body ?? "", "base64").toString("utf8"),
) as { secret?: string };
assert.equal(
  ssrfBody.secret,
  INTERNAL_SECRET,
  "Bug A: SSRF – proxy returned secret data from the internal server",
);
console.log(
  `Bug A (SSRF): confirmed – proxy fetched http://127.0.0.1/internal ` +
    `and returned secret="${ssrfBody.secret}"`,
);

// ─────────────────────────────────────────────────────────────────────────────
// Bug B – SHA-256 skip: downloadAndVerify accepts any bytes when
//         tarball_sha256 is absent from the manifest
// ─────────────────────────────────────────────────────────────────────────────
// Expected (fixed) behaviour: if the manifest has no tarball_sha256, the
//   function should throw rather than silently accepting unverified bytes.
// Actual (buggy) behaviour:   the `if (manifest.tarball_sha256 && …)` guard
//   short-circuits when the field is absent, accepting any content.

const TAMPERED_BYTES = Buffer.from(
  "MALICIOUS-PAYLOAD-NOT-A-REAL-TARBALL-" + crypto.randomUUID(),
);
const CORRECT_SHA256 = require("node:crypto")
  .createHash("sha256")
  .update(TAMPERED_BYTES)
  .digest("hex");

const updateServer = Bun.serve({
  port: 0,
  fetch() {
    return new Response(TAMPERED_BYTES);
  },
});

const manifestWithoutHash: ReleaseManifest = {
  product: "consensus-node",
  version: "9.9.9-malicious",
  artifact: "npm-tarball",
  platform: "linux-x64",
  commit: "badc0ffee",
  download_url: `http://127.0.0.1:${updateServer.port}/update.tgz`,
  // tarball_sha256 intentionally absent – this is what triggers the bug
  routes_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  capabilities: [],
};

let sha256SkipError: Error | null = null;
let sha256SkipResult: { path: string; sha256: string } | null = null;
try {
  sha256SkipResult = await downloadAndVerify(manifestWithoutHash);
} catch (err) {
  sha256SkipError = err instanceof Error ? err : new Error(String(err));
}

updateServer.stop(true);

// This assertion PASSES, proving the bug: downloadAndVerify accepted
// arbitrary bytes without performing any integrity check.
assert.equal(
  sha256SkipError,
  null,
  "Bug B: downloadAndVerify should require tarball_sha256 to be present " +
    `and throw when it is missing, but it returned successfully: ` +
    JSON.stringify(sha256SkipResult),
);
assert.ok(
  sha256SkipResult !== null,
  "Bug B: tampered content was accepted without integrity verification",
);
// Extra evidence: the downloaded hash differs from nothing – we have no
// expected hash to compare against, which is exactly the problem.
assert.equal(
  sha256SkipResult!.sha256,
  CORRECT_SHA256,
  "Bug B: file was written to disk with no sha256 verification performed",
);
console.log(
  `Bug B (SHA-256 skip): confirmed – downloaded ${TAMPERED_BYTES.length} bytes ` +
    `with no tarball_sha256 in manifest; file written to ${sha256SkipResult!.path}`,
);

// ─────────────────────────────────────────────────────────────────────────────
// Bug C – Handshake timestamp never validated for staleness
// ─────────────────────────────────────────────────────────────────────────────
// Expected (fixed) behaviour: acceptClientHandshake rejects init messages
//   whose timestamp is outside an acceptable window (e.g. ±5 minutes).
// Actual (buggy) behaviour:   assertHandshakeBase only checks
//   Number.isFinite(timestamp); a message from 1 hour ago is accepted.

const identity = await loadOrCreateIdentity();
const ephemeralKeyPair = await generateHandshakeKeyPair();
const clientNonce = randomHandshakeNonce();

const ONE_HOUR_AGO = nowSeconds() - 3_600;

// Build and sign a legitimately-formed message but with an old timestamp.
// The signature is valid (key matches node_public_key_pem), so the only thing
// that should reject this is a staleness check – which doesn't exist.
const unsignedStale = {
  type: HANDSHAKE_TYPE.INIT,
  protocol: HANDSHAKE_PROTOCOL,
  version: HANDSHAKE_VERSION,
  mode: TUNNEL_MODE.EVAL,
  timestamp: ONE_HOUR_AGO,
  client_public_key: ephemeralKeyPair.publicKeyRaw.toString("base64"),
  client_nonce: clientNonce.toString("base64"),
  node_public_key_pem: identity.publicKeyPem,
};

// Signing payload is canonicalJson of the message body (no signature field).
const staleSignature = signUtf8(
  identity.privateKeyPem,
  canonicalJson(unsignedStale),
);
const staleInitMessage = { ...unsignedStale, signature: staleSignature };

let stalenessError: Error | null = null;
try {
  await acceptClientHandshake({ init: staleInitMessage });
} catch (err) {
  stalenessError = err instanceof Error ? err : new Error(String(err));
}

// This assertion PASSES, proving the bug: the 1-hour-old message was accepted.
assert.equal(
  stalenessError,
  null,
  `Bug C: acceptClientHandshake must reject messages older than the ` +
    `acceptable window, but accepted timestamp=${ONE_HOUR_AGO} ` +
    `(${nowSeconds() - ONE_HOUR_AGO}s ago)`,
);
console.log(
  `Bug C (timestamp staleness): confirmed – handshake init with timestamp ` +
    `${nowSeconds() - ONE_HOUR_AGO}s in the past was accepted without error`,
);

// ─────────────────────────────────────────────────────────────────────────────
// Bug D – canonical-json sortValue has no recursion depth limit
// ─────────────────────────────────────────────────────────────────────────────
// Expected (fixed) behaviour: canonicalJson throws a descriptive error (or
//   uses an iterative algorithm) when nesting exceeds a safe threshold.
// Actual (buggy) behaviour:   sortValue recurses without bound, causing
//   "Maximum call stack size exceeded" and crashing the process.

function buildDeepObject(depth: number): unknown {
  let node: unknown = { value: "leaf" };
  for (let i = 0; i < depth; i++) {
    node = { child: node };
  }
  return node;
}

const MALICIOUS_DEPTH = 50_000;
const deepObject = buildDeepObject(MALICIOUS_DEPTH);

let recursionError: Error | null = null;
try {
  canonicalJson(deepObject);
} catch (err) {
  recursionError = err instanceof Error ? err : new Error(String(err));
}

// This assertion PASSES, proving the bug: the call stack overflowed.
assert.ok(
  recursionError !== null,
  `Bug D: canonicalJson must throw with a depth-limit error at depth ` +
    `${MALICIOUS_DEPTH}, but it returned successfully`,
);
assert.match(
  recursionError.message,
  /call stack|maximum|stack|exceeded/i,
  `Bug D: expected call-stack overflow, got unexpected error: ${recursionError.message}`,
);
console.log(
  `Bug D (recursion DoS): confirmed – canonicalJson at depth ${MALICIOUS_DEPTH} ` +
    `threw "${recursionError.message}"`,
);

// ─────────────────────────────────────────────────────────────────────────────
console.log("\nAll 4 bugs confirmed. See inline comments for fix guidance.");
