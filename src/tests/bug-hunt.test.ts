/**
 * Daily Bug Hunt — 2026-05-09
 *
 * Four bugs found and fixed today.  Each section below contains the evidence
 * that shows the bug would have caused real harm and proves the fix is correct.
 *
 * BUG 1 — CRITICAL SECURITY: tarball_sha256 bypass in downloadAndVerify
 *   File: src/update.ts
 *   Before fix: the hash check was guarded by `if (manifest.tarball_sha256 && ...)`,
 *   so a server could omit the field entirely to push an arbitrary binary without
 *   any integrity verification.  The download would succeed and the artifact would
 *   be installed silently.
 *   Fix: reject immediately (before any network I/O) when tarball_sha256 is absent
 *   or empty, and remove the conditional guard on the hash comparison.
 *
 * BUG 2 — SECURITY: Handshake timestamp not validated for freshness (replay attack)
 *   File: src/tunnel/handshake.ts  (assertHandshakeBase)
 *   Before fix: the timestamp field was only checked to be a finite number.  A
 *   captured, validly-signed INIT message could be replayed minutes or hours later
 *   and verifyClientHandshake() would still return true.
 *   Fix: reject messages whose timestamp is older than 5 minutes or more than
 *   1 minute in the future (clock-skew tolerance).
 *
 * BUG 3 — PERFORMANCE: releaseManifest() called 3× in integrityPayload()
 *   File: src/node/integrity.ts
 *   Before fix: releaseManifest() was called on three separate lines.  Each call
 *   runs routesHash() — a SHA-256 computation over the route list — and
 *   potentially gitCommit() which spawns a child process via execFileSync().
 *   Three calls = 3× the work for a single payload.
 *   Fix: call releaseManifest() once, store the result, reuse it.
 *   Evidence: we instrument crypto.createHash to count SHA-256 invocations;
 *   routesHash() is the only SHA-256 user in the integrityPayload() call chain.
 *
 * BUG 4 — SECURITY: SSRF via proxy without URL validation
 *   File: src/runtime/proxy-command.ts
 *   Before fix: executeProxyCommand() fetched message.target_url with no
 *   restrictions.  A malicious server could direct any node to hit the cloud
 *   instance-metadata endpoint (169.254.169.254), localhost services, or
 *   RFC-1918 ranges — classic Server-Side Request Forgery.
 *   Fix: block requests to loopback, link-local (169.254.x.x), RFC-1918, and
 *   ULA IPv6 ranges before the fetch is attempted.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// Use an isolated temp directory so key generation doesn't touch the real state.
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-bug-hunt-"),
);
// Pin version/commit/platform so releaseManifest() never spawns git.
process.env.CONSENSUS_NODE_VERSION  = "0.1.0-bugtest";
process.env.CONSENSUS_NODE_COMMIT   = "test-commit-bugtest";
process.env.CONSENSUS_NODE_PLATFORM = "linux-x64-bugtest";

import { downloadAndVerify } from "../update";
import {
  createClientHandshake,
  verifyClientHandshake,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { canonicalJson } from "../crypto/canonical-json";
import { nowSeconds, TUNNEL_MODE } from "../tunnel/messages";
import { integrityPayload } from "../node/integrity";
import { isBlockedProxyUrl } from "../runtime/proxy-command";
import type { ReleaseManifest } from "../types";

// ============================================================================
// BUG 1 — tarball_sha256 bypass
// ============================================================================

{
  const base: Omit<ReleaseManifest, "tarball_sha256"> = {
    product: "consensus-node",
    version: "1.0.0",
    artifact: "npm-tarball",
    platform: "linux-x64",
    commit: "abc123",
    routes_hash: "sha256:abc",
    capabilities: [],
    // Point at an unreachable port; the fix must throw before any network I/O.
    download_url: "http://127.0.0.1:1/should-never-be-reached.tgz",
  };

  // Case A — tarball_sha256 entirely absent
  {
    const manifest = { ...base } as ReleaseManifest; // no tarball_sha256 key
    const err = await downloadAndVerify(manifest).then(
      () => null,
      (e: unknown) => (e instanceof Error ? e : new Error(String(e))),
    );
    assert.ok(err !== null,
      "Bug 1a: downloadAndVerify must reject a manifest that has no tarball_sha256");
    assert.match(err.message, /tarball_sha256/i,
      "Bug 1a: error must mention tarball_sha256");
  }

  // Case B — tarball_sha256 is an empty string
  {
    const manifest: ReleaseManifest = { ...base, tarball_sha256: "" };
    const err = await downloadAndVerify(manifest).then(
      () => null,
      (e: unknown) => (e instanceof Error ? e : new Error(String(e))),
    );
    assert.ok(err !== null,
      "Bug 1b: downloadAndVerify must reject a manifest with an empty tarball_sha256");
    assert.match(err.message, /tarball_sha256/i,
      "Bug 1b: error must mention tarball_sha256");
  }

  console.log("bug 1 (tarball_sha256 bypass): FIXED ✓");
}

// ============================================================================
// BUG 2 — handshake replay / timestamp not validated
// ============================================================================

{
  const identity = await loadOrCreateIdentity();

  // Build a HandshakeInitMessage with a custom timestamp, re-signed correctly.
  // This simulates an attacker replaying a captured, validly-signed INIT.
  function buildSignedHandshake(
    base: HandshakeInitMessage,
    timestamp: number,
  ): HandshakeInitMessage {
    const { signature: _sig, ...unsigned } = { ...base, timestamp };
    const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
    return { ...unsigned, signature } as HandshakeInitMessage;
  }

  const fresh = await createClientHandshake({ mode: TUNNEL_MODE.EVAL, identity });

  // A fresh handshake must still be accepted after the fix.
  assert.equal(
    verifyClientHandshake(fresh.message),
    true,
    "Bug 2: fresh handshake must still pass",
  );

  // 10-minute-old message — classic replay.
  const stale = buildSignedHandshake(fresh.message, nowSeconds() - 600);
  assert.throws(
    () => verifyClientHandshake(stale),
    /timestamp/i,
    "Bug 2: handshake with 10-minute-old timestamp must be rejected",
  );

  // 2-minutes-in-the-future message — prevents clock-skew abuse / pre-generation.
  const future = buildSignedHandshake(fresh.message, nowSeconds() + 120);
  assert.throws(
    () => verifyClientHandshake(future),
    /timestamp/i,
    "Bug 2: handshake with far-future timestamp must be rejected",
  );

  console.log("bug 2 (handshake replay): FIXED ✓");
}

// ============================================================================
// BUG 3 — releaseManifest() called 3× (routesHash / gitCommit wasted work)
// ============================================================================

{
  // Instrument crypto.createHash to count SHA-256 invocations.
  // routesHash() — called once per releaseManifest() — is the only SHA-256 user
  // in the integrityPayload() call chain.
  // Before fix: 3 calls to releaseManifest() → sha256Calls === 3.
  // After  fix: 1 call to releaseManifest() → sha256Calls === 1.

  let sha256Calls = 0;
  const realCreateHash = (crypto as Record<string, unknown>).createHash as typeof crypto.createHash;

  (crypto as Record<string, unknown>).createHash = function patchedCreateHash(
    algorithm: string,
    ...rest: Parameters<typeof crypto.createHash> extends [string, ...infer R] ? R : never[]
  ) {
    if (algorithm === "sha256") sha256Calls++;
    return realCreateHash.call(crypto, algorithm as Parameters<typeof crypto.createHash>[0], ...rest);
  };

  let payload;
  try {
    payload = await integrityPayload();
  } finally {
    (crypto as Record<string, unknown>).createHash = realCreateHash;
  }

  assert.equal(
    sha256Calls,
    1,
    `Bug 3: releaseManifest() must be called once per integrityPayload() — ` +
    `detected ${sha256Calls} SHA-256 call(s); before the fix this was 3.`,
  );

  // Correctness invariants that also hold after the fix.
  assert.equal(payload.version, payload.manifest.version,
    "Bug 3: payload.version must equal payload.manifest.version");
  assert.equal(payload.platform, payload.manifest.platform,
    "Bug 3: payload.platform must equal payload.manifest.platform");
  assert.ok(payload.nonce.length > 0, "nonce must be present");
  assert.ok(typeof payload.signature === "string" && payload.signature.length > 0,
    "signature must be present");

  console.log("bug 3 (releaseManifest 3× calls): FIXED ✓");
}

// ============================================================================
// BUG 4 — SSRF via proxy without URL validation
// ============================================================================

{
  const blocked: string[] = [
    // Loopback
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/admin",
    "http://127.1.2.3/",
    "http://localhost/",
    "http://localhost:9200/",
    // Link-local — AWS / GCP / Azure instance-metadata endpoint
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.0.1/",
    // RFC-1918 private ranges
    "http://10.0.0.1/",
    "http://10.255.255.255/",
    "http://172.16.0.1/",
    "http://172.20.0.1/",
    "http://172.31.255.255/",
    "http://192.168.1.1/",
    "http://192.168.255.255/",
    // IPv6 loopback and link-local
    "http://[::1]/",
    "http://[fe80::1]/",
    // Garbage / unparseable
    "not-a-url",
    "",
  ];

  for (const url of blocked) {
    assert.equal(
      isBlockedProxyUrl(url),
      true,
      `Bug 4: "${url}" must be blocked to prevent SSRF`,
    );
  }

  const allowed: string[] = [
    "https://example.com/",
    "https://api.example.com/v1/data",
    "http://1.2.3.4/",
    "https://8.8.8.8/",
    "https://1.1.1.1/dns-query",
    "https://203.0.113.1/", // TEST-NET-3 — publicly routable for tests
  ];

  for (const url of allowed) {
    assert.equal(
      isBlockedProxyUrl(url),
      false,
      `Bug 4: "${url}" must not be blocked`,
    );
  }

  console.log("bug 4 (SSRF via proxy): FIXED ✓");
}

console.log("\nAll bug-hunt tests passed.");
