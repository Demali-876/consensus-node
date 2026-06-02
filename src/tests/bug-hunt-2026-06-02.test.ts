/**
 * Daily Bug Hunt — 2026-06-02
 *
 * Four confirmed bugs across security and performance:
 *   1. writeJson creates files with world-readable permissions (SECURITY)
 *   2. SHA-256 artifact verification is bypassable (SECURITY)
 *   3. Handshake timestamp has no freshness check (SECURITY)
 *   4. O(n) linear scan on every STREAM_DATA/STREAM_CLOSE message (PERFORMANCE)
 *
 * Run: bun src/tests/bug-hunt-2026-06-02.test.ts
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import { canonicalJson } from "../crypto/canonical-json";
import {
  HANDSHAKE_TYPE,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_VERSION,
  verifyClientHandshake,
} from "../tunnel/handshake";
import { TUNNEL_MODE } from "../tunnel/messages";

// ─────────────────────────────────────────────────────────────────────────────
// Bug 1 — writeJson creates config.json with world-readable permissions
//
// Location : src/node/state.ts:60-63
// Severity : SECURITY — Medium
//
// writeJson() calls fs.writeFile(file, content, "utf8") with no mode option.
// On a typical Linux host (umask 0022) this produces mode 0o644, giving group
// and world read access to the config file.  saveJoinAuthorization() and
// saveSetupProgress() already use { mode: 0o600 } correctly; saveConfig()
// goes through writeJson() and is the odd one out.
//
// The config contains node_id, domain, region, IPv4/IPv6, port, and
// registration timestamp — enough for reconnaissance on a shared host.
//
// Fix: add { mode: 0o600 } to the fs.writeFile call inside writeJson().
// ─────────────────────────────────────────────────────────────────────────────
{
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "bug1-"));
  const configFile = path.join(tmpDir, "config.json");

  // Replicate exactly what writeJson() does
  await fs.writeFile(
    configFile,
    JSON.stringify({ node_id: "secret-id", domain: "example.com" }, null, 2),
    "utf8",        // ← no mode: default umask applies → 0o644
  );

  const mode = (await fs.stat(configFile)).mode & 0o777;

  // Confirm the bug is present: group or world read bit is set
  const isGroupOrWorldReadable = (mode & 0o044) !== 0;
  assert.ok(
    isGroupOrWorldReadable,
    `Expected bug to be present but file was already restricted (mode 0o${mode.toString(8)})`,
  );

  // Confirm the fix works: explicit 0o600 on a fresh file drops the unwanted bits
  const fixedFile = path.join(tmpDir, "config-fixed.json");
  await fs.writeFile(
    fixedFile,
    JSON.stringify({ node_id: "secret-id" }, null, 2),
    { encoding: "utf8", mode: 0o600 },
  );
  const fixedMode = (await fs.stat(fixedFile)).mode & 0o777;
  assert.equal(fixedMode, 0o600, "Fix: mode 0o600 correctly restricts access");

  await fs.rm(tmpDir, { recursive: true });

  console.log(
    `Bug 1 (permissions): CONFIRMED — writeJson produces mode 0o${mode.toString(8)} on config.json, should be 0o600`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Bug 2 — SHA-256 artifact verification is bypassable
//
// Location : src/update.ts:90-92
// Severity : SECURITY — High
//
// downloadAndVerify() guards the hash check with:
//
//   if (manifest.tarball_sha256 && sha256 !== stripShaPrefix(manifest.tarball_sha256))
//
// The leading `&&` means: if the server sends a manifest where tarball_sha256
// is absent (undefined), null, or "", the entire integrity check is skipped and
// any downloaded bytes are written to disk and installed.
//
// A compromised update server — or a MITM that strips the field from the
// manifest — can deliver an arbitrary binary and have it installed without
// any hash rejection.
//
// Fix: throw when tarball_sha256 is absent rather than silently accepting.
// ─────────────────────────────────────────────────────────────────────────────
{
  function stripShaPrefix(value: string): string {
    return value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  }

  // Replicates the guard in downloadAndVerify (update.ts:90)
  function isHashMismatch(tarball_sha256: string | undefined, actualSha256: string): boolean {
    return !!(tarball_sha256 && actualSha256 !== stripShaPrefix(tarball_sha256));
  }

  // Control A: hash present and matching — no mismatch
  assert.equal(isHashMismatch("sha256:abc123", "abc123"), false, "Matching hash: no mismatch");

  // Control B: hash present and different — mismatch caught
  assert.equal(isHashMismatch("sha256:expected", "different_actual"), true, "Hash mismatch detected");

  // BUG: tarball_sha256 absent — any hash passes silently
  assert.equal(
    isHashMismatch(undefined, "evil_payload_hash"),
    false,
    "Expected bug: absent tarball_sha256 should have raised but guard short-circuits to false",
  );

  // BUG: empty string also bypasses
  assert.equal(
    isHashMismatch("", "evil_payload_hash"),
    false,
    "Expected bug: empty tarball_sha256 also bypasses verification",
  );

  // Confirm a safe alternative guard (the fix)
  function isHashMismatchFixed(tarball_sha256: string | undefined, actualSha256: string): never | boolean {
    if (!tarball_sha256) throw new Error("Manifest is missing tarball_sha256 — refusing to install unverified artifact");
    return actualSha256 !== stripShaPrefix(tarball_sha256);
  }

  assert.throws(
    () => isHashMismatchFixed(undefined, "any"),
    /missing tarball_sha256/,
    "Fix: absent tarball_sha256 throws instead of silently accepting",
  );

  console.log("Bug 2 (sha256 bypass): CONFIRMED — downloadAndVerify skips hash check when tarball_sha256 is absent");
}

// ─────────────────────────────────────────────────────────────────────────────
// Bug 3 — Handshake timestamp has no freshness window check
//
// Location : src/tunnel/handshake.ts:110-117, 277-279
// Severity : SECURITY — Medium
//
// verifyClientHandshake() calls assertHandshakeInit() and then verifyUtf8().
// assertHandshakeBase() validates that timestamp is a finite number, but never
// compares it against Date.now().  An attacker who captures a valid
// handshake_init message (e.g. via a recording) can replay it hours later and
// it will pass signature verification unchanged.
//
// Each accepted init triggers a full ECDH key derivation on the server side,
// so replaying captured inits at scale is a CPU-exhaustion vector.
//
// Fix: inside assertHandshakeBase (or verifyClientHandshake) reject messages
// whose timestamp differs from the current time by more than N seconds
// (e.g. 300 s / 5 minutes).
// ─────────────────────────────────────────────────────────────────────────────
{
  const identity = await loadOrCreateIdentity();
  const keyPair = await generateHandshakeKeyPair();
  const clientNonce = randomHandshakeNonce();

  const STALE_AGE_S = 7200; // 2 hours ago
  const staleTimestamp = Math.floor(Date.now() / 1000) - STALE_AGE_S;

  // Build a structurally valid init message with a 2-hour-old timestamp
  const unsigned = {
    type: HANDSHAKE_TYPE.INIT as const,
    protocol: HANDSHAKE_PROTOCOL,
    version: HANDSHAKE_VERSION as 1,
    mode: TUNNEL_MODE.EVAL as const,
    timestamp: staleTimestamp,
    client_public_key: keyPair.publicKeyRaw.toString("base64"),
    client_nonce: clientNonce.toString("base64"),
    node_public_key_pem: identity.publicKeyPem,
  };

  // Sign it — the signature IS cryptographically valid, timestamp is just stale
  const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
  const staleHandshake = { ...unsigned, signature };

  const accepted = verifyClientHandshake(staleHandshake);

  assert.equal(
    accepted,
    true,
    "Expected bug: verifyClientHandshake should reject a 2-hour-old handshake but it returned true",
  );

  // Double-check the claimed age
  const ageSeconds = Math.floor(Date.now() / 1000) - staleHandshake.timestamp;
  assert.ok(ageSeconds >= STALE_AGE_S, `Handshake is ${ageSeconds}s old`);

  // Confirm a freshness guard (the fix)
  function isFresh(timestamp: number, maxAgeSeconds = 300): boolean {
    const ageSecs = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
    return ageSecs <= maxAgeSeconds;
  }

  assert.equal(isFresh(staleHandshake.timestamp), false, "Fix: freshness guard correctly rejects 2-hour-old timestamp");
  assert.equal(isFresh(Math.floor(Date.now() / 1000)), true, "Fix: freshness guard accepts current timestamp");

  console.log(
    `Bug 3 (stale handshake): CONFIRMED — handshake ${ageSeconds}s old accepted by verifyClientHandshake; no freshness check exists`,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Bug 4 — O(n) linear scan on every STREAM_DATA and STREAM_CLOSE message
//
// Location : src/clients/control-client.ts:336-337 and 430-431
// Severity : PERFORMANCE — Medium-High
//
// To find the owning tunnel for an incoming stream message, the handler does:
//
//   Array.from(publicTunnelOwners.entries())
//     .find(([, owner]) => owner.streamId === message.stream_id)
//
// publicTunnelOwners is a Map<tunnelId, OwnerState> keyed by tunnel ID, but
// the lookup is by streamId.  Every STREAM_DATA and STREAM_CLOSE message
// materialises the entire Map as a temporary array and scans it linearly —
// O(n) where n is the number of active public tunnels.
//
// The same pattern appears twice (lines 336-337 for STREAM_DATA,
// lines 430-431 for STREAM_CLOSE).
//
// Fix: add a reverse-index Map<streamId, tunnelId> that is kept in sync when
// tunnel owners are added and removed.  Both lookups become O(1).
// ─────────────────────────────────────────────────────────────────────────────
{
  const N = 2_000;
  const ITERATIONS = 5_000;

  // Build the same structure control-client uses
  type OwnerState = { streamId: string; nextStreamId: number };
  const publicTunnelOwners = new Map<string, OwnerState>();
  for (let i = 0; i < N; i++) {
    publicTunnelOwners.set(`tunnel-${i}`, { streamId: `stream-${i}`, nextStreamId: 1 });
  }

  // Worst-case target: last entry (maximum scan length for Array.find)
  const targetStreamId = `stream-${N - 1}`;

  // ── Current O(n) implementation ──────────────────────────────────────────
  const scanStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    Array.from(publicTunnelOwners.entries())
      .find(([, owner]) => owner.streamId === targetStreamId);
  }
  const scanMs = performance.now() - scanStart;

  // ── Proposed O(1) fix: reverse index Map<streamId, tunnelId> ─────────────
  const streamToTunnel = new Map<string, string>();
  for (const [tunnelId, owner] of publicTunnelOwners) {
    streamToTunnel.set(owner.streamId, tunnelId);
  }

  const lookupStart = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    streamToTunnel.get(targetStreamId);
  }
  const lookupMs = performance.now() - lookupStart;

  const speedup = scanMs / lookupMs;

  // Verify both approaches find the right entry
  const foundByArray = Array.from(publicTunnelOwners.entries())
    .find(([, owner]) => owner.streamId === targetStreamId);
  const foundByIndex = streamToTunnel.get(targetStreamId);
  assert.ok(foundByArray, "Array.find should locate the entry");
  assert.equal(foundByIndex, `tunnel-${N - 1}`, "Map.get should locate the entry");

  // The scan must be substantially slower — this will hold at any realistic n
  assert.ok(
    speedup > 5,
    `Expected O(1) to be >5× faster than O(n) with n=${N}; got ${speedup.toFixed(1)}×`,
  );

  console.log("Bug 4 (O(n) scan): CONFIRMED");
  console.log(`  O(n) Array.from().find() — ${N} entries, ${ITERATIONS} iters: ${scanMs.toFixed(1)} ms`);
  console.log(`  O(1) Map.get()           — ${N} entries, ${ITERATIONS} iters: ${lookupMs.toFixed(1)} ms`);
  console.log(`  Reverse-index speedup: ${speedup.toFixed(1)}×`);
}

console.log("\n✓ All 4 bugs confirmed. See comments in this file for fix guidance.");
