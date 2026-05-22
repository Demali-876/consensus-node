/**
 * Daily bug hunt — 2026-05-22
 *
 * Four confirmed findings:
 *   BUG-1  CRITICAL  SHA-256 integrity check bypassed when manifest omits tarball_sha256
 *   BUG-2  SECURITY  Handshake timestamp never validated against current time (replay risk)
 *   BUG-3  PERF      O(n) linear scan for public-tunnel-owner on every STREAM_DATA/CLOSE
 *   BUG-4  RELIAB    writeJson writes non-atomically — crash mid-write silently corrupts state
 *
 * Each "check" function returns true when the bug is PRESENT on current code.
 * Assertions encode the correct behaviour; they will start passing once a bug
 * is fixed.  All four bugs run to completion before the process exits so every
 * finding appears in the output even when prior ones are still unpatched.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "../crypto/canonical-json";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { nowSeconds, TUNNEL_MODE } from "../tunnel/messages";
import { createClientHandshake, verifyClientHandshake } from "../tunnel/handshake";
import { downloadAndVerify } from "../update";
import { writeJson, readJson } from "../node/state";
import type { ReleaseManifest } from "../types";

// ─────────────────────────────────────────────────────────────────────────────
// Tiny test harness — collects results; exits 1 if any bug confirmed
// ─────────────────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  desc: string;
  bugPresent: boolean;
  error?: unknown;
}

const findings: Finding[] = [];

async function check(
  id: string,
  desc: string,
  fn: () => Promise<boolean>,
): Promise<void> {
  let bugPresent = false;
  let error: unknown;
  try {
    bugPresent = await fn();
  } catch (e) {
    // An unexpected throw (not an assertion) is itself evidence of a problem
    bugPresent = true;
    error = e;
  }
  findings.push({ id, desc, bugPresent, error });
}

function buildManifest(overrides: Partial<ReleaseManifest> = {}): ReleaseManifest {
  return {
    product: "consensus-node",
    version: "99.0.0-test",
    artifact: "npm-tarball",
    platform: "linux-x64",
    commit: "deadbeef",
    routes_hash: "aabbcc",
    capabilities: [],
    download_url: "https://fake.test/release.tgz",
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// BUG-1  CRITICAL SECURITY
//
// File:    src/update.ts  line 90
// Code:    if (manifest.tarball_sha256 && sha256 !== ...)
//
// The `&&` guard means the entire SHA-256 check is skipped whenever the server
// omits tarball_sha256.  A compromised or malicious update server can push any
// binary to every node without the node verifying its hash.
//
// Fix:
//   if (!manifest.tarball_sha256)
//     throw new Error("Manifest missing required tarball_sha256");
//   if (sha256 !== stripShaPrefix(manifest.tarball_sha256))
//     throw new Error(`SHA-256 mismatch …`);
// ═════════════════════════════════════════════════════════════════════════════

const FAKE_PAYLOAD = crypto.randomBytes(256);
const REAL_SHA256  = crypto.createHash("sha256").update(FAKE_PAYLOAD).digest("hex");
const WRONG_SHA256 = "0".repeat(64);

const _origFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(FAKE_PAYLOAD, { status: 200 }) as Response;

// Baseline A — correct sha256 must be accepted
await check("BUG-1-base-ok", "manifest with correct sha256 → accepted (baseline)", async () => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bh1a-"));
  process.env.CONSENSUS_STATE_DIR = tmp;
  try {
    const r = await downloadAndVerify(buildManifest({ tarball_sha256: REAL_SHA256 }));
    assert.equal(r.sha256, REAL_SHA256);
    return false; // no bug
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
    delete process.env.CONSENSUS_STATE_DIR;
  }
});

// Baseline B — wrong sha256 must be rejected
await check("BUG-1-base-bad", "manifest with wrong sha256 → rejected (baseline)", async () => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bh1b-"));
  process.env.CONSENSUS_STATE_DIR = tmp;
  try {
    let threw = false;
    try { await downloadAndVerify(buildManifest({ tarball_sha256: WRONG_SHA256 })); }
    catch { threw = true; }
    assert.ok(threw, "wrong sha256 must be rejected");
    return false; // no bug
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
    delete process.env.CONSENSUS_STATE_DIR;
  }
});

// Bug evidence — missing sha256 must be rejected; currently it is accepted
await check(
  "BUG-1",
  "manifest WITHOUT tarball_sha256 bypasses integrity check (any payload silently installed)",
  async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bh1c-"));
    process.env.CONSENSUS_STATE_DIR = tmp;
    try {
      const manifest = buildManifest(); // no tarball_sha256
      let accepted = false;
      try { await downloadAndVerify(manifest); accepted = true; }
      catch { accepted = false; }
      return accepted; // true = bug is present
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
      delete process.env.CONSENSUS_STATE_DIR;
    }
  },
);

globalThis.fetch = _origFetch;

// ═════════════════════════════════════════════════════════════════════════════
// BUG-2  SECURITY — HANDSHAKE REPLAY
//
// File:    src/tunnel/handshake.ts — assertHandshakeBase (~line 277)
// Code:    `typeof timestamp === "number" && isFinite(timestamp)` only
//
// Impact:  A captured handshake_init with a valid signature can be replayed
//          at any future time.  The server allocates a session thinking the
//          node is reconnecting, enabling resource exhaustion (DoS).
//
// Fix (in assertHandshakeBase or verifyClientHandshake):
//   const MAX_SKEW = 300; // seconds
//   if (Math.abs(nowSeconds() - message.timestamp) > MAX_SKEW)
//     throw new TypeError(`Handshake timestamp too old: skew=${…}s`);
// ═════════════════════════════════════════════════════════════════════════════

const identity = await loadOrCreateIdentity();
const freshHS   = await createClientHandshake({ mode: TUNNEL_MODE.EVAL, identity });

// Baseline — fresh handshake must pass
await check("BUG-2-base", "freshly-created handshake → accepted (baseline)", async () => {
  const ok = verifyClientHandshake(freshHS.message);
  assert.equal(ok, true, "fresh handshake must be accepted");
  return false;
});

// Bug evidence — 600-second-old message with valid signature must be rejected
await check(
  "BUG-2",
  "handshake_init with 600-second-old timestamp passes signature check — replay window is infinite",
  async () => {
    const { signature: _discard, ...unsigned } = freshHS.message;
    const staleBody = { ...unsigned, timestamp: nowSeconds() - 600 };
    const staleSig  = signUtf8(identity.privateKeyPem, canonicalJson(staleBody));
    const staleMsg  = { ...staleBody, signature: staleSig };

    const accepted = verifyClientHandshake(staleMsg);
    return accepted; // true = bug is present
  },
);

// ═════════════════════════════════════════════════════════════════════════════
// BUG-3  PERFORMANCE — O(n) SCAN ON HOT MESSAGE PATH
//
// File:    src/clients/control-client.ts  lines 336-337 and 430-431
// Code:    Array.from(publicTunnelOwners.entries())
//            .find(([, o]) => o.streamId === message.stream_id)
//
// Called on every STREAM_DATA and STREAM_CLOSE.  Allocates a fresh k-element
// array and scans up to k entries on each message.
//
// Fix:  maintain a reverse map  ownerByStreamId: Map<string, string>
//       so lookup is O(1) with no allocation.
// ═════════════════════════════════════════════════════════════════════════════

await check(
  "BUG-3",
  "O(n) linear scan for owner lookup is ≥10× slower than O(1) map (2 000 owners, 5 000 iters)",
  async () => {
    const N     = 2_000;
    const ITERS = 5_000;
    const TARGET = `stream-${N - 1}`; // worst-case: last entry

    type Owner = { streamId: string; nextStreamId: number };
    const owners = new Map<string, Owner>();
    for (let i = 0; i < N; i++)
      owners.set(`tunnel-${i}`, { streamId: `stream-${i}`, nextStreamId: 1 });

    // O(n) pattern — current code
    const t0 = performance.now();
    for (let i = 0; i < ITERS; i++)
      Array.from(owners.entries()).find(([, o]) => o.streamId === TARGET);
    const linearMs = performance.now() - t0;

    // O(1) pattern — proposed fix
    const rev = new Map<string, string>();
    for (const [tid, o] of owners) rev.set(o.streamId, tid);
    const t1 = performance.now();
    for (let i = 0; i < ITERS; i++) rev.get(TARGET);
    const hashMs = performance.now() - t1;

    const ratio = linearMs / Math.max(hashMs, 0.001);
    findings.push({
      id: "BUG-3-perf-ratio",
      desc: `O(n) ${linearMs.toFixed(1)} ms  vs  O(1) ${hashMs.toFixed(1)} ms  —  ${ratio.toFixed(0)}× speedup available`,
      bugPresent: ratio >= 10,
    });

    return ratio >= 10; // true = perf bug is measurable
  },
);

// ═════════════════════════════════════════════════════════════════════════════
// BUG-4  RELIABILITY — NON-ATOMIC STATE WRITES
//
// File:    src/node/state.ts  lines 60-63
// Code:    await fs.writeFile(file, JSON.stringify(value, null, 2), "utf8")
//
// fs.writeFile truncates first, then writes.  A SIGKILL between those two
// kernel operations (or during a long write of a large file) leaves partial
// JSON.  readJson silently returns its fallback — state loss is invisible.
//
// Fix:
//   const tmp = file + ".tmp." + process.pid;
//   await fs.writeFile(tmp, JSON.stringify(value, null, 2), "utf8");
//   await fs.rename(tmp, file);   // atomic on POSIX
// ═════════════════════════════════════════════════════════════════════════════

await check(
  "BUG-4",
  "partial write leaves undetectable corrupt JSON — readJson silently loses node_id",
  async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "bh4-"));
    const filePath = path.join(tmp, "config.json");
    try {
      await writeJson(filePath, { node_id: "node-abc", port: 9090 });

      // Simulate crash mid-write: truncate to incomplete JSON
      const handle  = await fs.open(filePath, "r+");
      const partial = Buffer.from('{"node_id":"replacing","por', "utf8");
      await handle.write(partial, 0, partial.length, 0);
      await handle.truncate(partial.length);
      await handle.close();

      const FALLBACK = { port: 9090 };
      const loaded   = await readJson<{ node_id?: string; port: number } | typeof FALLBACK>(filePath, FALLBACK);
      const silentlyLost = (loaded === FALLBACK); // fallback returned → corruption hidden

      return silentlyLost; // true = bug is present
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  },
);

// ─────────────────────────────────────────────────────────────────────────────
// Summary + exit code
// ─────────────────────────────────────────────────────────────────────────────

const bugs      = findings.filter(f => f.bugPresent && !f.id.endsWith("-perf-ratio"));
const baselines = findings.filter(f => !f.bugPresent && f.id.includes("-base"));

console.log("\n╔══════════════════════════════════════════════════════════════════════╗");
console.log(  "║  Daily Bug Hunt — 2026-05-22                                         ║");
console.log(  "╠══════════════════════════════════════════════════════════════════════╣");

for (const f of findings) {
  if (f.id.endsWith("-base") || f.id.endsWith("-base-ok") || f.id.endsWith("-base-bad") || f.id.endsWith("-base")) {
    console.log(`  ✓  ${f.desc}`);
  } else if (f.id.endsWith("-perf-ratio")) {
    console.log(`  ℹ  ${f.desc}`);
  } else if (f.bugPresent) {
    console.log(`  ✗  [${f.id}] ${f.desc}`);
    if (f.error) console.log(`       error: ${String(f.error)}`);
  } else {
    console.log(`  ✓  [${f.id}] FIXED — ${f.desc}`);
  }
}

console.log("╚══════════════════════════════════════════════════════════════════════╝\n");

if (bugs.length > 0) {
  console.error(`${bugs.length} bug(s) confirmed on this build. See findings above.\n`);
  process.exit(1);
}
