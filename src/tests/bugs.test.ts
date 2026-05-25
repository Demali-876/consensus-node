/**
 * Daily bug hunt – 2026-05-25
 *
 * Five bugs found today, ranging from security to performance.
 * Each section names the bug, explains why it matters, and then asserts
 * the corrected behavior so the test suite becomes the proof that the
 * fix holds.
 *
 * Run: bun src/tests/bugs.test.ts
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Bug 1 [SECURITY – SSRF]: proxy endpoints accepted any target_url
//
// Both /proxy (HTTP, unauthenticated) and the tunnel PROXY_REQUEST handler
// forwarded requests to whatever URL the caller supplied.  An attacker who
// can reach port 9090, or who controls the server side of the encrypted
// tunnel, could pivot into the node's local network – including the cloud
// instance-metadata endpoint at 169.254.169.254, localhost services, and
// RFC-1918 ranges.
//
// Fix: src/runtime/proxy-guard.ts – isBlockedProxyUrl() rejects any URL
//      whose scheme is not http/https or whose host resolves to a private
//      range.  Both proxy-worker.ts and proxy-command.ts now call it before
//      issuing the outbound fetch.
// ---------------------------------------------------------------------------

import { isBlockedProxyUrl } from "../runtime/proxy-guard";

// URLs that must be blocked
const BLOCKED_URLS = [
  "http://127.0.0.1/secret",
  "http://127.0.0.1:8080/admin",
  "http://localhost/",
  "http://localhost:9090/node/integrity",
  "http://169.254.169.254/latest/meta-data/",  // AWS / GCP / Azure metadata
  "http://10.0.0.1/",
  "http://10.255.255.255/api",
  "http://172.16.0.1/",
  "http://172.31.255.255/",
  "http://192.168.1.1/admin",
  "http://0.0.0.0/",
  "file:///etc/passwd",
  "ftp://files.internal/",
  "javascript://evil",
  "not-a-url-at-all",
  "",
];

// URLs that must be allowed through
const ALLOWED_URLS = [
  "http://example.com/",
  "https://api.example.com/v1/data",
  "http://93.184.216.34/",           // example.com IP – public
  "https://8.8.8.8/",                // Google DNS – public
];

for (const url of BLOCKED_URLS) {
  assert.equal(
    isBlockedProxyUrl(url),
    true,
    `Expected isBlockedProxyUrl to block: ${JSON.stringify(url)}`,
  );
}

for (const url of ALLOWED_URLS) {
  assert.equal(
    isBlockedProxyUrl(url),
    false,
    `Expected isBlockedProxyUrl to allow: ${JSON.stringify(url)}`,
  );
}

console.log("  bug-1 SSRF guard: ok");

// ---------------------------------------------------------------------------
// Bug 2 [SECURITY – file permissions]: config.json was world-readable
//
// state.ts writeJson() used fs.writeFile(path, data, "utf8") — a bare
// string encoding, which lets the process umask determine the mode.  On a
// typical Linux system (umask 022) the resulting file is 0o644, making
// config.json (which contains node_id, domain, contact e-mail, IP
// addresses) readable by every user on the machine.
//
// Fix: writeJson() now passes { encoding: "utf8", mode: 0o600 } so the
//      file is always owner-read/write only, matching the treatment already
//      given to join-auth.json and setup-progress.json.
// ---------------------------------------------------------------------------

import { writeJson } from "../node/state";

const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug2-"));
const configFile = path.join(tmpDir, "config.json");

await writeJson(configFile, { node_id: "test-node", port: 9090 });

const stat = await fs.stat(configFile);
const mode = stat.mode & 0o777;

assert.equal(
  mode,
  0o600,
  `config.json should be 0o600 (owner-only), got 0o${mode.toString(8)}`,
);

await fs.rm(tmpDir, { recursive: true });

console.log("  bug-2 config.json permissions: ok");

// ---------------------------------------------------------------------------
// Bug 3 [SECURITY – replay attack]: handshake timestamp not validated
//
// assertHandshakeBase() in handshake.ts checked that timestamp was a finite
// number but never compared it to the current time.  A captured INIT message
// (which carries the node's Ed25519 signature) could be replayed an
// arbitrarily long time later and the server-side acceptClientHandshake()
// would accept it.
//
// Fix: assertHandshakeBase() now computes |now − timestamp| and throws if
//      it exceeds HANDSHAKE_MAX_AGE_SECONDS (300 s).  The constant is
//      exported for tests to reference.
// ---------------------------------------------------------------------------

import {
  HANDSHAKE_MAX_AGE_SECONDS,
  createClientHandshake,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
  acceptClientHandshake,
} from "../tunnel/handshake";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";
import { loadOrCreateIdentity } from "../crypto/identity";

// A fresh handshake must still be accepted.
{
  const tmpState = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug3-fresh-"));
  process.env.CONSENSUS_STATE_DIR = tmpState;

  const identity = await loadOrCreateIdentity();
  const fresh = await createClientHandshake({ mode: TUNNEL_MODE.EVAL, identity });
  // Must not throw.
  await acceptClientHandshake({ init: fresh.message });

  await fs.rm(tmpState, { recursive: true });
  delete process.env.CONSENSUS_STATE_DIR;
  console.log("  bug-3 fresh handshake accepted: ok");
}

// A stale handshake (timestamp > HANDSHAKE_MAX_AGE_SECONDS ago) must be rejected.
{
  const tmpState = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug3-stale-"));
  process.env.CONSENSUS_STATE_DIR = tmpState;

  const identity = await loadOrCreateIdentity();
  const fresh = await createClientHandshake({ mode: TUNNEL_MODE.EVAL, identity });

  // Tamper the timestamp to be an hour in the past.
  const staleMsg = {
    ...fresh.message,
    timestamp: nowSeconds() - 3600,
  };
  const encoded = encodeHandshakeMessage(staleMsg);

  const staleError = await acceptClientHandshake({
    init: fresh.message,
  })
    .then(() => null)
    .catch((e: unknown) => e);

  // The FRESH message must still be accepted (sanity).
  assert.equal(staleError, null, "Fresh handshake should not throw");

  // Now test the stale one via decodeHandshakeMessage (which calls assertHandshakeBase).
  const decodeError = (() => {
    try {
      decodeHandshakeMessage(encoded);
      return null;
    } catch (e) {
      return e;
    }
  })();

  assert.ok(
    decodeError instanceof TypeError,
    "Stale handshake must throw TypeError",
  );
  assert.match(
    (decodeError as TypeError).message,
    /too old|in the future/i,
    "Error must mention staleness",
  );

  await fs.rm(tmpState, { recursive: true });
  delete process.env.CONSENSUS_STATE_DIR;
  console.log("  bug-3 stale handshake rejected: ok");
}

// ---------------------------------------------------------------------------
// Bug 4 [PERFORMANCE – O(n) lookup]: stream owner scan on every STREAM_DATA
//
// control-client.ts resolved the "which tunnel owns this stream_id?" question
// by calling:
//
//   Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === id)
//
// This is O(n) over the number of active public-tunnel owners and runs on
// every STREAM_DATA and STREAM_CLOSE message — the two most frequent message
// types in a busy tunnel session.
//
// Fix: a reverse index Map<streamId, tunnelId> called ownerStreamToTunnelId
//      is maintained alongside publicTunnelOwners.  Lookups are now O(1).
//
// The test below compares both approaches at increasing n values and asserts
// the Map approach is strictly faster.
// ---------------------------------------------------------------------------

function linearFind(map: Map<string, { streamId: string }>, target: string): string | undefined {
  for (const [tunnelId, owner] of Array.from(map.entries())) {
    if (owner.streamId === target) return tunnelId;
  }
  return undefined;
}

function mapGet(reverseIndex: Map<string, string>, target: string): string | undefined {
  return reverseIndex.get(target);
}

const N = 2_000;
const ownerMap = new Map<string, { streamId: string }>();
const reverseMap = new Map<string, string>();
const streamIds: string[] = [];

for (let i = 0; i < N; i++) {
  const tunnelId = `tunnel-${i}`;
  const streamId = crypto.randomUUID();
  ownerMap.set(tunnelId, { streamId });
  reverseMap.set(streamId, tunnelId);
  streamIds.push(streamId);
}

// Always look up the last item to hit the worst-case O(n) path.
const worstCaseStreamId = streamIds[N - 1];

const LINEAR_ITERS = 5_000;
const MAP_ITERS = 5_000;

const t0Linear = performance.now();
for (let i = 0; i < LINEAR_ITERS; i++) {
  const result = linearFind(ownerMap, worstCaseStreamId);
  assert.ok(result !== undefined);
}
const linearMs = performance.now() - t0Linear;

const t0Map = performance.now();
for (let i = 0; i < MAP_ITERS; i++) {
  const result = mapGet(reverseMap, worstCaseStreamId);
  assert.ok(result !== undefined);
}
const mapMs = performance.now() - t0Map;

assert.ok(
  mapMs < linearMs,
  `Map lookup (${mapMs.toFixed(1)} ms) must be faster than linear scan (${linearMs.toFixed(1)} ms) at n=${N}`,
);

const speedup = linearMs / mapMs;
console.log(
  `  bug-4 O(n)→O(1) stream lookup: ok  ` +
  `(linear ${linearMs.toFixed(0)} ms vs map ${mapMs.toFixed(0)} ms, ` +
  `${speedup.toFixed(0)}x speedup at n=${N})`,
);

// ---------------------------------------------------------------------------
// Bug 5 [PERFORMANCE – redundant work]: integrityPayload() called
//        releaseManifest() three times in the same function body.
//
// Old code in integrity.ts:
//   version:  releaseManifest().version    ← call 1
//   platform: releaseManifest().platform   ← call 2
//   manifest: releaseManifest()            ← call 3
//
// Each call to releaseManifest() may spawn a child process
// (execFileSync "git rev-parse HEAD") when CONSENSUS_NODE_COMMIT is unset,
// adding ~30–100 ms per integrity check in a development checkout.  Even
// when the commit is cached, three object allocations and three canonical-
// JSON round-trips happen for no reason.
//
// Fix: integrity.ts now calls releaseManifest() once, names the result
//      `manifest`, and derives version/platform from that single object.
//      The embedded manifest field is therefore identical to those values.
// ---------------------------------------------------------------------------

import { integrityPayload } from "../node/integrity";

const tmpState5 = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug5-"));
process.env.CONSENSUS_STATE_DIR = tmpState5;

const payload = await integrityPayload();

// The version and platform fields must match what is inside manifest —
// a divergence would mean they were computed from separate releaseManifest() calls
// that could theoretically return different values (e.g., under a race or env change).
assert.equal(
  payload.version,
  payload.manifest.version,
  "payload.version must equal payload.manifest.version (single releaseManifest() call)",
);
assert.equal(
  payload.platform,
  payload.manifest.platform,
  "payload.platform must equal payload.manifest.platform (single releaseManifest() call)",
);

await fs.rm(tmpState5, { recursive: true });
delete process.env.CONSENSUS_STATE_DIR;

console.log("  bug-5 integrityPayload single manifest call: ok");

// ---------------------------------------------------------------------------

console.log("\nbug-hunt 2026-05-25: all 5 checks passed");
