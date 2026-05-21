/**
 * BUG: O(n) linear scan for public tunnel owner in hot message path
 *
 * control-client.ts handles STREAM_DATA and STREAM_CLOSE messages with:
 *
 *   const ownerEntry = Array.from(publicTunnelOwners.entries())
 *     .find(([, owner]) => owner.streamId === message.stream_id);
 *
 * `publicTunnelOwners` is keyed by tunnelId but searched by streamId.
 * Every incoming data or close frame triggers a full scan of all owners.
 * With N active public tunnel owners this is O(N) per message.
 *
 * This test proves the performance gap by timing the linear scan versus
 * a constant-time reverse-lookup Map<streamId, tunnelId>.
 *
 * Fix: maintain a parallel `streamIdToTunnelId: Map<string, string>` that
 * is populated when an owner stream is opened and removed when it is closed.
 * The STREAM_DATA handler becomes a single O(1) Map.get() instead of O(n).
 */

import assert from "node:assert/strict";

const N = 10_000; // number of simulated public tunnel owners

// ---- Build the data structures ----

// Current approach: Map<tunnelId, {streamId, ...}> — search by value.
const publicTunnelOwners = new Map<
  string,
  { streamId: string; nextStreamId: number }
>();

// Fix approach: Map<streamId, tunnelId> — O(1) reverse lookup.
const streamIdToTunnelId = new Map<string, string>();

for (let i = 0; i < N; i++) {
  const tunnelId = `tunnel-${i}`;
  const streamId = `stream-${i}`;
  publicTunnelOwners.set(tunnelId, { streamId, nextStreamId: 1 });
  streamIdToTunnelId.set(streamId, tunnelId);
}

// The lookup target is always the LAST entry to exercise worst-case O(n).
const targetStreamId = `stream-${N - 1}`;

// ---- Benchmark the current O(n) scan ----

const ITERATIONS = 1_000;

const scanStart = performance.now();
for (let i = 0; i < ITERATIONS; i++) {
  const found = Array.from(publicTunnelOwners.entries())
    .find(([, owner]) => owner.streamId === targetStreamId);
  // Prevent the loop from being optimised away.
  if (!found) throw new Error("entry not found");
}
const scanMs = performance.now() - scanStart;

// ---- Benchmark the O(1) reverse lookup ----

const mapStart = performance.now();
for (let i = 0; i < ITERATIONS; i++) {
  const tunnelId = streamIdToTunnelId.get(targetStreamId);
  if (!tunnelId) throw new Error("entry not found");
}
const mapMs = performance.now() - mapStart;

// ---- Assert the O(1) approach is meaningfully faster ----

const speedup = scanMs / mapMs;

console.log(
  `BUG: O(n) scan (n=${N}): ${scanMs.toFixed(2)} ms for ${ITERATIONS} iterations`,
);
console.log(
  `FIX: O(1) map lookup:    ${mapMs.toFixed(2)} ms for ${ITERATIONS} iterations`,
);
console.log(`Speedup with fix: ${speedup.toFixed(1)}×`);

assert.ok(
  speedup > 10,
  `Expected O(1) Map to be >10× faster than O(n) scan, got ${speedup.toFixed(1)}×. ` +
  "The fix (reverse lookup map) must be significantly faster for N=10,000.",
);

console.log(
  "BUG CONFIRMED — stream-owner-linear-scan: " +
  `Array.find() over ${N} owners is ${speedup.toFixed(0)}× slower than a Map lookup. ` +
  "Fix: add streamIdToTunnelId Map updated on STREAM_OPEN/STREAM_CLOSE.",
);
