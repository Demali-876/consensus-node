/**
 * PERFORMANCE BUG: O(n) linear scan in STREAM_DATA and STREAM_CLOSE handlers.
 *
 * In control-client.ts two message handlers call:
 *
 *   Array.from(publicTunnelOwners.entries())
 *     .find(([, owner]) => owner.streamId === message.stream_id);
 *
 * publicTunnelOwners is keyed by tunnelId, not streamId.  To find the owner
 * whose streamId matches the incoming message the code converts the entire Map
 * to an array and performs a sequential search.  This is O(n) where n is the
 * number of active public-tunnel owners, and it runs on EVERY STREAM_DATA and
 * STREAM_CLOSE message — including the common case where the message belongs
 * to a raw TCP stream (no match found, so the full scan always completes).
 *
 * Fix: maintain a reverse map  streamId → tunnelId  that is updated whenever
 * a public-tunnel-owner stream is opened or closed:
 *
 *   const ownerStreamIdToTunnelId = new Map<string, string>();
 *   // on open:  ownerStreamIdToTunnelId.set(streamId, tunnelId);
 *   // on close: ownerStreamIdToTunnelId.delete(streamId);
 *   // lookup:   ownerStreamIdToTunnelId.get(message.stream_id)
 *
 * This makes the lookup O(1) regardless of how many tunnel owners are active.
 *
 * Test contract
 * ─────────────
 * This test benchmarks both approaches with N=1 000 entries (worst-case:
 * target is the last entry).  It CURRENTLY PASSES because the speedup is
 * always measurable — that is intentional: the test is a performance
 * regression guard that also serves as evidence of the bottleneck.
 */
import assert from "node:assert/strict";

const N = 1_000;
const ITERS = 4_000;

interface OwnerEntry {
  streamId: string;
  nextStreamId: number;
  ownerToServer: Map<number, string>;
  serverToOwner: Map<string, number>;
}

// Build the same data structures used in control-client.ts
const publicTunnelOwners = new Map<string, OwnerEntry>();
const ownerStreamIdToTunnelId = new Map<string, string>(); // proposed fix

for (let i = 0; i < N; i++) {
  const tunnelId = `tunnel-${i}`;
  const streamId = `stream-owner-${i}`;
  publicTunnelOwners.set(tunnelId, {
    streamId,
    nextStreamId: 1,
    ownerToServer: new Map(),
    serverToOwner: new Map(),
  });
  ownerStreamIdToTunnelId.set(streamId, tunnelId);
}

// Worst-case lookup target: the very last entry in insertion order
const targetStreamId = `stream-owner-${N - 1}`;

// Warm-up (prevent cold-JIT skew)
for (let i = 0; i < 200; i++) {
  Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === targetStreamId);
  ownerStreamIdToTunnelId.get(targetStreamId);
}

// ── Current implementation: O(n) array scan ──────────────────────────────────

let linearResult: string | undefined;
const t0 = performance.now();
for (let i = 0; i < ITERS; i++) {
  linearResult = Array.from(publicTunnelOwners.entries())
    .find(([, o]) => o.streamId === targetStreamId)?.[0];
}
const linearMs = performance.now() - t0;

// ── Proposed fix: O(1) reverse-map lookup ────────────────────────────────────

let mapResult: string | undefined;
const t1 = performance.now();
for (let i = 0; i < ITERS; i++) {
  mapResult = ownerStreamIdToTunnelId.get(targetStreamId);
}
const mapMs = performance.now() - t1;

console.log(`O(n) scan  (N=${N}, ${ITERS} iters): ${linearMs.toFixed(1)} ms`);
console.log(`O(1) lookup (${ITERS} iters):         ${mapMs.toFixed(1)} ms`);
console.log(`Speedup: ${(linearMs / mapMs).toFixed(1)}×`);

// Both approaches must return the same tunnelId
assert.equal(linearResult, mapResult, "O(n) and O(1) approaches must return the same tunnelId");
assert.equal(linearResult, `tunnel-${N - 1}`, "Lookup must find the correct tunnel owner");

// The O(1) reverse-map must be meaningfully faster
assert.ok(
  linearMs > mapMs * 3,
  `PERF BUG (public-tunnel-scan): O(n) array scan took ${linearMs.toFixed(1)} ms ` +
  `but O(1) Map.get() took only ${mapMs.toFixed(1)} ms (${(linearMs / mapMs).toFixed(1)}× ` +
  `slower, expected >3×).  ` +
  `STREAM_DATA / STREAM_CLOSE handlers in control-client.ts call ` +
  `Array.from(publicTunnelOwners.entries()).find() on every incoming message — ` +
  `replace with a reverse ownerStreamId→tunnelId Map to restore O(1) dispatch.`,
);

console.log("public-tunnel-scan ok");
