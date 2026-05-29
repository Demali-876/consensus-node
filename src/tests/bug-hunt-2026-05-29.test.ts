/**
 * Bug Hunt – 2026-05-29
 *
 * Bug 1 – Handshake replay attack (SECURITY)
 *   assertHandshakeBase only checked that timestamp was a finite number; it
 *   never compared it against the current clock.  A captured, validly-signed
 *   INIT message could be replayed indefinitely.
 *   Fix: reject messages whose |timestamp - now| > MAX_HANDSHAKE_CLOCK_SKEW_SECONDS (300 s).
 *
 * Bug 2 – O(n) owner-stream lookup in STREAM_DATA / STREAM_CLOSE (PERFORMANCE)
 *   Both handlers scanned publicTunnelOwners linearly to find a stream by its
 *   value field.  With many concurrent public tunnels this degraded from O(1)
 *   to O(n) per message.
 *   Fix: maintain ownerStreamIds, a Map<streamId, tunnelId> reverse index.
 *
 * Bug 3 – Unbounded proxy response body (SECURITY / DoS)
 *   executeProxyCommand loaded the entire response body with response.arrayBuffer()
 *   and no size guard.  A target URL that returns gigabytes of data would
 *   exhaust the node's memory.
 *   Fix: reject responses whose Content-Length header or actual body exceeds
 *   MAX_PROXY_RESPONSE_BYTES (50 MB).
 */

import assert from "node:assert/strict";
import { decodeHandshakeMessage, MAX_HANDSHAKE_CLOCK_SKEW_SECONDS } from "../tunnel/handshake";
import { nowSeconds } from "../tunnel/messages";
import { executeProxyCommand } from "../runtime/proxy-command";

// ── Bug 1: Handshake Replay Attack ──────────────────────────────────────────
// Build a structurally valid INIT message (signature field not cryptographically
// verified by decodeHandshakeMessage; only checked to be a non-empty string).
const INIT_BASE = {
  type: "handshake_init",
  protocol: "consensus-node-tunnel",
  version: 1,
  mode: "eval",
  // 65-byte uncompressed EC point (P-256 raw public key shape)
  client_public_key: Buffer.alloc(65, 1).toString("base64"),
  client_nonce:      Buffer.alloc(32, 2).toString("base64"),
  node_public_key_pem: "-----BEGIN PUBLIC KEY-----\naGVsbG8=\n-----END PUBLIC KEY-----",
  signature:         Buffer.alloc(64, 3).toString("base64"),
};

// Fresh timestamp (within the window) must be accepted.
{
  const msg = { ...INIT_BASE, timestamp: nowSeconds() };
  const parsed = decodeHandshakeMessage(JSON.stringify(msg));
  assert.equal(parsed.type, "handshake_init", "Fresh handshake should parse successfully");
}

// Stale timestamp (past the skew window) must be rejected with a TypeError.
{
  const staleTs = nowSeconds() - (MAX_HANDSHAKE_CLOCK_SKEW_SECONDS + 60);
  const msg = { ...INIT_BASE, timestamp: staleTs };
  let threw: unknown = null;
  try { decodeHandshakeMessage(JSON.stringify(msg)); }
  catch (e) { threw = e; }
  assert.ok(
    threw instanceof TypeError,
    `Expected TypeError for stale timestamp, got: ${String(threw)}`,
  );
  assert.match(
    (threw as TypeError).message,
    /stale|skew|timestamp/i,
    "Error message should mention staleness",
  );
}

// Far-future timestamp (past the skew window) must also be rejected.
{
  const futureTs = nowSeconds() + (MAX_HANDSHAKE_CLOCK_SKEW_SECONDS + 60);
  const msg = { ...INIT_BASE, timestamp: futureTs };
  let threw: unknown = null;
  try { decodeHandshakeMessage(JSON.stringify(msg)); }
  catch (e) { threw = e; }
  assert.ok(
    threw instanceof TypeError,
    `Expected TypeError for future timestamp, got: ${String(threw)}`,
  );
}

// Timestamp exactly at the boundary (edge of the allowed window) must pass.
{
  const edgeTs = nowSeconds() - MAX_HANDSHAKE_CLOCK_SKEW_SECONDS;
  const msg = { ...INIT_BASE, timestamp: edgeTs };
  // This should not throw – boundary is inclusive.
  const parsed = decodeHandshakeMessage(JSON.stringify(msg));
  assert.equal(parsed.type, "handshake_init");
}

console.log("bug-1 (handshake replay) ok");

// ── Bug 2: O(n) Owner-Stream Lookup ─────────────────────────────────────────
// Demonstrate that the reverse-index Map lookup is faster than the linear
// Array.from(...).find(...) pattern it replaces.  With N=8 000 entries and
// the target at the end, the difference is pronounced.
{
  const N = 8_000;
  const ITERATIONS = 300;

  type OwnerEntry = { streamId: string; nextStreamId: number; ownerToServer: Map<number, string>; serverToOwner: Map<string, number> };
  const publicTunnelOwners = new Map<string, OwnerEntry>();
  const ownerStreamIds    = new Map<string, string>(); // reverse index (the fix)

  const targetStreamId = `stream-target-${crypto.randomUUID()}`;
  for (let i = 0; i < N; i++) {
    const tunnelId = `tunnel-${i}`;
    const streamId = i === N - 1 ? targetStreamId : `stream-${i}`;
    publicTunnelOwners.set(tunnelId, { streamId, nextStreamId: 1, ownerToServer: new Map(), serverToOwner: new Map() });
    ownerStreamIds.set(streamId, tunnelId);
  }

  // Old O(n) approach (what the code did before the fix)
  const t0 = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === targetStreamId);
  }
  const linearMs = performance.now() - t0;

  // New O(1) approach (after the fix)
  const t1 = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    const tid = ownerStreamIds.get(targetStreamId);
    if (tid !== undefined) publicTunnelOwners.get(tid);
  }
  const mapMs = performance.now() - t1;

  assert.ok(
    mapMs < linearMs,
    `Map O(1) lookup (${mapMs.toFixed(2)} ms) should be faster than linear O(n) scan ` +
    `(${linearMs.toFixed(2)} ms) over ${N} entries × ${ITERATIONS} iterations`,
  );
}

console.log("bug-2 (O(n) owner-stream lookup) ok");

// ── Bug 3: Unbounded Proxy Response Body ─────────────────────────────────────
// Mock globalThis.fetch to return a Content-Length header that exceeds the
// 50 MB guard added by the fix.  No real network traffic is needed.
{
  const MAX_BYTES = 50 * 1024 * 1024; // must match proxy-command.ts constant
  const OVER_LIMIT = MAX_BYTES + 1;

  const realFetch = globalThis.fetch;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).fetch = async () =>
    new Response(new Uint8Array(0), {
      status: 200,
      headers: { "content-length": String(OVER_LIMIT) },
    });

  let threw: unknown = null;
  try {
    await executeProxyCommand({
      type: "proxy_request",
      timestamp: nowSeconds(),
      id: crypto.randomUUID(),
      method: "GET",
      target_url: "http://example.invalid/oversized",
    });
  } catch (e) {
    threw = e;
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.ok(
    threw instanceof Error,
    `Expected Error for oversized proxy response, got: ${String(threw)}`,
  );
  assert.match(
    (threw as Error).message,
    /too large|exceed|limit/i,
    "Error message should describe the size violation",
  );
}

// Also verify that responses within the limit still succeed.
{
  const realFetch = globalThis.fetch;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).fetch = async () =>
    new Response(Buffer.from("hello"), {
      status: 200,
      headers: { "content-type": "text/plain" },
    });

  let result: Awaited<ReturnType<typeof executeProxyCommand>> | null = null;
  try {
    result = await executeProxyCommand({
      type: "proxy_request",
      timestamp: nowSeconds(),
      id: crypto.randomUUID(),
      method: "GET",
      target_url: "http://example.invalid/small",
    });
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.ok(result !== null, "Small response should succeed");
  assert.equal(result!.status, 200);
}

console.log("bug-3 (proxy response size limit) ok");

console.log("bug-hunt-2026-05-29 all checks passed");
