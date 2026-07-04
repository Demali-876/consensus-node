import assert from "node:assert/strict";
import {
  DEFAULT_COMPOSITE_SIZES,
  runCompositeRequest,
  type CompositeStageName,
} from "../runtime/benchmarks/suites/composite-request";

// ---------------------------------------------------------------------------
// runCompositeRequest() — shape + internal consistency on tiny windows.
// The suite's own sanity pass (real serveDataConnection + runDataRequest round
// trip per size) runs inside this call: if the decomposed stages ever drift
// from the production pipeline, this test fails before any assertion below.
// ---------------------------------------------------------------------------

const STAGES: CompositeStageName[] = [
  "handshake",
  "request_open",
  "ticket_verify",
  "response_encode",
  "response_seal",
];

const result = await runCompositeRequest({
  warmupMs: 30,
  measureMs: 150,
  sizes: [
    { label: "1KB", response_bytes: 1024, inner: 2 },
    { label: "16KB", response_bytes: 16384, inner: 1 },
  ],
});

assert.equal(result.results.length, 2, "one sub-result per size config");

for (const sub of result.results) {
  const tag = `${sub.response_size_bytes}B`;
  assert.ok(sub.exchange.samples > 0, `${tag}: runner collected samples`);
  assert.ok(sub.exchange.total_ops > 0, `${tag}: iterations counted`);
  assert.ok(sub.node_requests_per_second > 0, `${tag}: node req/s > 0`);
  assert.ok(sub.node_ns_per_request > 0, `${tag}: node ns/request > 0`);

  // Node-side time must be positive but cannot exceed the whole exchange
  // (client prep + node stages) the runner timed.
  assert.ok(
    sub.node_ns_per_request < sub.exchange.ns_per_op.mean,
    `${tag}: node share (${sub.node_ns_per_request}ns) below whole exchange (${sub.exchange.ns_per_op.mean}ns)`,
  );

  let shareSum = 0;
  for (const stage of STAGES) {
    const stats = sub.stages[stage];
    assert.ok(stats, `${tag}: stage ${stage} present`);
    assert.ok(stats.mean_ns > 0, `${tag}: stage ${stage} measured (> 0ns)`);
    shareSum += stats.share;
  }
  assert.ok(Math.abs(shareSum - 1) < 0.01, `${tag}: stage shares sum to ~1 (got ${shareSum})`);
}

// Larger responses cost more node-side time per request (encode + seal scale).
const [small, big] = result.results;
assert.ok(
  big!.node_ns_per_request > small!.node_ns_per_request,
  "16KB responses cost more per request than 1KB",
);

// Headline convention: node req/s at 16KB (falls back to last size otherwise).
assert.equal(
  result.requests_per_second,
  big!.node_requests_per_second,
  "headline is the 16KB figure",
);

// Default size table stays on the documented axis.
assert.deepEqual(
  DEFAULT_COMPOSITE_SIZES.map((s) => s.response_bytes),
  [1024, 16384, 262144],
  "default sizes are 1KB / 16KB / 256KB",
);

console.log("composite-request ok");
