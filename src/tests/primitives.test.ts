import assert from "node:assert/strict";
import { runEd25519 } from "../runtime/benchmarks/suites/ed25519";
import { runSessionDerive } from "../runtime/benchmarks/suites/session-derive";
import { runEncode } from "../runtime/benchmarks/suites/encode";

// ---------------------------------------------------------------------------
// Primitive diagnostic suites — shape + sanity on short windows. These decompose
// the composite stages (handshake, ticket_verify, response_encode); the actual
// numbers are calibrated per-hardware from full bench:cpu runs.
// ---------------------------------------------------------------------------

const SHORT = { warmupMs: 20, measureMs: 100 };

const ed = await runEd25519(SHORT);
assert.ok(ed.sign_per_second > 0, "ed25519 sign/s > 0");
assert.ok(ed.verify_per_second > 0, "ed25519 verify/s > 0");
assert.equal(ed.sign.name, "ed25519-sign", "sign result named");
assert.equal(ed.verify.name, "ed25519-verify", "verify result named");
assert.equal(typeof ed.reliable, "boolean", "ed25519 reliable is boolean");

const sd = await runSessionDerive(SHORT);
assert.equal(sd.curve, "P-256", "session-derive reports the real curve");
assert.ok(sd.derivations_per_second > 0, "session derivations/s > 0");
assert.ok(sd.ops_per_second > 0, "session-derive ops/s > 0");

const enc = await runEncode(SHORT);
assert.equal(enc.results.length, 3, "encode covers 1KB/16KB/256KB");
assert.deepEqual(
  enc.results.map((r) => r.payload_size_bytes),
  [1024, 16384, 262144],
  "encode sizes in order",
);
for (const r of enc.results) {
  assert.ok(r.bytes_per_second > 0, `encode ${r.payload_size_bytes}B throughput > 0`);
}
// Larger payloads move more bytes/sec (base64+copy is bandwidth-bound at size).
assert.ok(
  enc.results[2]!.bytes_per_second > enc.results[0]!.bytes_per_second,
  "256KB encode throughput exceeds 1KB (amortized per-call overhead)",
);
assert.equal(
  enc.bytes_per_second,
  enc.results[1]!.bytes_per_second,
  "encode headline is the 16KB figure",
);

console.log("primitives ok");
