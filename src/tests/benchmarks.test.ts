import assert from "node:assert/strict";
import { bench, percentile } from "../runtime/benchmarks/runner";

// ---------------------------------------------------------------------------
// percentile() — index calculation edge cases
// ---------------------------------------------------------------------------

// p=0 must return the minimum (first) element, not undefined ?? 0
assert.equal(percentile([5, 10, 15], 0), 5, "p=0 must return minimum value");
assert.equal(percentile([0, 10, 20], 0), 0, "p=0 of [0,10,20] is 0 (the actual minimum)");
assert.equal(percentile([], 0.95), 0, "empty array returns 0");
assert.equal(percentile([], 0), 0, "empty array with p=0 returns 0");

const ten = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
assert.equal(percentile(ten, 0.95), 10, "p95 of [1..10] is 10");
assert.equal(percentile(ten, 0.5), 5, "p50 of [1..10] is 5");
assert.equal(percentile([1], 0.95), 1, "single-element array returns that element");

// ---------------------------------------------------------------------------
// bench() — sanity check the runner with a deterministic workload
// ---------------------------------------------------------------------------

const result = await bench(
  () => {
    // Workload sized so each sample takes ~microseconds, ensuring the runner
    // actually fills minSamples before measureMs elapses but doesn't burn the
    // whole budget on a trivial loop.
    let acc = 1;
    for (let i = 1; i <= 10_000; i++) acc = (acc * i) % 1_000_003;
    if (acc < 0) throw new Error("unreachable");
    return 10_000;
  },
  { name: "test-workload", warmupMs: 50, measureMs: 200, minSamples: 5 }
);

assert.equal(result.name, "test-workload", "name passed through");
assert.ok(result.samples >= 5, `expected at least 5 samples, got ${result.samples}`);
assert.ok(result.total_ops > 0, "total_ops must be > 0");
assert.ok(result.duration_ms > 0, "duration_ms must be > 0");
assert.ok(result.ops_per_second > 0, "ops_per_second must be > 0");
assert.ok(result.ns_per_op.min > 0, "min ns/op must be > 0");
assert.ok(result.ns_per_op.median >= result.ns_per_op.min, "median >= min");
assert.ok(result.ns_per_op.p95 >= result.ns_per_op.median, "p95 >= median");
assert.ok(result.ns_per_op.p99 >= result.ns_per_op.p95, "p99 >= p95");
assert.ok(result.ns_per_op.stddev >= 0, "stddev must be >= 0");
assert.ok(result.cv >= 0, "cv must be >= 0");
assert.equal(typeof result.reliable, "boolean", "reliable is a boolean flag");

console.log("benchmarks ok");
