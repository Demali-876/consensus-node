import assert from "node:assert/strict";
import { defaultPoints, runMultiCore } from "../runtime/benchmarks/suites/multi-core";

// ---------------------------------------------------------------------------
// defaultPoints() — powers of two up to the core count, core count included.
// ---------------------------------------------------------------------------

assert.deepEqual(defaultPoints(1), [1], "single core samples only K=1");
assert.deepEqual(defaultPoints(2), [1, 2], "two cores");
assert.deepEqual(defaultPoints(8), [1, 2, 4, 8], "power-of-two core count has no duplicate tail");
assert.deepEqual(defaultPoints(14), [1, 2, 4, 8, 14], "core count appended when not a power of two");

// ---------------------------------------------------------------------------
// runMultiCore() — real workers, tiny windows. Verifies the ready/start/done
// protocol, self-timed rates, and the efficiency math; the actual scaling
// curve needs a full run on target hardware.
// ---------------------------------------------------------------------------

const result = await runMultiCore({ durationMs: 250, points: [1, 2] });

assert.equal(result.points.length, 2, "one point per requested worker count");
assert.equal(result.chain, "int-mix", "chain identifies the allocation-free workload");
assert.ok(result.cores >= 1, "core count reported");

const [one, two] = result.points;
assert.equal(one!.workers, 1);
assert.equal(two!.workers, 2);
assert.ok(one!.total_ops_per_second > 0, "K=1 measured");
assert.ok(two!.total_ops_per_second > 0, "K=2 measured");
assert.equal(
  one!.total_ops_per_second,
  one!.per_worker_ops_per_second,
  "K=1 total equals per-worker",
);
assert.equal(one!.efficiency, 1, "efficiency is defined as 1.0 at K=1");
assert.ok(
  two!.efficiency > 0.2 && two!.efficiency <= 1.6,
  `K=2 efficiency in a sane band, got ${two!.efficiency}`,
);
assert.equal(
  result.single_ops_per_second,
  one!.per_worker_ops_per_second,
  "single-worker baseline echoed",
);
assert.ok(result.effective_cores > 0, "effective cores computed");

console.log("multi-core ok");
