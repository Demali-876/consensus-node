import assert from "node:assert/strict";
import { runSustained } from "../runtime/benchmarks/suites/sustained";

// ---------------------------------------------------------------------------
// runSustained() — shape + windowing on a tiny run (1.2s, 300ms windows).
// The throttle finding itself needs a real 60s run on target hardware; this
// verifies the mechanics: windows fill, both throughput clocks tick, the
// ratio and cpu accounting are computed.
// ---------------------------------------------------------------------------

const result = await runSustained({
  durationMs: 1200,
  windowMs: 300,
  warmupMs: 100,
  responseBytes: 4096,
});

assert.equal(result.response_size_bytes, 4096, "response size echoed");
assert.ok(result.windows.length >= 3, `expected >= 3 full windows, got ${result.windows.length}`);
assert.ok(result.total_requests > 0, "requests were served");
assert.equal(result.window_ms, 300, "window length echoed");

let windowRequests = 0;
for (const window of result.windows) {
  assert.ok(window.requests > 0, "every window served requests");
  assert.ok(window.rps > 0, "wall rps > 0");
  assert.ok(window.node_rps > 0, "node rps > 0");
  assert.ok(
    window.node_rps > window.rps,
    `node-side rps (${window.node_rps}) must exceed wall rps (${window.rps}) — node time is a subset of wall time`,
  );
  windowRequests += window.requests;
}
assert.ok(
  windowRequests <= result.total_requests,
  "windowed requests never exceed the total (trailing partial window is dropped)",
);

assert.ok(result.node_rps_early > 0, "early throughput computed");
assert.ok(result.node_rps_late > 0, "late throughput computed");
assert.ok(result.throttle_ratio > 0, "throttle ratio computed");
assert.ok(
  result.node_rps_min_window <= result.node_rps_max_window,
  "min window <= max window",
);
assert.ok(result.cpu_time_ratio > 0, "cpu time ratio computed");
assert.equal(typeof result.steady, "boolean", "steady verdict is boolean");

console.log("sustained ok");
