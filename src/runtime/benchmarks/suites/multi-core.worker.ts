// Worker body for the multi-core scaling suite. Runs a sequential integer-mix
// chain — each round consumes the previous 32-bit state, so the work cannot be
// parallelized or skipped WITHIN a worker; total across K workers therefore
// measures how many truly concurrent cores the machine gives this process.
//
// The kernel is deliberately ALLOCATION-FREE: xorshift + a multiply mix on a
// single local `number`, no heap traffic in the hot loop. An earlier version
// hashed with crypto.createHash("sha256") per round, which allocated a Hash
// object + digest Buffer every iteration; under K workers the process-wide
// allocator and each isolate's GC serialized on that, so the suite measured
// allocator contention instead of core scaling (2 workers already halved). A
// pure-ALU kernel isolates the thing we actually want: parallel compute.
//
// The final state is returned so a verifier can recompute the chain from the
// seed — a deterministic proof-of-work primitive the orchestrator-timed
// challenge can reuse later (cleaner than crypto-lib timing variance).
//
// Protocol: posts {type:"ready"} on load; on {type:"start", duration_ms, seed}
// runs the chain and posts {type:"done", ops, elapsed_ms, final}. The worker
// times its own loop so parent-side spawn overhead never pollutes the rate.

import { hrtime } from "node:process";

declare var self: Worker;

// Integer ops are ~1ns, so batch large between clock reads — the hrtime call
// must not dominate the loop.
const BATCH = 8192;

/** FNV-1a-ish fold of the seed string into a non-zero 32-bit state. */
function seedState(seed: string): number {
  let h = 0x811c9dc5 | 0;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193) | 0;
  }
  return h === 0 ? 1 : h;
}

self.onmessage = (event: MessageEvent) => {
  const data = event.data as { type?: string; duration_ms?: number; seed?: string };
  if (data.type !== "start") return;

  const durationMs = Math.max(1, Number(data.duration_ms ?? 1000));
  let h = seedState(String(data.seed ?? "consensus"));

  const t0 = hrtime.bigint();
  const tEnd = t0 + BigInt(Math.round(durationMs * 1e6));
  let ops = 0;
  let now = t0;

  while (now < tEnd) {
    for (let i = 0; i < BATCH; i++) {
      h ^= h << 13;
      h ^= h >>> 17;
      h ^= h << 5;
      h = (Math.imul(h, 0x9e3779b1) + 0x6d2b79f5) | 0;
    }
    ops += BATCH;
    now = hrtime.bigint();
  }

  // Post `final` so the JIT cannot eliminate the loop as dead code.
  postMessage({ type: "done", ops, elapsed_ms: Number(now - t0) / 1e6, final: h >>> 0 });
};

postMessage({ type: "ready" });
