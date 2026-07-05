// Worker body for the multi-core scaling suite. Runs a sequential SHA-256
// chain — each hash consumes the previous digest, so the work cannot be
// parallelized or skipped WITHIN a worker; total across K workers therefore
// measures how many truly concurrent cores the machine gives this process.
// The final digest is returned so a verifier can recompute the chain from the
// seed — the same primitive the orchestrator-timed challenge will use later.
//
// Protocol: posts {type:"ready"} on load; on {type:"start", duration_ms, seed}
// runs the chain and posts {type:"done", ops, elapsed_ms, final}. The worker
// times its own loop so parent-side spawn overhead never pollutes the rate.

import crypto from "node:crypto";
import { hrtime } from "node:process";

declare var self: Worker;

const CHECK_EVERY = 256;

self.onmessage = (event: MessageEvent) => {
  const data = event.data as { type?: string; duration_ms?: number; seed?: string };
  if (data.type !== "start") return;

  const durationMs = Math.max(1, Number(data.duration_ms ?? 1000));
  let digest: Buffer = Buffer.from(String(data.seed ?? "consensus"), "utf8");

  const t0 = hrtime.bigint();
  const tEnd = t0 + BigInt(Math.round(durationMs * 1e6));
  let ops = 0;
  let now = t0;

  while (now < tEnd) {
    for (let i = 0; i < CHECK_EVERY; i++) {
      digest = crypto.createHash("sha256").update(digest).digest();
    }
    ops += CHECK_EVERY;
    now = hrtime.bigint();
  }

  postMessage({
    type: "done",
    ops,
    elapsed_ms: Number(now - t0) / 1e6,
    final: digest.toString("hex"),
  });
};

postMessage({ type: "ready" });
