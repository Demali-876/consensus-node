import { bench, type BenchResult } from "../runner";

export type EventLoopResult = BenchResult;

/**
 * Measure event-loop scheduling jitter via `setImmediate`. Each sample is one
 * round-trip from "schedule a callback" to "callback fires".
 *
 * For a proxy that handles thousands of concurrent connections, this is the most
 * predictive single number for responsiveness — a healthy event loop has p99 well
 * under 1ms (~1,000,000 ns); a pathological one can stretch to tens of ms.
 *
 * `ops_per_second` is roughly "scheduling iterations per second the event loop
 * can sustain when nothing is competing for it"; the percentile breakdown is
 * what actually matters for assessing tail latency.
 */
export async function runEventLoop(): Promise<EventLoopResult> {
  return bench(
    async () => {
      await new Promise<void>((resolve) => setImmediate(resolve));
      return 1;
    },
    { name: "event-loop", measureMs: 500, maxSamples: 1000 },
  );
}
