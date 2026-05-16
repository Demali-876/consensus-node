import { hrtime } from "node:process";

export interface BenchOptions {
  name: string;
  warmupMs?: number;
  measureMs?: number;
  minSamples?: number;
  maxSamples?: number;
}

export interface BenchStats {
  min: number;
  median: number;
  mean: number;
  p95: number;
  p99: number;
  stddev: number;
}

export interface BenchResult {
  name: string;
  reliable: boolean;
  samples: number;
  total_ops: number;
  duration_ms: number;
  ops_per_second: number;
  ns_per_op: BenchStats;
  cv: number;
}

/**
 * Run a benchmark function with warmup, multi-sample measurement, and statistical reporting.
 *
 * The function is invoked many times. Each invocation should perform some number of
 * operations (returning that count) — for fast operations, embed a tight inner loop and
 * return its iteration count so closure overhead is amortized.
 *
 * The runner discards results during warmup, then collects samples until either
 * `maxSamples` or `measureMs` is reached (whichever comes first, but never below
 * `minSamples`). Stats are computed across the per-op nanoseconds of every sample.
 *
 * `reliable: true` means the coefficient of variation is below 10% — the result is
 * stable enough to act on. Below that threshold treat the number with suspicion.
 */
export async function bench(
  fn: () => number | Promise<number>,
  opts: BenchOptions,
): Promise<BenchResult> {
  const warmupMs = opts.warmupMs ?? 200;
  const measureMs = opts.measureMs ?? 1000;
  const minSamples = opts.minSamples ?? 10;
  const maxSamples = opts.maxSamples ?? 200;

  // Warmup: run for warmupMs, discard results.
  const warmupEnd = hrtime.bigint() + BigInt(warmupMs * 1_000_000);
  while (hrtime.bigint() < warmupEnd) {
    await fn();
  }

  // Measure
  const samplesNs: number[] = [];
  const samplesOps: number[] = [];
  const measureStart = hrtime.bigint();
  const measureEnd = measureStart + BigInt(measureMs * 1_000_000);
  while (samplesNs.length < maxSamples) {
    if (hrtime.bigint() >= measureEnd && samplesNs.length >= minSamples) break;
    const start = hrtime.bigint();
    const ops = await fn();
    const elapsedNs = Number(hrtime.bigint() - start);
    if (ops > 0 && elapsedNs > 0) {
      samplesNs.push(elapsedNs);
      samplesOps.push(ops);
    }
  }
  const durationMs = Number(hrtime.bigint() - measureStart) / 1e6;

  if (samplesNs.length === 0) {
    return {
      name: opts.name,
      reliable: false,
      samples: 0,
      total_ops: 0,
      duration_ms: Math.round(durationMs),
      ops_per_second: 0,
      ns_per_op: { min: 0, median: 0, mean: 0, p95: 0, p99: 0, stddev: 0 },
      cv: 0,
    };
  }

  const nsPerOp = samplesNs.map((ns, i) => ns / samplesOps[i]);
  const sorted = [...nsPerOp].sort((a, b) => a - b);
  const mean = nsPerOp.reduce((a, b) => a + b, 0) / nsPerOp.length;
  const variance = nsPerOp.reduce((a, b) => a + (b - mean) ** 2, 0) / nsPerOp.length;
  const stddev = Math.sqrt(variance);
  const cv = mean > 0 ? stddev / mean : 0;

  return {
    name: opts.name,
    reliable: cv < 0.10 && samplesNs.length >= minSamples,
    samples: samplesNs.length,
    total_ops: samplesOps.reduce((a, b) => a + b, 0),
    duration_ms: Math.round(durationMs),
    ops_per_second: 1e9 / mean,
    ns_per_op: {
      min: sorted[0],
      median: percentile(sorted, 0.5),
      mean,
      p95: percentile(sorted, 0.95),
      p99: percentile(sorted, 0.99),
      stddev,
    },
    cv,
  };
}

export function percentile(sortedValues: number[], p: number): number {
  if (sortedValues.length === 0) return 0;
  const index = Math.max(
    0,
    Math.min(sortedValues.length - 1, Math.ceil(sortedValues.length * p) - 1),
  );
  return sortedValues[index] ?? 0;
}
