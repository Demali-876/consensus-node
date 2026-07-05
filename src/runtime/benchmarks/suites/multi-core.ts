// Multi-core scaling: K workers each run an independent sequential SHA-256
// chain (see multi-core.worker.ts) for the same wall window; summing their
// self-timed rates shows how much total CPU the machine really gives this
// process as concurrency rises.
//
// What the curve tells you:
//   - efficiency ~1.0 up to N     → N real, unshared cores
//   - efficiency cliff at small K → oversubscribed vCPUs / shared host
//   - taper on Apple Silicon      → P-core vs E-core mix (expected, not a flaw)
//
// `effective_cores` (total throughput at max K over one worker's rate) is the
// honest core count for capacity math — os.cpus().length is what the OS
// advertises, not what you can use. The node runtime itself is single-threaded
// today, so this does not gate the composite headline; it informs fleet
// capacity planning and exposes dishonest hosting.
//
// All workers start together: each posts "ready" on load, the parent then
// broadcasts "start", and each worker times its own loop — parent-side spawn
// cost stays out of the measurement.

import crypto from "node:crypto";
import os from "node:os";

export interface MultiCoreOptions {
  /** Per-point measurement window (each worker times itself). */
  durationMs?: number;
  /** Worker counts to sample. Defaults to powers of two up to the core count,
   *  plus the core count itself. */
  points?: number[];
}

export interface MultiCorePoint {
  workers: number;
  total_ops_per_second: number;
  per_worker_ops_per_second: number;
  /** (total@K / K) / per-worker@1 — 1.0 means perfect scaling. */
  efficiency: number;
}

export interface MultiCoreResult {
  cores: number;
  chain: "sha256";
  points: MultiCorePoint[];
  single_ops_per_second: number;
  /** total@maxK / per-worker@1 — how many cores' worth of work you actually get. */
  effective_cores: number;
}

interface WorkerDone {
  type: "done";
  ops: number;
  elapsed_ms: number;
  final: string;
}

export async function runMultiCore(opts: MultiCoreOptions = {}): Promise<MultiCoreResult> {
  const cores = Math.max(1, os.cpus().length);
  const durationMs = opts.durationMs ?? 1500;
  const points = opts.points ?? defaultPoints(cores);

  const measured: MultiCorePoint[] = [];
  let singleRate = 0;

  for (const workers of points) {
    const totalRate = await measureWorkers(workers, durationMs);
    const perWorker = totalRate / workers;
    if (workers === 1) singleRate = perWorker;
    measured.push({
      workers,
      total_ops_per_second: Math.round(totalRate),
      per_worker_ops_per_second: Math.round(perWorker),
      efficiency: singleRate > 0 ? round3(perWorker / singleRate) : 0,
    });
  }

  const last = measured[measured.length - 1];
  return {
    cores,
    chain: "sha256",
    points: measured,
    single_ops_per_second: Math.round(singleRate),
    effective_cores:
      singleRate > 0 && last ? round1(last.total_ops_per_second / singleRate) : 0,
  };
}

export function defaultPoints(cores: number): number[] {
  const points = [1];
  for (let k = 2; k < cores; k *= 2) points.push(k);
  if (!points.includes(cores)) points.push(cores);
  return points;
}

async function measureWorkers(count: number, durationMs: number): Promise<number> {
  const workers = Array.from(
    { length: count },
    () => new Worker(new URL("./multi-core.worker.ts", import.meta.url).href),
  );

  try {
    await Promise.all(workers.map((worker) => waitForMessage(worker, "ready", 10_000)));

    const done = workers.map((worker) => waitForMessage(worker, "done", durationMs + 15_000));
    for (const worker of workers) {
      worker.postMessage({
        type: "start",
        duration_ms: durationMs,
        seed: crypto.randomBytes(16).toString("hex"),
      });
    }

    const results = (await Promise.all(done)) as WorkerDone[];
    return results.reduce((sum, result) => {
      if (!(result.ops > 0) || !(result.elapsed_ms > 0)) {
        throw new Error("multi-core: worker reported an empty measurement");
      }
      return sum + (result.ops * 1000) / result.elapsed_ms;
    }, 0);
  } finally {
    for (const worker of workers) worker.terminate();
  }
}

function waitForMessage(worker: Worker, type: string, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`multi-core: timed out waiting for worker "${type}"`)),
      timeoutMs,
    );
    const onMessage = (event: MessageEvent): void => {
      const data = event.data as { type?: string };
      if (data?.type !== type) return;
      clearTimeout(timer);
      worker.removeEventListener("message", onMessage);
      resolve(event.data);
    };
    worker.addEventListener("message", onMessage);
    worker.addEventListener("error", (event) => {
      clearTimeout(timer);
      reject(new Error(`multi-core: worker error: ${event.message}`));
    });
  });
}

const round1 = (v: number): number => Math.round(v * 10) / 10;
const round3 = (v: number): number => Math.round(v * 1000) / 1000;
