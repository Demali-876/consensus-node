// Sustained-vs-burst: runs the composite request workload continuously (60s by
// default) and windows the throughput, because the machines that fail in
// production are the ones that look fine for ten seconds — burst-credit cloud
// vCPUs (T-series and friends) that run out of credits, and thermally limited
// SBCs that throttle once the SoC heats up. A short benchmark measures the
// burst; a Consensus node lives in the steady state.
//
// The finding is the THROTTLE RATIO: late-window node-side throughput divided
// by early-window node-side throughput. A healthy machine holds ≥ 0.85; a
// throttling one decays visibly across the window series.
//
// Two throughputs are reported per window:
//   - node_rps   from the workload's timed node-side stage clock — comparable
//                to the composite headline, and what the ratio judges.
//   - rps        wall-clock exchanges/sec (includes the untimed client prep
//                that shares this CPU) — context only, do NOT compare it to
//                the composite headline.
//
// The run also tracks process.cpuUsage() over the whole window: cpu_time_ratio
// well below ~0.95 means the process was not getting a full core — hypervisor
// steal or host contention — so a low throttle ratio should be read as "this
// environment", not necessarily "this silicon". (JavaScriptCore's concurrent GC
// threads can push the ratio slightly above 1; that is normal.)

import { hrtime } from "node:process";
import { createCompositeWorkload } from "./composite-request";

export interface SustainedOptions {
  durationMs?: number;
  windowMs?: number;
  responseBytes?: number;
  warmupMs?: number;
}

export interface SustainedWindow {
  start_ms: number;
  requests: number;
  /** Wall-clock exchanges/sec in this window (client + node work). */
  rps: number;
  /** Node-side requests/sec in this window (timed stages only). */
  node_rps: number;
}

export interface SustainedResult {
  response_size_bytes: number;
  duration_ms: number;
  window_ms: number;
  windows: SustainedWindow[];
  total_requests: number;
  node_rps_mean: number;
  node_rps_early: number;
  node_rps_late: number;
  node_rps_min_window: number;
  node_rps_max_window: number;
  /** late / early node-side throughput. < 1 means the machine slowed down. */
  throttle_ratio: number;
  /** Process CPU time / wall time. Well below ~0.95 → steal or contention. */
  cpu_time_ratio: number;
  /** throttle_ratio at or above the floor — the machine sustains its burst. */
  steady: boolean;
}

export const STEADY_RATIO_FLOOR = 0.85;

export async function runSustained(opts: SustainedOptions = {}): Promise<SustainedResult> {
  const durationMs = opts.durationMs ?? 60_000;
  const windowMs = opts.windowMs ?? 5_000;
  const responseBytes = opts.responseBytes ?? 16_384;
  const warmupMs = opts.warmupMs ?? 500;

  const workload = createCompositeWorkload(responseBytes);
  await workload.sanity();

  const warmupEnd = hrtime.bigint() + BigInt(Math.round(warmupMs * 1e6));
  while (hrtime.bigint() < warmupEnd) {
    await workload.iterate();
  }
  Bun.gc(true);

  const windows: SustainedWindow[] = [];
  const windowNs = BigInt(Math.round(windowMs * 1e6));
  const cpuBefore = process.cpuUsage();
  const t0 = hrtime.bigint();
  const tEnd = t0 + BigInt(Math.round(durationMs * 1e6));

  let windowStart = t0;
  let windowRequests = 0;
  let windowNodeNsStart = workload.nodeNs();
  let totalRequests = 0;
  let now = t0;

  while (now < tEnd) {
    await workload.iterate();
    totalRequests += 1;
    windowRequests += 1;
    now = hrtime.bigint();

    if (now - windowStart >= windowNs) {
      const spanNs = Number(now - windowStart);
      const nodeNs = Number(workload.nodeNs() - windowNodeNsStart);
      windows.push({
        start_ms: Math.round(Number(windowStart - t0) / 1e6),
        requests: windowRequests,
        rps: round1((windowRequests * 1e9) / spanNs),
        node_rps: nodeNs > 0 ? round1((windowRequests * 1e9) / nodeNs) : 0,
      });
      windowStart = now;
      windowRequests = 0;
      windowNodeNsStart = workload.nodeNs();
    }
  }
  // A trailing partial window is dropped: its shorter span would read as noise
  // in the early/late comparison.

  const cpuAfter = process.cpuUsage(cpuBefore);
  const wallMs = Number(now - t0) / 1e6;
  const cpuMs = (cpuAfter.user + cpuAfter.system) / 1000;

  const nodeRates = windows.map((w) => w.node_rps);
  const early = meanOf(nodeRates.slice(0, 2));
  const late = meanOf(nodeRates.slice(-2));

  return {
    response_size_bytes: responseBytes,
    duration_ms: Math.round(wallMs),
    window_ms: windowMs,
    windows,
    total_requests: totalRequests,
    node_rps_mean: round1(meanOf(nodeRates)),
    node_rps_early: round1(early),
    node_rps_late: round1(late),
    node_rps_min_window: round1(Math.min(...nodeRates)),
    node_rps_max_window: round1(Math.max(...nodeRates)),
    throttle_ratio: early > 0 ? round3(late / early) : 0,
    cpu_time_ratio: wallMs > 0 ? round3(cpuMs / wallMs) : 0,
    steady: early > 0 && late / early >= STEADY_RATIO_FLOOR,
  };
}

function meanOf(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

const round1 = (v: number): number => Math.round(v * 10) / 10;
const round3 = (v: number): number => Math.round(v * 1000) / 1000;
