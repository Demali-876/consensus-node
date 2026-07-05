import { capabilitiesRecord } from "./capabilities";
import { integrityPayload } from "../node/integrity";
import { runCpuHash, runCryptoAead, runEventLoop, runMemory, runSystem } from "./benchmarks/index";
import { runCompositeRequest } from "./benchmarks/suites/composite-request";
import { runSustained } from "./benchmarks/suites/sustained";
import { runMultiCore } from "./benchmarks/suites/multi-core";
import { runSpeedtestFetch, runTunnelEcho } from "./network-eval";
import type { EvalAction } from "../tunnel/messages";

// `_params` is reserved for future per-action tuning; the auto-tuning runner does
// not require it today, but keeping it on the signature preserves the wire shape.
export async function runEvalAction(action: EvalAction, _params: Record<string, unknown> = {}): Promise<unknown> {
  if (action === "capabilities") return capabilitiesRecord();
  if (action === "integrity") return integrityPayload();
  if (action === "benchmark_system") return runSystem();
  if (action === "benchmark_cpu") return runCpuHash();
  if (action === "benchmark_crypto") return runCryptoAead();
  if (action === "benchmark_memory") return runMemory();
  if (action === "benchmark_event_loop") return runEventLoop();
  if (action === "benchmark_memory_pressure") return runLegacyMemoryPressure(_params);
  // Admission suites. The server drives these and gates on their results; params
  // let it tune the sustained window (see evalActionTimeout on the server). All
  // three run node-side-timed via the real production pipeline — see the suites.
  if (action === "benchmark_composite") {
    return runCompositeRequest(_params.quick ? { warmupMs: 50, measureMs: 300 } : {});
  }
  if (action === "benchmark_sustained") {
    return runSustained({
      durationMs: positiveNumber(_params.duration_ms),
      windowMs: positiveNumber(_params.window_ms),
    });
  }
  if (action === "benchmark_multicore") {
    return runMultiCore({ durationMs: positiveNumber(_params.duration_ms) });
  }
  if (action === "tunnel_echo") return runTunnelEcho(_params);
  if (action === "speedtest_fetch") return runSpeedtestFetch(_params);
  throw new Error(`Unsupported eval action: ${action satisfies never}`);
}

async function runLegacyMemoryPressure(params: Record<string, unknown>): Promise<unknown> {
  const requestedMb = clampInt(params.test_size_mb, 128, 1, 512);
  const rounds = clampInt(params.rounds, 2, 1, 8);
  const buffers: Buffer[] = [];
  const rssBefore = process.memoryUsage().rss;
  let rssPeak = rssBefore;
  const startedAt = Date.now();

  for (let round = 0; round < rounds; round++) {
    const buffer = Buffer.alloc(requestedMb * 1024 * 1024, round & 0xff);
    buffers.push(buffer);
    rssPeak = Math.max(rssPeak, process.memoryUsage().rss);
    await new Promise<void>((resolve) => setImmediate(resolve));
  }

  const rssAfter = process.memoryUsage().rss;
  return {
    success: true,
    requested_mb: requestedMb,
    rounds,
    allocated_mb: requestedMb * rounds,
    duration_ms: Date.now() - startedAt,
    rss_before_mb: bytesToMb(rssBefore),
    rss_peak_mb: bytesToMb(rssPeak),
    rss_after_mb: bytesToMb(rssAfter),
    rss_retained_mb: bytesToMb(Math.max(0, rssAfter - rssBefore)),
  };
}

function clampInt(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

// Server-supplied duration/window overrides for the admission suites. Returns
// undefined for absent/invalid input so the suite falls back to its own default.
function positiveNumber(value: unknown): number | undefined {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function bytesToMb(value: number): number {
  return Math.round(value / 1024 / 1024);
}
