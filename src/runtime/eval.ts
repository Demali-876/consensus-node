import { capabilitiesRecord } from "./capabilities";
import { integrityPayload } from "../node/integrity";
import { runCpuHash, runCryptoAead, runEventLoop, runMemory, runSystem } from "./benchmarks/index";
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

function bytesToMb(value: number): number {
  return Math.round(value / 1024 / 1024);
}
