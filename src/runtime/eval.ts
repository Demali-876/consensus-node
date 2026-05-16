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
  throw new Error(`Unsupported eval action: ${action satisfies never}`);
}
