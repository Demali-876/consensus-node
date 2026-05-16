import crypto from "node:crypto";
import { bench, type BenchResult } from "../runner";

// Three sizes that bracket the realistic range a proxy/tunnel node hashes:
// small control frames, typical request bodies, and chunked payloads.
const PAYLOAD_SIZES_BYTES = [64, 1024, 16384];

// Inner loop counts tuned so each sample takes ~5–10ms across our range. Closure
// overhead is amortized across the inner loop; the runner only sees the outer call.
const INNER_OPS_BY_SIZE: Record<number, number> = {
  64: 5000,
  1024: 1000,
  16384: 100,
};

export interface CpuHashSubResult extends BenchResult {
  payload_size_bytes: number;
  bytes_per_second: number;
}

export interface CpuHashResult {
  algorithm: "sha256";
  results: CpuHashSubResult[];
  // Headline metric: bytes/sec at 1KB — representative of typical tunnel frames.
  bytes_per_second: number;
  reliable: boolean;
}

export async function runCpuHash(): Promise<CpuHashResult> {
  const sub: CpuHashSubResult[] = [];
  for (const sz of PAYLOAD_SIZES_BYTES) {
    const payload = crypto.randomBytes(sz);
    const inner = INNER_OPS_BY_SIZE[sz] ?? 100;
    const result = await bench(
      () => {
        for (let i = 0; i < inner; i++) {
          crypto.createHash("sha256").update(payload).digest();
        }
        return inner;
      },
      { name: `sha256-${sz}B` },
    );
    sub.push({
      ...result,
      payload_size_bytes: sz,
      bytes_per_second: sz * result.ops_per_second,
    });
  }
  const headline = sub.find((r) => r.payload_size_bytes === 1024) ?? sub[0];
  return {
    algorithm: "sha256",
    results: sub,
    bytes_per_second: headline.bytes_per_second,
    reliable: sub.every((r) => r.reliable),
  };
}
