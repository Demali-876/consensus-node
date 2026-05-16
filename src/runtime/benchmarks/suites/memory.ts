import { bench, type BenchResult } from "../runner";

// Three sizes:
//   1MB  — fits in L2/L3 cache; tests cache bandwidth, not main memory
//   16MB — exceeds cache on most machines; closest to true RAM bandwidth
//   64MB — confirms sustained bandwidth at larger working sets
const SIZES_MB = [1, 16, 64];

export interface MemoryCopySubResult extends BenchResult {
  buffer_size_mb: number;
  bandwidth_bytes_per_second: number;
  bandwidth_gbps: number;
}

export interface MemoryResult {
  copy: MemoryCopySubResult[];
  // Headline: bandwidth at 16MB (real memory bandwidth, not cache).
  bandwidth_gbps: number;
  bytes_per_second: number;
  reliable: boolean;
}

/**
 * STREAM-style memory copy benchmark. Reports bandwidth in bytes/sec, accounting
 * for the fact that a copy reads `size` bytes AND writes `size` bytes — so the
 * memory subsystem moves `2 * size` bytes per operation.
 */
export async function runMemory(): Promise<MemoryResult> {
  const sub: MemoryCopySubResult[] = [];
  for (const mb of SIZES_MB) {
    const size = mb * 1024 * 1024;
    const a = Buffer.alloc(size);
    const b = Buffer.alloc(size);
    // Touch every page of `b` so it's resident before we start measuring.
    for (let i = 0; i < size; i += 4096) b[i] = i & 0xff;

    const result = await bench(
      () => {
        a.set(b);
        return 1;
      },
      { name: `mem-copy-${mb}MB`, measureMs: 500 },
    );
    const bandwidthBps = 2 * size * result.ops_per_second;
    sub.push({
      ...result,
      buffer_size_mb: mb,
      bandwidth_bytes_per_second: bandwidthBps,
      bandwidth_gbps: bandwidthBps / 1e9,
    });
  }
  const headline = sub.find((r) => r.buffer_size_mb === 16) ?? sub[0];
  return {
    copy: sub,
    bandwidth_gbps: headline.bandwidth_gbps,
    bytes_per_second: headline.bandwidth_bytes_per_second,
    reliable: sub.every((r) => r.reliable),
  };
}
