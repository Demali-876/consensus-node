import os from "node:os";
import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

const ALLOWED_BENCHMARK_TARGETS = new Set([
  "https://httpbin.org/json",
  "https://api.github.com/zen",
  "https://jsonplaceholder.typicode.com/posts/1",
]);

export async function registerBenchmarkRoutes(app: FastifyInstance): Promise<void> {
  app.post("/benchmark/fetch", async (request, reply) => {
    const body = request.body as { target_url?: string };
    if (!body?.target_url) return reply.code(400).send({ error: "Missing target_url" });
    if (!ALLOWED_BENCHMARK_TARGETS.has(body.target_url)) {
      return reply.code(400).send({ error: "Unsupported benchmark target" });
    }

    const start = performance.now();
    const response = await fetch(body.target_url, { signal: AbortSignal.timeout(5000) });
    await response.arrayBuffer();

    return {
      success: true,
      status: response.status,
      duration_ms: Math.round(performance.now() - start)
    };
  });

  app.post("/benchmark/cpu", async (request, reply) => {
    const body = request.body as { iterations?: number; data?: string };
    if (!body?.iterations || !body?.data) return reply.code(400).send({ error: "Missing iterations or data" });

    const start = performance.now();
    for (let i = 0; i < body.iterations; i++) {
      crypto.createHash("sha256").update(body.data).digest("hex");
    }
    const durationMs = performance.now() - start;

    return {
      success: true,
      iterations: body.iterations,
      duration_ms: Math.round(durationMs),
      hashes_per_second: Math.round((body.iterations / Math.max(durationMs, 1)) * 1000)
    };
  });

  app.post("/benchmark/crypto", async (request) => {
    const body = request.body as { iterations?: number; payload_size_kb?: number };
    const iterations = integerParam(body?.iterations, 1_000, 10, 25_000);
    const payloadSizeKb = integerParam(body?.payload_size_kb, 16, 1, 1024);
    const payload = crypto.randomBytes(payloadSizeKb * 1024);
    const aad = Buffer.from("consensus-node-benchmark-v1");
    const key = crypto.randomBytes(32);
    const nonce = Buffer.alloc(12);
    let encryptedBytes = 0;
    let decryptedBytes = 0;

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      nonce.writeUInt32BE(i, 8);
      const sealed = Buffer.from(chacha20poly1305(key, nonce, aad).encrypt(payload));
      const opened = Buffer.from(chacha20poly1305(key, nonce, aad).decrypt(sealed));
      if (opened.length !== payload.length || opened[0] !== payload[0]) {
        throw new Error("ChaCha20-Poly1305 benchmark verification failed");
      }
      encryptedBytes += payload.length;
      decryptedBytes += opened.length;
    }
    const durationMs = performance.now() - start;
    const totalBytes = encryptedBytes + decryptedBytes;

    return {
      success: true,
      algorithm: "chacha20-poly1305",
      iterations,
      payload_size_kb: payloadSizeKb,
      duration_ms: Math.round(durationMs),
      encrypted_bytes_per_second: Math.round((encryptedBytes / Math.max(durationMs, 1)) * 1000),
      decrypted_bytes_per_second: Math.round((decryptedBytes / Math.max(durationMs, 1)) * 1000),
      total_bytes_per_second: Math.round((totalBytes / Math.max(durationMs, 1)) * 1000)
    };
  });

  app.post("/benchmark/concurrency", async (request) => {
    const body = request.body as { target_urls?: string[]; requests?: number; concurrency?: number };
    const requestedTargets = Array.isArray(body?.target_urls) && body.target_urls.length > 0
      ? body.target_urls.slice(0, 10)
      : ["https://httpbin.org/json"];
    const targetUrls = requestedTargets.filter((target) => ALLOWED_BENCHMARK_TARGETS.has(target));
    if (targetUrls.length === 0) {
      return {
        success: false,
        error: "No supported benchmark targets provided",
        requests: 0,
        concurrency: 0,
        successful: 0,
        failed: 0,
        success_rate: 0,
        duration_ms: 0,
        avg_latency_ms: 0,
        p95_latency_ms: 0,
        requests_per_second: 0
      };
    }
    const requests = integerParam(body?.requests, 24, 1, 200);
    const concurrency = integerParam(body?.concurrency, 6, 1, 50);
    const latencies: number[] = [];
    let successful = 0;
    let next = 0;

    async function worker(): Promise<void> {
      while (next < requests) {
        const index = next++;
        const targetUrl = targetUrls[index % targetUrls.length];
        const start = performance.now();
        try {
          const response = await fetch(targetUrl, { signal: AbortSignal.timeout(7000) });
          await response.arrayBuffer();
          if (response.ok) successful++;
        } catch {
          // The failed request is counted through the success rate.
        } finally {
          latencies.push(performance.now() - start);
        }
      }
    }

    const start = performance.now();
    await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, () => worker()));
    const durationMs = performance.now() - start;
    const sorted = latencies.sort((a, b) => a - b);

    return {
      success: successful === requests,
      requests,
      concurrency,
      successful,
      failed: requests - successful,
      success_rate: successful / requests,
      duration_ms: Math.round(durationMs),
      avg_latency_ms: Math.round(average(sorted)),
      p95_latency_ms: Math.round(percentile(sorted, 0.95)),
      requests_per_second: Number((successful / Math.max(durationMs / 1000, 0.001)).toFixed(2))
    };
  });

  app.post("/benchmark/memory-test", async (request, reply) => {
    const body = request.body as { test_size_mb?: number };
    const requestedMb = integerParam(body?.test_size_mb, 128, 16, 512);
    const start = performance.now();

    try {
      const chunks: Buffer[] = [];
      for (let i = 0; i < requestedMb; i += 1) {
        const chunk = Buffer.alloc(1024 * 1024);
        chunk[0] = i % 255;
        chunks.push(chunk);
      }
      const allocatedMb = chunks.length;
      chunks.length = 0;

      return {
        success: true,
        requested_mb: requestedMb,
        allocated_mb: allocatedMb,
        duration_ms: Math.round(performance.now() - start)
      };
    } catch (error) {
      return reply.code(500).send({
        success: false,
        requested_mb: requestedMb,
        allocated_mb: 0,
        duration_ms: Math.round(performance.now() - start),
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });

  app.post("/benchmark/memory-pressure", async (request, reply) => {
    const body = request.body as { test_size_mb?: number; rounds?: number };
    const requestedMb = integerParam(body?.test_size_mb, 256, 16, 1024);
    const rounds = integerParam(body?.rounds, 3, 1, 10);
    const rssBefore = process.memoryUsage().rss;
    const start = performance.now();
    let peakRss = rssBefore;

    try {
      for (let round = 0; round < rounds; round++) {
        const chunks: Buffer[] = [];
        for (let i = 0; i < requestedMb; i += 1) {
          const chunk = Buffer.alloc(1024 * 1024);
          for (let offset = 0; offset < chunk.length; offset += 4096) {
            chunk[offset] = (round + i + offset) % 255;
          }
          chunks.push(chunk);
        }
        peakRss = Math.max(peakRss, process.memoryUsage().rss);
        chunks.length = 0;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
      const rssAfter = process.memoryUsage().rss;

      return {
        success: true,
        requested_mb: requestedMb,
        rounds,
        allocated_mb: requestedMb * rounds,
        duration_ms: Math.round(performance.now() - start),
        rss_before_mb: bytesToMb(rssBefore),
        rss_peak_mb: bytesToMb(peakRss),
        rss_after_mb: bytesToMb(rssAfter),
        rss_retained_mb: bytesToMb(Math.max(0, rssAfter - rssBefore))
      };
    } catch (error) {
      return reply.code(500).send({
        success: false,
        requested_mb: requestedMb,
        rounds,
        allocated_mb: 0,
        duration_ms: Math.round(performance.now() - start),
        rss_before_mb: bytesToMb(rssBefore),
        rss_peak_mb: bytesToMb(peakRss),
        rss_after_mb: bytesToMb(process.memoryUsage().rss),
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });

  app.get("/benchmark/system", async () => ({
    success: true,
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    total_memory_bytes: os.totalmem(),
    free_memory_bytes: os.freemem(),
    uptime_seconds: os.uptime(),
    bun_version: Bun.version
  }));
}

export function integerParam(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== "number" && typeof value !== "string") return fallback;
  if (typeof value === "string" && value.trim() === "") return fallback;
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function average(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function percentile(sortedValues: number[], p: number): number {
  if (sortedValues.length === 0) return 0;
  const index = Math.max(0, Math.min(sortedValues.length - 1, Math.ceil(sortedValues.length * p) - 1));
  return sortedValues[index] ?? 0;
}

function bytesToMb(value: number): number {
  return Math.round(value / 1024 / 1024);
}
