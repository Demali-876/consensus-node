import os from "node:os";
import crypto from "node:crypto";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { capabilitiesRecord } from "./capabilities";
import { integrityPayload } from "../node/integrity";
import type { EvalAction } from "../tunnel/messages";

export async function runEvalAction(action: EvalAction, params: Record<string, unknown> = {}): Promise<unknown> {
  if (action === "capabilities") return capabilitiesRecord();
  if (action === "integrity") return integrityPayload();
  if (action === "benchmark_system") return systemBenchmark();
  if (action === "benchmark_cpu") return cpuBenchmark(params);
  if (action === "benchmark_crypto") return cryptoBenchmark(params);
  if (action === "benchmark_memory_pressure") return memoryPressureBenchmark(params);
  throw new Error(`Unsupported eval action: ${action}`);
}

function systemBenchmark() {
  return {
    success: true,
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    total_memory_bytes: os.totalmem(),
    free_memory_bytes: os.freemem(),
    uptime_seconds: os.uptime(),
    bun_version: Bun.version,
  };
}

function cpuBenchmark(params: Record<string, unknown>) {
  const iterations = integerParam(params.iterations, 5_000, 1, 200_000);
  const data = typeof params.data === "string" && params.data.length > 0
    ? params.data
    : "consensus-node-eval";

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    crypto.createHash("sha256").update(data).digest("hex");
  }
  const durationMs = performance.now() - start;

  return {
    success: true,
    iterations,
    duration_ms: Math.round(durationMs),
    hashes_per_second: Math.round((iterations / Math.max(durationMs, 1)) * 1000),
  };
}

function cryptoBenchmark(params: Record<string, unknown>) {
  const iterations = integerParam(params.iterations, 500, 10, 25_000);
  const payloadSizeKb = integerParam(params.payload_size_kb, 16, 1, 1024);
  const payload = crypto.randomBytes(payloadSizeKb * 1024);
  const aad = Buffer.from("consensus-node-eval-v1");
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
      throw new Error("ChaCha20-Poly1305 eval verification failed");
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
    total_bytes_per_second: Math.round((totalBytes / Math.max(durationMs, 1)) * 1000),
  };
}

async function memoryPressureBenchmark(params: Record<string, unknown>) {
  const requestedMb = integerParam(params.test_size_mb, 128, 16, 1024);
  const rounds = integerParam(params.rounds, 2, 1, 10);
  const rssBefore = process.memoryUsage().rss;
  const start = performance.now();
  let peakRss = rssBefore;

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
    rss_retained_mb: bytesToMb(Math.max(0, rssAfter - rssBefore)),
  };
}

function integerParam(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function bytesToMb(value: number): number {
  return Math.round(value / 1024 / 1024);
}
