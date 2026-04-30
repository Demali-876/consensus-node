import os from "node:os";
import crypto from "node:crypto";
import type { FastifyInstance } from "fastify";

export async function registerBenchmarkRoutes(app: FastifyInstance): Promise<void> {
  app.post("/benchmark/fetch", async (request, reply) => {
    const body = request.body as { target_url?: string };
    if (!body?.target_url) return reply.code(400).send({ error: "Missing target_url" });

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

function integerParam(value: unknown, fallback: number, min: number, max: number): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}
