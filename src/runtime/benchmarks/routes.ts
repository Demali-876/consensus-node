import type { FastifyInstance } from "fastify";
import { runCpuHash, runCryptoAead, runEventLoop, runMemory, runSystem } from "./index";

/**
 * HTTP routes are thin wrappers around the same suite functions used by the
 * encrypted eval tunnel — single source of truth, no duplication.
 *
 * These endpoints exist for manual testing and operational visibility. The
 * authoritative join-time evaluation runs over the eval tunnel via
 * `runtime/eval.ts`; the HTTP routes mirror it.
 */
export async function registerBenchmarkRoutes(app: FastifyInstance): Promise<void> {
  app.get("/benchmark/system", async () => runSystem());
  app.post("/benchmark/cpu", async () => runCpuHash());
  app.post("/benchmark/crypto", async () => runCryptoAead());
  app.post("/benchmark/memory", async () => runMemory());
  app.post("/benchmark/event-loop", async () => runEventLoop());
  app.post("/benchmark/all", async () => ({
    system: runSystem(),
    cpu: await runCpuHash(),
    crypto: await runCryptoAead(),
    memory: await runMemory(),
    event_loop: await runEventLoop(),
  }));
}
