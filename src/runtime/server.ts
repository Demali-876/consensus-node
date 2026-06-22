import Fastify from "fastify";
import websocket from "@fastify/websocket";
import { loadConfig } from "../node/state";
import { releaseManifest } from "../node/manifest";
import { integrityPayload } from "../node/integrity";
import { capabilitiesRecord } from "./capabilities";
import { registerBenchmarkRoutes } from "./benchmarks/routes";
import { registerProxyRoutes } from "./proxy-worker";
import { registerDataPlaneRoute } from "./data-route";
import { loadOrCreateIdentity } from "../crypto/identity";
import { loadPinnedOrchestratorKey } from "../tickets/orchestrator-key";

export async function buildServer() {
  const app = Fastify({ logger: true });
  await app.register(websocket);

  app.get("/health", async () => {
    const config = await loadConfig();
    return {
      status: "healthy",
      registered: Boolean(config.node_id),
      node_id: config.node_id ?? null,
      domain: config.domain ?? null,
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    };
  });

  app.get("/node/version", async () => ({
    product: "consensus-node",
    version: releaseManifest().version,
    runtime: "bun",
    bun_version: Bun.version
  }));

  app.get("/node/manifest", async () => releaseManifest());
  app.get("/node/integrity", async () => integrityPayload());
  app.get("/node/capabilities", async () => capabilitiesRecord());

  await registerBenchmarkRoutes(app);
  await registerProxyRoutes(app);

  // Client-facing data plane: encrypted, node-authenticated, ticket-gated proxy.
  registerDataPlaneRoute(app, {
    resolve: async () => {
      const config = await loadConfig();
      if (!config.node_id) throw new Error("node is not registered");
      const pinned = await loadPinnedOrchestratorKey();
      if (!pinned) throw new Error("no pinned orchestrator key");
      const identity = await loadOrCreateIdentity();
      return { nodeId: config.node_id, identity, pinnedKey: pinned.key };
    },
  });

  return app;
}
