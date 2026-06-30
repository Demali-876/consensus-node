import { buildServer } from "./runtime/server";

async function main(): Promise<void> {
  const port = Number(process.env.NODE_PORT || 9090);
  // Bind loopback-only by default. The client-facing data plane no longer needs
  // an inbound listener: the orchestrator node-gateway bridges a client's
  // wss://<node>.consensus.canister.software/connect onto the node's outbound
  // control tunnel (see src/clients/data-plane-stream.ts), so this Fastify server
  // only serves local operator endpoints (/health, /node/*). A node that CAN
  // expose a port (a future "direct mode") opts in with NODE_HOST=:: (or 0.0.0.0)
  // and fronts it with its own TLS — exposure is never required.
  const host = process.env.NODE_HOST || "127.0.0.1";
  const app = await buildServer();

  await app.listen({ port, host });
}

main().catch((error) => {
  console.error("Fatal:", error);
  process.exit(1);
});
