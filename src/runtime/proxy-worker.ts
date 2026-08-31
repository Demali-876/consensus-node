import type { FastifyInstance } from "fastify";
import { serveProxyRequest } from "./proxy-serve";
import type { ProxyExecutionProfileV1 } from "./profile-v1";

export async function registerProxyRoutes(app: FastifyInstance): Promise<void> {
  app.post("/proxy", async (request, reply) => {
    const body = request.body as {
      target_url?: string;
      method?: string;
      headers?: Record<string, string>;
      body?: unknown;
      profile?: ProxyExecutionProfileV1;
    };

    if (!body?.target_url) return reply.code(400).send({ error: "Missing target_url" });

    const method = (body.method || "GET").toUpperCase();
    const start = performance.now();
    const response = await serveProxyRequest({
      target_url: body.target_url,
      method,
      headers: body.headers,
      body: method === "GET" || method === "HEAD"
        ? undefined
        : typeof body.body === "string"
          ? body.body
          : JSON.stringify(body.body ?? null),
      profile: body.profile,
    });
    const responseText = response.body.toString("utf8");

    return reply.code(response.status).send({
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
      data: responseText,
      meta: {
        processing_ms: Math.round(performance.now() - start),
        timestamp: new Date().toISOString(),
        cached: response.cached,
        profile_hash: response.profile_hash,
      }
    });
  });
}
