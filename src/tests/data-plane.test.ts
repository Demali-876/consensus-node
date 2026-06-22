import assert from "node:assert/strict";
import crypto from "node:crypto";
import Fastify from "fastify";
import websocket from "@fastify/websocket";

import {
  runDataRequest,
  serveDataConnection,
  type DataPlaneServeDeps,
  type MessageTransport,
  type ProxyResponsePayload,
} from "../tunnel/data-plane";
import { registerDataPlaneRoute } from "../runtime/data-route";
import { issueTicket } from "../tickets/ticket";
import { JtiReplayCache } from "../tickets/replay";
import { generateDedupeKey } from "../runtime/dedupe";
import { serveProxyRequest, type ProxyServeRequest, type SsrfCheck } from "../runtime/proxy-serve";
import type { SafeResolution } from "../runtime/ssrf";
import type { NodeIdentity } from "../crypto/identity";

// ---- fixtures -------------------------------------------------------------
function newIdentity(): NodeIdentity {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

const NODE_ID = "node-dp";
const KID = "orch-kid";
const orchestrator = crypto.generateKeyPairSync("ed25519");
const identity = newIdentity();
const NOW = Math.floor(Date.now() / 1000);

function mint(dedupeKey: string, jti: string): string {
  return issueTicket({ nodeId: NODE_ID, dedupeKey, jti, now: NOW, ttlSec: 300 }, orchestrator.privateKey, KID);
}

// Loopback is normally blocked; tests inject a permissive resolver so the serve
// path can reach a local upstream (same pattern as the server suite's noSsrf).
const allowLoopback: SsrfCheck = async (): Promise<SafeResolution> => ({
  ip: "127.0.0.1",
  family: 4,
  hostname: "127.0.0.1",
  isLiteral: true,
});
const permissiveServe = (req: ProxyServeRequest) => serveProxyRequest(req, { ssrfCheck: allowLoopback });

// In-memory ordered message pipe (no socket).
function endpoint(
  inbox: Buffer[],
  inWaiters: Array<(b: Buffer) => void>,
  outbox: Buffer[],
  outWaiters: Array<(b: Buffer) => void>,
): MessageTransport {
  return {
    recv: () => {
      const m = inbox.shift();
      return m ? Promise.resolve(m) : new Promise<Buffer>((res) => inWaiters.push(res));
    },
    send: (d: Buffer) => {
      const w = outWaiters.shift();
      if (w) w(d);
      else outbox.push(d);
    },
    close: () => {},
  };
}
function memoryPipe(): { client: MessageTransport; server: MessageTransport } {
  const toServer: Buffer[] = [];
  const toClient: Buffer[] = [];
  const serverWaiters: Array<(b: Buffer) => void> = [];
  const clientWaiters: Array<(b: Buffer) => void> = [];
  return {
    client: endpoint(toClient, clientWaiters, toServer, serverWaiters),
    server: endpoint(toServer, serverWaiters, toClient, clientWaiters),
  };
}

// ---- local upstream -------------------------------------------------------
const upstream = Bun.serve({
  port: 0,
  async fetch(req) {
    const body = await req.text();
    return new Response(`echo:${req.method}:${body}`, { status: 200, headers: { "content-type": "text/plain" } });
  },
});
const upstreamUrl = `http://127.0.0.1:${upstream.port}/echo`;

let checks = 0;

try {
  const baseDeps = (replay: JtiReplayCache, serve = permissiveServe): DataPlaneServeDeps => ({
    nodeId: NODE_ID,
    identity,
    pinnedKey: orchestrator.publicKey,
    replay,
    serve,
  });
  const clientParams = (token: string, request: ProxyServeRequest) => ({
    nodeId: NODE_ID,
    expectedNodePublicKeyPem: identity.publicKeyPem,
    token,
    request,
  });

  const echoRequest: ProxyServeRequest = {
    target_url: upstreamUrl,
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: "hi",
  };
  const echoDedupe = generateDedupeKey({
    target_url: upstreamUrl,
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: Buffer.from("hi"),
  });

  // 1) Happy path end-to-end (in-memory): handshake -> ticket -> serve -> response.
  {
    const { client, server } = memoryPipe();
    const [, resp] = await Promise.all([
      serveDataConnection(server, baseDeps(new JtiReplayCache())),
      runDataRequest(client, clientParams(mint(echoDedupe, "j-happy"), echoRequest)),
    ]);
    assert.equal(resp.type, "proxy_response");
    const ok = resp as Extract<ProxyResponsePayload, { type: "proxy_response" }>;
    assert.equal(ok.status, 200);
    assert.equal(Buffer.from(ok.body, "base64").toString(), "echo:POST:hi");
    checks += 3;
  }

  // 2) Ticket bound to a different request -> unauthorized (request binding).
  {
    const { client, server } = memoryPipe();
    const wrongToken = mint(generateDedupeKey({ target_url: "https://elsewhere.test/", method: "GET" }), "j-wrong");
    const [, resp] = await Promise.all([
      serveDataConnection(server, baseDeps(new JtiReplayCache())),
      runDataRequest(client, clientParams(wrongToken, echoRequest)),
    ]);
    assert.equal(resp.type, "error");
    assert.equal((resp as { code: string }).code, "unauthorized");
    checks += 2;
  }

  // 3) Valid ticket but SSRF-blocked target -> upstream_error (default real guard).
  {
    const { client, server } = memoryPipe();
    const blocked: ProxyServeRequest = { target_url: "http://127.0.0.1/", method: "GET" };
    const token = mint(generateDedupeKey({ target_url: "http://127.0.0.1/", method: "GET" }), "j-ssrf");
    const deps: DataPlaneServeDeps = {
      nodeId: NODE_ID,
      identity,
      pinnedKey: orchestrator.publicKey,
      replay: new JtiReplayCache(),
    }; // no serve override -> real SSRF guard
    const [, resp] = await Promise.all([
      serveDataConnection(server, deps),
      runDataRequest(client, clientParams(token, blocked)),
    ]);
    assert.equal(resp.type, "error");
    assert.equal((resp as { code: string }).code, "upstream_error");
    assert.match((resp as { message: string }).message, /Forbidden|private/i);
    checks += 3;
  }

  // 4) Replay: the same ticket spent twice across connections (shared cache).
  {
    const replay = new JtiReplayCache();
    const token = mint(echoDedupe, "j-replay");
    const p1 = memoryPipe();
    const [, r1] = await Promise.all([
      serveDataConnection(p1.server, baseDeps(replay)),
      runDataRequest(p1.client, clientParams(token, echoRequest)),
    ]);
    assert.equal(r1.type, "proxy_response");
    const p2 = memoryPipe();
    const [, r2] = await Promise.all([
      serveDataConnection(p2.server, baseDeps(replay)),
      runDataRequest(p2.client, clientParams(token, echoRequest)),
    ]);
    assert.equal(r2.type, "error");
    assert.match((r2 as { message: string }).message, /replay/i);
    checks += 3;
  }

  // 5) Live WebSocket round-trip through the actual Fastify route.
  {
    const app = Fastify();
    await app.register(websocket);
    registerDataPlaneRoute(app, {
      resolve: async () => ({ nodeId: NODE_ID, identity, pinnedKey: orchestrator.publicKey }),
      serve: permissiveServe,
    });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const port = (app.server.address() as { port: number }).port;
    try {
      const ws = await connectWs(`ws://127.0.0.1:${port}/connect`);
      try {
        const resp = await runDataRequest(
          wsClientTransport(ws),
          clientParams(mint(echoDedupe, "j-live"), echoRequest),
        );
        assert.equal(resp.type, "proxy_response");
        const ok = resp as Extract<ProxyResponsePayload, { type: "proxy_response" }>;
        assert.equal(ok.status, 200);
        assert.equal(Buffer.from(ok.body, "base64").toString(), "echo:POST:hi");
        checks += 3;
      } finally {
        ws.close();
      }
    } finally {
      // Drop the lingering WS connection so Fastify's close() doesn't hang.
      (app.server as { closeAllConnections?: () => void }).closeAllConnections?.();
      await app.close();
    }
  }
} finally {
  upstream.stop(true);
}

console.log(`data-plane.test.ts: ${checks} checks passed — direct client<->node request: handshake, ticket gate, SSRF serve, replay, live WS`);

// ---- WHATWG WebSocket client transport (for the live test) ----------------
function wsClientTransport(ws: WebSocket): MessageTransport {
  ws.binaryType = "arraybuffer";
  const inbox: Buffer[] = [];
  const waiters: Array<{ resolve: (b: Buffer) => void; reject: (e: Error) => void }> = [];
  let failure: Error | null = null;
  ws.addEventListener("message", (ev: MessageEvent) => {
    const buf = typeof ev.data === "string" ? Buffer.from(ev.data) : Buffer.from(ev.data as ArrayBuffer);
    const w = waiters.shift();
    if (w) w.resolve(buf);
    else inbox.push(buf);
  });
  const fail = (e: Error) => {
    failure = e;
    while (waiters.length) waiters.shift()!.reject(e);
  };
  ws.addEventListener("close", (ev: CloseEvent) => fail(new Error(`ws closed ${ev.code}`)));
  ws.addEventListener("error", () => fail(new Error("ws error")));
  return {
    recv: () => {
      const m = inbox.shift();
      if (m) return Promise.resolve(m);
      if (failure) return Promise.reject(failure);
      return new Promise<Buffer>((resolve, reject) => waiters.push({ resolve, reject }));
    },
    send: (d: Buffer) => ws.send(d),
    close: (code?: number) => ws.close(code),
  };
}

function connectWs(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", () => reject(new Error("ws connect failed")));
  });
}
