// Fastify WebSocket route for the client-facing data plane. Adapts a @fastify/
// websocket connection to the transport-agnostic serveDataConnection protocol
// (tunnel/data-plane.ts). Per-process state (the jti replay cache) lives here so
// it is shared across connections; node identity / pinned key are resolved per
// connection so a node that registers (or rotates its pin) later works without a
// restart.

import type { FastifyInstance } from "fastify";
import type { KeyObject } from "node:crypto";

import { JtiReplayCache } from "../tickets/replay";
import {
  DATA_PLANE_PATH,
  serveDataConnection,
  type MessageTransport,
} from "../tunnel/data-plane";
import type { ProxyResult, ProxyServeRequest } from "./proxy-serve";
import type { NodeIdentity } from "../crypto/identity";
import { log } from "../log";

// Structural view of the @fastify/websocket socket — only what this adapter uses,
// so we don't depend on `ws` type declarations being resolvable.
type RawWsData = Buffer | ArrayBuffer | Buffer[];
interface WsSocket {
  on(event: "message", listener: (data: RawWsData) => void): void;
  on(event: "close", listener: () => void): void;
  on(event: "error", listener: (err: Error) => void): void;
  send(data: Buffer): void;
  close(code?: number): void;
}

export interface DataPlaneRouteOptions {
  /** Per-connection lookup of node identity + the pinned orchestrator key.
   *  Throws if the node is not yet provisioned (the connection is then closed). */
  resolve: () => Promise<{ nodeId: string; identity: NodeIdentity; pinnedKey: KeyObject }>;
  serve?: (req: ProxyServeRequest) => Promise<ProxyResult>;
  replay?: JtiReplayCache;
  path?: string;
}

export function registerDataPlaneRoute(app: FastifyInstance, opts: DataPlaneRouteOptions): void {
  const replay = opts.replay ?? new JtiReplayCache(); // shared across all connections
  app.get(opts.path ?? DATA_PLANE_PATH, { websocket: true }, (socket: WsSocket) => {
    const transport = wsServerTransport(socket);
    void (async () => {
      try {
        const base = await opts.resolve();
        await serveDataConnection(transport, { ...base, replay, serve: opts.serve });
      } catch (err) {
        log.warn("data-plane", "connection_failed", {
          error: err instanceof Error ? err.message : String(err),
        });
        transport.close(1011);
      }
    })();
  });
}

function wsServerTransport(socket: WsSocket): MessageTransport {
  const inbox: Buffer[] = [];
  const waiters: Array<{ resolve: (b: Buffer) => void; reject: (e: Error) => void }> = [];
  let failure: Error | null = null;

  socket.on("message", (data: RawWsData) => {
    const buf = toBuffer(data);
    const waiter = waiters.shift();
    if (waiter) waiter.resolve(buf);
    else inbox.push(buf);
  });
  const fail = (err: Error): void => {
    failure = err;
    while (waiters.length) waiters.shift()!.reject(err);
  };
  socket.on("close", () => fail(new Error("connection closed")));
  socket.on("error", (err: Error) => fail(err));

  return {
    recv() {
      const buffered = inbox.shift();
      if (buffered) return Promise.resolve(buffered);
      if (failure) return Promise.reject(failure);
      return new Promise<Buffer>((resolve, reject) => waiters.push({ resolve, reject }));
    },
    send(data: Buffer) {
      socket.send(data);
    },
    close(code?: number) {
      try {
        socket.close(code);
      } catch {
        /* already closing */
      }
    },
  };
}

function toBuffer(data: RawWsData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data);
}
