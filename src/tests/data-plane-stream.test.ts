import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  runDataRequest,
  type MessageTransport,
  type ProxyResponsePayload,
} from "../tunnel/data-plane";
import { startDataPlaneStream } from "../clients/data-plane-stream";
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

const NODE_ID = "node-dp-stream";
const KID = "orch-kid";
const orchestrator = crypto.generateKeyPairSync("ed25519");
const identity = newIdentity();
const NOW = Math.floor(Date.now() / 1000);

function mint(dedupeKey: string, jti: string): string {
  return issueTicket({ nodeId: NODE_ID, dedupeKey, jti, now: NOW, ttlSec: 300 }, orchestrator.privateKey, KID);
}

// Loopback is normally blocked; inject a permissive resolver so serve can reach
// the local upstream (same pattern as data-plane.test.ts / the server suite).
const allowLoopback: SsrfCheck = async (): Promise<SafeResolution> => ({
  ip: "127.0.0.1",
  family: 4,
  hostname: "127.0.0.1",
  isLiteral: true,
});
const permissiveServe = (req: ProxyServeRequest) => serveProxyRequest(req, { ssrfCheck: allowLoopback });

// A control-tunnel stream simulated as an ordered byte channel. The node's
// outbound STREAM_DATA (sendData) is delivered to the client's recv(); the
// client's send() is delivered to the node via stream.push() — exactly how the
// orchestrator gateway bridges the two sides over the tunnel.
function tunnelStreamHarness(opts: {
  resolveDeps: Parameters<typeof startDataPlaneStream>[0]["resolveDeps"];
}): {
  client: MessageTransport;
  closeReason: () => string | null;
  errored: () => Error | null;
  done: Promise<void>;
} {
  const toClient: Buffer[] = [];
  const clientWaiters: Array<(b: Buffer) => void> = [];
  let closeReason: string | null = null;
  let errored: Error | null = null;
  let resolveDone!: () => void;
  const done = new Promise<void>((resolve) => (resolveDone = resolve));

  const stream = startDataPlaneStream({
    resolveDeps: opts.resolveDeps,
    sendData: (data) => {
      const waiter = clientWaiters.shift();
      if (waiter) waiter(data);
      else toClient.push(data);
    },
    sendClose: (reason) => {
      closeReason = reason;
    },
    onError: (error) => {
      errored = error;
    },
    onDone: () => resolveDone(),
  });

  const client: MessageTransport = {
    recv: () => {
      const buffered = toClient.shift();
      return buffered ? Promise.resolve(buffered) : new Promise<Buffer>((res) => clientWaiters.push(res));
    },
    send: (data: Buffer) => {
      stream.push(data);
    },
    close: () => {},
  };

  return { client, closeReason: () => closeReason, errored: () => errored, done };
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

  // 1) Happy path: a ticketed request served over the simulated tunnel stream,
  //    then the node finishes the stream with a single STREAM_CLOSE.
  {
    const h = tunnelStreamHarness({
      resolveDeps: async () => ({
        nodeId: NODE_ID,
        identity,
        pinnedKey: orchestrator.publicKey,
        replay: new JtiReplayCache(),
        serve: permissiveServe,
      }),
    });
    const resp = await runDataRequest(h.client, {
      nodeId: NODE_ID,
      expectedNodePublicKeyPem: identity.publicKeyPem,
      token: mint(echoDedupe, "j-stream-happy"),
      request: echoRequest,
    });
    await h.done;
    assert.equal(resp.type, "proxy_response");
    const ok = resp as Extract<ProxyResponsePayload, { type: "proxy_response" }>;
    assert.equal(ok.status, 200);
    assert.equal(Buffer.from(ok.body, "base64").toString(), "echo:POST:hi");
    assert.equal(h.closeReason(), "data-plane complete");
    assert.equal(h.errored(), null);
    checks += 5;
  }

  // 2) A ticket bound to a different request is rejected in-band (request
  //    binding) — the adapter faithfully surfaces serveDataConnection's error
  //    response rather than throwing.
  {
    const h = tunnelStreamHarness({
      resolveDeps: async () => ({
        nodeId: NODE_ID,
        identity,
        pinnedKey: orchestrator.publicKey,
        replay: new JtiReplayCache(),
        serve: permissiveServe,
      }),
    });
    const wrongToken = mint(generateDedupeKey({ target_url: "https://elsewhere.test/", method: "GET" }), "j-stream-wrong");
    const resp = await runDataRequest(h.client, {
      nodeId: NODE_ID,
      expectedNodePublicKeyPem: identity.publicKeyPem,
      token: wrongToken,
      request: echoRequest,
    });
    await h.done;
    assert.equal(resp.type, "error");
    assert.equal((resp as { code: string }).code, "unauthorized");
    assert.equal(h.closeReason(), "data-plane complete");
    checks += 2;
  }

  // 3) resolveDeps failure (e.g. no pinned orchestrator key) surfaces via
  //    onError and still closes the stream — never a silent hang.
  {
    const h = tunnelStreamHarness({
      resolveDeps: async () => {
        throw new Error("no pinned orchestrator key");
      },
    });
    await h.done;
    assert.equal(h.errored()?.message, "no pinned orchestrator key");
    assert.equal(h.closeReason(), "data-plane closed");
    checks += 2;
  }

  console.log(`data-plane-stream.test: ${checks} checks passed`);
} finally {
  upstream.stop(true);
}
