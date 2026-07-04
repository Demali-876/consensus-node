// Composite request benchmark: measures what this CPU can do for Consensus by
// running the node's ACTUAL per-request data-plane pipeline in memory, with the
// upstream fetch stubbed out. One iteration = one full request lifecycle exactly
// as production pays it (the data plane serves ONE request per connection, so the
// handshake is per-request cost, not per-session):
//
//   handshake       acceptDataInit — P-256 ephemeral keygen + ECDH + HKDF derive
//                   + Ed25519 identity sign (tunnel/data-handshake.ts)
//   request_open    openFrame (ChaCha20-Poly1305) + JSON.parse + payload checks
//                   + body base64-decode (mirrors resolveProxyResponse)
//   ticket_verify   PASETO v4.public Ed25519 verify + dedupe-key recompute +
//                   jti replay consume (tickets/request-ticket.ts)
//   response_encode body base64-encode + JSON.stringify of the response payload
//   response_seal   sealFrame (ChaCha20-Poly1305) of the encoded response
//
// Client-side work (createDataInit, session derive, request sealing) and ticket
// minting are real too — they produce valid inputs each iteration — but run
// UNTIMED between stages: this suite judges the node's share only.
//
// Every function in the timed path IS the production implementation, imported
// from its real module — never a reimplementation. The stage ORDER mirrors
// serveDataConnection/resolveProxyResponse in tunnel/data-plane.ts; keep them in
// sync. As a drift guard, each size config first runs one untimed round trip
// through the real serveDataConnection + runDataRequest over an in-memory pipe
// and asserts the response body survives byte-identical — if the pipeline shape
// changes, the benchmark fails loudly instead of measuring a stale profile.
//
// Reported numbers:
//   - exchange.*                 runner stats over the WHOLE loop (client + node
//                                on this same CPU) — its CV drives `reliable`.
//   - node_requests_per_second   derived from the timed node-side stages only:
//                                the headline "what can this CPU serve" figure.
//   - stages.*                   mean ns + share of node-side time per stage, so
//                                a slow machine shows WHERE it is slow.

import crypto from "node:crypto";
import { hrtime } from "node:process";
import { bench, type BenchResult } from "../runner";
import { openFrame, sealFrame } from "../../../crypto/secure-channel";
import { FRAME_TYPE } from "../../../tunnel/frames";
import { acceptDataInit, createDataInit, deriveClientDataSession } from "../../../tunnel/data-handshake";
import {
  runDataRequest,
  serveDataConnection,
  type MessageTransport,
  type ProxyRequestPayload,
} from "../../../tunnel/data-plane";
import { issueTicket } from "../../../tickets/ticket";
import { verifyRequestTicket } from "../../../tickets/request-ticket";
import { JtiReplayCache } from "../../../tickets/replay";
import { generateDedupeKey, type DedupeParams } from "../../dedupe";
import type { NodeIdentity } from "../../../crypto/identity";
import type { ProxyResult } from "../../proxy-serve";

export interface CompositeSizeConfig {
  label: string;
  response_bytes: number;
  /** Iterations per runner sample. Omit to auto-tune from the warmup timing so
   *  samples land near TARGET_SAMPLE_MS on fast and slow hardware alike — a
   *  fixed count that suits a Raspberry Pi gives sub-millisecond samples on an
   *  M-series Mac, and short samples read scheduler noise as variance. */
  inner?: number;
}

// Response-size axis: small API reply, typical JSON payload, chunky download.
// Request side is a fixed GET; response size is what scales the encode/seal cost.
export const DEFAULT_COMPOSITE_SIZES: CompositeSizeConfig[] = [
  { label: "1KB", response_bytes: 1024 },
  { label: "16KB", response_bytes: 16384 },
  { label: "256KB", response_bytes: 262144 },
];

const TARGET_SAMPLE_MS = 8;
const MAX_INNER = 64;

export type CompositeStageName =
  | "handshake"
  | "request_open"
  | "ticket_verify"
  | "response_encode"
  | "response_seal";

export interface CompositeStageStats {
  mean_ns: number;
  /** Fraction of node-side time spent in this stage (all stages sum to ~1). */
  share: number;
}

export interface CompositeRequestSubResult {
  response_size_bytes: number;
  /** Runner stats over the whole exchange (client + node work on this CPU). */
  exchange: BenchResult;
  /** Node-side stages only — requests/sec this CPU could serve, single core. */
  node_requests_per_second: number;
  node_ns_per_request: number;
  stages: Record<CompositeStageName, CompositeStageStats>;
  reliable: boolean;
}

export interface CompositeRequestResult {
  results: CompositeRequestSubResult[];
  // Headline: node-side requests/sec at 16KB — the "typical response" figure,
  // consistent with the other suites' headline-at-1KB/16KB convention.
  requests_per_second: number;
  reliable: boolean;
}

export interface CompositeRequestOptions {
  sizes?: CompositeSizeConfig[];
  warmupMs?: number;
  measureMs?: number;
}

const NODE_ID = "bench-node";
const KID = "bench-kid";
const TARGET_URL = "https://upstream.example.com/api/v1/resource?b=2&a=1";

// Realistic scoped GET: `accept`/`content-type` exercise the semantic-header
// canonicalization, `x-api-key` forces the scope hash, the rest is passthrough.
const REQUEST_HEADERS: Record<string, string> = {
  accept: "application/json",
  "content-type": "application/json",
  "user-agent": "consensus-bench/1.0",
  "x-api-key": "bench-scope-key",
};

const STAGE_NAMES: CompositeStageName[] = [
  "handshake",
  "request_open",
  "ticket_verify",
  "response_encode",
  "response_seal",
];

interface Fixture {
  identity: NodeIdentity;
  orchestrator: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };
  replay: JtiReplayCache;
  dedupeKey: string;
  /** Pre-built upstream result the stubbed serve returns (untimed by design —
   *  the real serve cost is network, excluded from a CPU benchmark). */
  upstream: ProxyResult;
}

type StageTotals = Record<CompositeStageName, bigint> & { iterations: number };

export async function runCompositeRequest(
  opts: CompositeRequestOptions = {},
): Promise<CompositeRequestResult> {
  const sizes = opts.sizes ?? DEFAULT_COMPOSITE_SIZES;
  const results: CompositeRequestSubResult[] = [];

  for (const size of sizes) {
    const fixture = buildFixture(size.response_bytes);

    // Drift guard: prove the fixture drives the REAL production pipeline before
    // timing a decomposed copy of it.
    await sanityRoundTrip(fixture);

    // Collect the previous size's garbage now so its GC debt is not paid
    // inside this size's timed samples.
    Bun.gc(true);
    results.push(await measureSize(size, fixture, opts));
  }

  const headline =
    results.find((r) => r.response_size_bytes === 16384) ?? results[results.length - 1];
  return {
    results,
    requests_per_second: headline?.node_requests_per_second ?? 0,
    reliable: results.every((r) => r.reliable),
  };
}

function buildFixture(responseBytes: number): Fixture {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const identity: NodeIdentity = { privateKeyPem: privateKey, publicKeyPem: publicKey };
  const orchestrator = crypto.generateKeyPairSync("ed25519");

  const dedupeKey = generateDedupeKey(requestDedupeParams());

  const upstream: ProxyResult = {
    status: 200,
    statusText: "OK",
    headers: {
      "content-type": "application/json",
      "content-length": String(responseBytes),
      date: new Date(0).toUTCString(),
      server: "upstream/1.0",
      "cache-control": "no-store",
      etag: '"bench-etag"',
      "x-request-id": "bench-request",
    },
    body: crypto.randomBytes(responseBytes),
  };

  return { identity, orchestrator, replay: new JtiReplayCache(), dedupeKey, upstream };
}

// Return type is the intersection both consumers accept: generateDedupeKey
// takes DedupeParams; runDataRequest's request param types `body` more narrowly.
// The fixture request is a bodiless GET, so the narrow shape satisfies both.
function requestDedupeParams(): { target_url: string; method: string; headers: Record<string, string> } {
  return {
    target_url: TARGET_URL,
    method: "GET",
    headers: { ...REQUEST_HEADERS },
  };
}

function mintTicket(fixture: Fixture): string {
  return issueTicket(
    { nodeId: NODE_ID, dedupeKey: fixture.dedupeKey, jti: crypto.randomUUID() },
    fixture.orchestrator.privateKey,
    KID,
  );
}

async function measureSize(
  size: CompositeSizeConfig,
  fixture: Fixture,
  opts: CompositeRequestOptions,
): Promise<CompositeRequestSubResult> {
  const totals = newStageTotals();

  // Manual warmup, one iteration at a time — it both warms the JIT and times a
  // representative exchange so `inner` can be tuned before measurement. The
  // stage accumulators are reset afterwards (bench() cannot signal warmup-end,
  // and JIT-cold iterations would skew the per-stage means), and bench() then
  // runs with warmupMs: 0.
  const warmupMs = opts.warmupMs ?? 200;
  const warmupStart = hrtime.bigint();
  const warmupEnd = warmupStart + BigInt(warmupMs * 1_000_000);
  let warmupIterations = 0;
  while (hrtime.bigint() < warmupEnd) {
    await runIteration(fixture, totals);
    warmupIterations += 1;
  }
  const warmupNsPerExchange = Number(hrtime.bigint() - warmupStart) / Math.max(1, warmupIterations);
  resetStageTotals(totals);

  const inner =
    size.inner ??
    Math.max(1, Math.min(MAX_INNER, Math.round((TARGET_SAMPLE_MS * 1e6) / warmupNsPerExchange)));

  const fn = async (): Promise<number> => {
    for (let i = 0; i < inner; i++) {
      await runIteration(fixture, totals);
    }
    return inner;
  };

  const exchange = await bench(fn, {
    name: `composite-request-${size.label}`,
    warmupMs: 0,
    measureMs: opts.measureMs ?? 1000,
  });

  const nodeNsTotal = STAGE_NAMES.reduce((sum, stage) => sum + totals[stage], 0n);
  const iterations = totals.iterations;
  const nodeNsPerRequest = iterations > 0 ? Number(nodeNsTotal) / iterations : 0;

  const stages = {} as Record<CompositeStageName, CompositeStageStats>;
  for (const stage of STAGE_NAMES) {
    const meanNs = iterations > 0 ? Number(totals[stage]) / iterations : 0;
    stages[stage] = {
      mean_ns: Math.round(meanNs),
      share: nodeNsPerRequest > 0 ? meanNs / nodeNsPerRequest : 0,
    };
  }

  return {
    response_size_bytes: size.response_bytes,
    exchange,
    node_requests_per_second: nodeNsPerRequest > 0 ? 1e9 / nodeNsPerRequest : 0,
    node_ns_per_request: Math.round(nodeNsPerRequest),
    stages,
    reliable: exchange.reliable,
  };
}

/** One request lifecycle. Node-side stages are timed into `totals`; client and
 *  orchestrator work (init, session derive, request sealing, ticket mint) runs
 *  untimed — production spends that CPU elsewhere. */
async function runIteration(fixture: Fixture, totals: StageTotals): Promise<void> {
  // --- client + orchestrator prep (untimed) --------------------------------
  const client = await createDataInit({ nodeId: NODE_ID });
  const token = mintTicket(fixture);

  // --- stage: handshake (node accepts, derives session, signs identity) ----
  let at = hrtime.bigint();
  const { message: accept, session: nodeSession } = await acceptDataInit({
    init: client.message,
    identity: fixture.identity,
    nodeId: NODE_ID,
  });
  totals.handshake += hrtime.bigint() - at;

  // --- client seals the ticketed request (untimed) --------------------------
  const clientSession = await deriveClientDataSession({
    client,
    accept,
    expectedNodeId: NODE_ID,
    expectedNodePublicKeyPem: fixture.identity.publicKeyPem,
  });
  const requestPayload: ProxyRequestPayload = {
    type: "proxy_request",
    token,
    target_url: TARGET_URL,
    method: "GET",
    headers: { ...REQUEST_HEADERS },
  };
  const requestFrame = sealFrame(
    clientSession.sendKey,
    FRAME_TYPE.DATA,
    0n,
    Buffer.from(JSON.stringify(requestPayload), "utf8"),
  );

  // --- stage: request_open (mirrors resolveProxyResponse ingest) -----------
  at = hrtime.bigint();
  const { frame, plaintext } = openFrame(nodeSession.receiveKey, requestFrame);
  if (frame.type !== FRAME_TYPE.DATA) throw new Error("composite: unexpected frame type");
  const parsed = JSON.parse(plaintext.toString("utf8")) as ProxyRequestPayload;
  if (parsed.type !== "proxy_request" || typeof parsed.token !== "string" || typeof parsed.target_url !== "string") {
    throw new Error("composite: invalid proxy_request payload");
  }
  const body = parsed.body ? Buffer.from(parsed.body, "base64") : undefined;
  const method = (parsed.method ?? "GET").toUpperCase();
  const dedupeParams: DedupeParams = {
    target_url: parsed.target_url,
    method,
    headers: parsed.headers,
    body,
  };
  totals.request_open += hrtime.bigint() - at;

  // --- stage: ticket_verify --------------------------------------------------
  at = hrtime.bigint();
  verifyRequestTicket({
    token: parsed.token,
    nodeId: NODE_ID,
    publicKey: fixture.orchestrator.publicKey,
    request: dedupeParams,
    replay: fixture.replay,
  });
  totals.ticket_verify += hrtime.bigint() - at;

  // (upstream serve is stubbed: fixture.upstream — network cost, not CPU)

  // --- stage: response_encode (mirrors resolveProxyResponse egress) --------
  at = hrtime.bigint();
  const responseJson = Buffer.from(
    JSON.stringify({
      type: "proxy_response",
      status: fixture.upstream.status,
      status_text: fixture.upstream.statusText,
      headers: fixture.upstream.headers,
      body: fixture.upstream.body.toString("base64"),
      body_encoding: "base64",
    }),
    "utf8",
  );
  totals.response_encode += hrtime.bigint() - at;

  // --- stage: response_seal --------------------------------------------------
  at = hrtime.bigint();
  const responseFrame = sealFrame(nodeSession.sendKey, FRAME_TYPE.DATA, 0n, responseJson);
  totals.response_seal += hrtime.bigint() - at;
  if (responseFrame.length <= fixture.upstream.body.length) {
    throw new Error("composite: sealed response impossibly small");
  }

  totals.iterations += 1;
}

/** Untimed round trip through the REAL serveDataConnection + runDataRequest over
 *  an in-memory pipe. Throws if the production pipeline and this fixture ever
 *  disagree — the guard that keeps the timed stages honest. */
async function sanityRoundTrip(fixture: Fixture): Promise<void> {
  const pipe = memoryPipe();
  const served = serveDataConnection(pipe.server, {
    nodeId: NODE_ID,
    identity: fixture.identity,
    pinnedKey: fixture.orchestrator.publicKey,
    replay: fixture.replay,
    serve: async () => fixture.upstream,
  });

  const response = await runDataRequest(pipe.client, {
    nodeId: NODE_ID,
    expectedNodePublicKeyPem: fixture.identity.publicKeyPem,
    token: mintTicket(fixture),
    request: requestDedupeParams(),
  });
  await served;

  if (response.type !== "proxy_response") {
    throw new Error(`composite sanity: pipeline returned ${response.type}: ${JSON.stringify(response)}`);
  }
  if (!fixture.upstream.body.equals(Buffer.from(response.body, "base64"))) {
    throw new Error("composite sanity: response body did not survive the pipeline");
  }
}

function newStageTotals(): StageTotals {
  return {
    handshake: 0n,
    request_open: 0n,
    ticket_verify: 0n,
    response_encode: 0n,
    response_seal: 0n,
    iterations: 0,
  };
}

function resetStageTotals(totals: StageTotals): void {
  for (const stage of STAGE_NAMES) totals[stage] = 0n;
  totals.iterations = 0;
}

/** Minimal ordered in-memory message pipe (same shape as the data-plane tests). */
function memoryPipe(): { client: MessageTransport; server: MessageTransport } {
  const toServer: Buffer[] = [];
  const toClient: Buffer[] = [];
  const serverWaiters: Array<(b: Buffer) => void> = [];
  const clientWaiters: Array<(b: Buffer) => void> = [];

  const push = (queue: Buffer[], waiters: Array<(b: Buffer) => void>, data: Buffer): void => {
    const waiter = waiters.shift();
    if (waiter) waiter(data);
    else queue.push(data);
  };
  const pull = (queue: Buffer[], waiters: Array<(b: Buffer) => void>): Promise<Buffer> => {
    const message = queue.shift();
    if (message) return Promise.resolve(message);
    return new Promise<Buffer>((resolve) => waiters.push(resolve));
  };

  return {
    client: {
      recv: () => pull(toClient, clientWaiters),
      send: (data) => push(toServer, serverWaiters, data),
      close: () => {},
    },
    server: {
      recv: () => pull(toServer, serverWaiters),
      send: (data) => push(toClient, clientWaiters, data),
      close: () => {},
    },
  };
}
