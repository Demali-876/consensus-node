// Network eval actions, driven over the eval tunnel and TIMED BY THE
// ORCHESTRATOR (not self-reported). The node just does the work and returns
// metadata; the server measures the round-trip on its own clock, so a node
// cannot inflate these numbers — it can only be honest or slow.
//
//   tunnel_echo      echo a payload back verbatim → server measures pure tunnel
//                    latency + throughput (frame seal/open + WS), no upstream.
//                    Isolates "is the node slow" from "is the tunnel slow".
//   speedtest_fetch  fetch an orchestrator-chosen target through the REAL
//                    SSRF-guarded serve path → server measures the node's proxy
//                    round-trip. Returns metadata only (status/bytes/node_ms),
//                    never the body — the echo test already measures tunnel
//                    throughput, so there is no need to haul the body back.

import { serveProxyRequest } from "./proxy-serve";
import type { SsrfCheck } from "./proxy-serve";

// Cap the echo payload so a malformed/hostile request can't force a huge
// allocation. The orchestrator's largest echo size is 256KB.
const MAX_ECHO_BYTES = 512 * 1024;
const DEFAULT_FETCH_TIMEOUT_MS = 15_000;

export interface TunnelEchoResult {
  ok: true;
  bytes: number;
  echo: string; // the base64 payload, returned verbatim
  nonce?: string;
}

/** Echo the request payload back so the orchestrator can time a tunnel round
 *  trip of known size. Pure and synchronous — the only cost is the frame the
 *  tunnel seals around the reply, which is exactly what we want to measure. */
export function runTunnelEcho(params: Record<string, unknown>): TunnelEchoResult {
  const payload = typeof params.payload === "string" ? params.payload : "";
  const bytes = Buffer.from(payload, "base64").length;
  if (bytes > MAX_ECHO_BYTES) {
    throw new Error(`tunnel_echo payload ${bytes} bytes exceeds max ${MAX_ECHO_BYTES}`);
  }
  return {
    ok: true,
    bytes,
    echo: payload,
    nonce: typeof params.nonce === "string" ? params.nonce : undefined,
  };
}

export interface SpeedtestFetchResult {
  ok: boolean;
  status: number;
  bytes: number;
  /** Node's own fetch timing — a cross-check; the orchestrator's round-trip
   *  clock is the authority for scoring. */
  node_ms: number;
  content_type?: string;
}

export interface SpeedtestFetchDeps {
  /** Injectable for tests; defaults to the real SSRF-guarded resolver. */
  ssrfCheck?: SsrfCheck;
}

/** Fetch the orchestrator-supplied target through the production serve path
 *  (SSRF resolve + IP-pin + fetch). Returns metadata only. */
export async function runSpeedtestFetch(
  params: Record<string, unknown>,
  deps: SpeedtestFetchDeps = {},
): Promise<SpeedtestFetchResult> {
  const targetUrl = typeof params.target_url === "string" ? params.target_url : "";
  if (!targetUrl) throw new Error("speedtest_fetch requires a target_url");
  const method = typeof params.method === "string" ? params.method.toUpperCase() : "GET";
  const timeoutCandidate = Number(params.timeout_ms ?? DEFAULT_FETCH_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(timeoutCandidate) && timeoutCandidate > 0
    ? timeoutCandidate
    : DEFAULT_FETCH_TIMEOUT_MS;

  const start = performance.now();
  const result = await serveProxyRequest(
    { target_url: targetUrl, method },
    { timeoutMs, ssrfCheck: deps.ssrfCheck },
  );
  const nodeMs = performance.now() - start;

  return {
    ok: result.status >= 200 && result.status < 400,
    status: result.status,
    bytes: result.body.length,
    node_ms: Math.round(nodeMs),
    content_type: result.headers["content-type"],
  };
}
