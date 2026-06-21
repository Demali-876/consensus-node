// SSRF-guarded proxy serve for the node data plane. Unlike runtime/proxy-command.ts
// (which fetches the client URL directly), this resolves and checks the target
// FIRST, then pins the outgoing connection to the verified IP — closing the
// DNS-rebinding TOCTOU window the guard is designed to prevent.
//
// Pinning: the URL host is rewritten to the verified IP so the HTTP stack never
// re-resolves the name; the original host is kept for the `Host` header (HTTP
// vhost routing) and TLS `serverName` (HTTPS SNI + cert validation). Redirects
// are NOT followed — a 3xx Location would skip the SSRF check, so it is returned
// to the caller verbatim.

import { resolveAndCheckTarget, type SafeResolution } from "./ssrf";

export type SsrfCheck = (url: string) => Promise<SafeResolution>;

export interface ProxyServeRequest {
  target_url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer | null;
}

export interface ProxyResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: Buffer;
}

export interface ProxyServeOptions {
  ssrfCheck?: SsrfCheck; // injectable for tests; defaults to the real guard
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;

// Hop-by-hop headers must not be forwarded to the upstream; `host` we set ourselves.
const HOP_BY_HOP = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

export async function serveProxyRequest(
  request: ProxyServeRequest,
  opts: ProxyServeOptions = {},
): Promise<ProxyResult> {
  const ssrfCheck = opts.ssrfCheck ?? resolveAndCheckTarget;
  const method = (request.method ?? "GET").toUpperCase();

  // SSRF gate: throws TypeError for private/loopback/invalid targets.
  const resolution = await ssrfCheck(request.target_url);

  const url = new URL(request.target_url);
  const originalHost = url.host; // hostname[:port], port omitted when default
  const serverName = url.hostname; // for TLS SNI / cert validation
  const isHttps = url.protocol === "https:";

  // Pin the connection to the verified IP — no second DNS lookup.
  url.hostname = resolution.family === 6 ? `[${resolution.ip}]` : resolution.ip;

  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers ?? {})) {
    if (!HOP_BY_HOP.has(key.toLowerCase())) headers.set(key, value);
  }
  headers.set("host", originalHost);
  if (!headers.has("user-agent")) headers.set("user-agent", "Consensus-Node/0.1");

  const init: RequestInit & { tls?: { serverName: string } } = {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : (request.body ?? undefined),
    redirect: "manual", // do not auto-follow — a redirect would bypass the SSRF check
    signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  };
  if (isHttps) init.tls = { serverName };

  const response = await fetch(url.toString(), init);

  return {
    status: response.status,
    statusText: response.statusText,
    headers: Object.fromEntries(response.headers.entries()),
    body: Buffer.from(await response.arrayBuffer()),
  };
}
