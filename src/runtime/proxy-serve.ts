// SSRF-guarded proxy serve for the node data plane. Unlike runtime/proxy-command.ts
// (which fetches the client URL directly), this resolves and checks the target
// FIRST, then pins the outgoing connection to the verified IP — closing the
// DNS-rebinding TOCTOU window the guard is designed to prevent.
//
// Pinning: the URL host is rewritten to the verified IP so the HTTP stack never
// re-resolves the name. The original host is kept for the `Host` header (HTTP
// vhost routing) and, for HTTPS, the TLS `serverName` (SNI). Because the URL now
// contains an IP, certificate identity must be validated against the ORIGINAL
// hostname, not the IP — done via a `checkServerIdentity` delegate to
// node:tls (chain/trust validation is unaffected and still fails closed on an
// untrusted cert). Redirects are NOT followed — a 3xx Location would skip the
// SSRF check, so it is returned to the caller verbatim.

import { checkServerIdentity, type PeerCertificate } from "node:tls";
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
  /** Extra TLS trust anchors (e.g. a private upstream CA). Tests inject a
   *  self-signed root here; production validates against the system store. */
  tls?: { ca?: string | string[] };
}

// Bun's fetch accepts a `tls` option that node's RequestInit type doesn't model.
interface BunFetchInit extends RequestInit {
  tls?: {
    serverName?: string;
    ca?: string | string[];
    checkServerIdentity?: (host: string, cert: PeerCertificate) => Error | undefined;
  };
}

const DEFAULT_TIMEOUT_MS = 30_000;

// Always-hop-by-hop headers (RFC 7230 §6.1); `host` we set ourselves. The
// `Connection` header itself additionally NAMES further hop-by-hop headers that
// must be stripped — see buildHopByHopDenySet.
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

/** The set of header names to strip: the fixed hop-by-hop set plus every token
 *  listed in the request's Connection header (those are connection-specific and
 *  must not traverse a proxy). */
function buildHopByHopDenySet(headers: Record<string, string>): Set<string> {
  const deny = new Set(HOP_BY_HOP);
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== "connection") continue;
    for (const token of value.split(",")) {
      const name = token.trim().toLowerCase();
      if (name) deny.add(name);
    }
  }
  return deny;
}

// Consensus-internal control headers that must never be forwarded to an upstream
// target. On the direct data plane the client supplies the request headers and
// the node serves them against the client's chosen upstream, so these are
// stripped node-side as defense-in-depth — the orchestrator (relayed path) and
// the consensus-client both strip them too. The deprecated `x-api-key` remains
// only as a denylist entry and has no identity, routing, or cache semantics.
//
// Source of truth: STRIP_REQUEST_HEADERS in the consensus repo
// (server/features/proxy/proxy.ts). This mirrors that list with ONE deliberate
// divergence: `content-encoding` is NOT stripped here. Unlike the orchestrator,
// this path forwards the original request body bytes verbatim, so the
// representation-encoding metadata must survive — drop it and the upstream gets
// e.g. gzip bytes with no Content-Encoding and misreads or rejects them.
// `content-length` IS still stripped because fetch recomputes it to match the
// forwarded body. Some entries (host, connection, transfer-encoding) overlap the
// hop-by-hop set and stay handled there as well.
const CONSENSUS_CONTROL_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "x-idempotency-key",
  "idempotency-key",
  "x-payment",
  "x-verbose",
  "x-api-key",
  "x-cache-ttl",
  "x-direct",
  "x-node-region",
  "x-node-domain",
  "x-node-exclude",
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
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
  const serverName = url.hostname; // for TLS SNI + certificate identity
  const isHttps = url.protocol === "https:";

  // Pin the connection to the verified IP — no second DNS lookup.
  url.hostname = resolution.family === 6 ? `[${resolution.ip}]` : resolution.ip;

  const deny = buildHopByHopDenySet(request.headers ?? {});
  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers ?? {})) {
    const lower = key.toLowerCase();
    if (deny.has(lower) || CONSENSUS_CONTROL_HEADERS.has(lower)) continue;
    headers.set(key, value);
  }
  headers.set("host", originalHost);
  if (!headers.has("user-agent")) headers.set("user-agent", "Consensus-Node/0.1");

  const init: BunFetchInit = {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : (request.body ?? undefined),
    redirect: "manual", // do not auto-follow — a redirect would bypass the SSRF check
    signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  };
  if (isHttps) {
    // Connecting to an IP literal: validate the cert against the real hostname,
    // not the IP. node:tls.checkServerIdentity does the SAN/wildcard matching;
    // trust-chain verification still runs and fails closed on an untrusted cert.
    init.tls = {
      serverName,
      checkServerIdentity: (_host, cert) => checkServerIdentity(serverName, cert),
      ...(opts.tls?.ca ? { ca: opts.tls.ca } : {}),
    };
  }

  const response = await fetch(url.toString(), init);

  return {
    status: response.status,
    statusText: response.statusText,
    headers: Object.fromEntries(response.headers.entries()),
    body: Buffer.from(await response.arrayBuffer()),
  };
}
