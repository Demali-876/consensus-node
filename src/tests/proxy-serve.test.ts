import assert from "node:assert/strict";

import { serveProxyRequest, type SsrfCheck } from "../runtime/proxy-serve";
import type { SafeResolution } from "../runtime/ssrf";

let checks = 0;

// 1) SSRF gate (real guard): private/loopback/invalid targets are refused before
// any connection is attempted.
for (const target of [
  "http://127.0.0.1/",
  "http://169.254.169.254/latest/meta-data/", // cloud metadata
  "http://[::1]/",
  "http://10.0.0.5/",
  "file:///etc/passwd",
  "not-a-url",
]) {
  await assert.rejects(() => serveProxyRequest({ target_url: target }), /Forbidden|private/i, `must refuse ${target}`);
  checks++;
}

// A local upstream to exercise the serve path. The real guard would block
// loopback, so tests inject a permissive ssrfCheck (same pattern as the server
// suite's noSsrf helper).
const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/redirect") {
      return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } });
    }
    const body = await req.text();
    return new Response(`echo:${req.method}:${body}`, {
      status: 200,
      headers: { "content-type": "text/plain", "x-host-seen": req.headers.get("host") ?? "" },
    });
  },
});
const port = server.port;

const allow =
  (hostname: string, ip = "127.0.0.1"): SsrfCheck =>
  async (): Promise<SafeResolution> => ({ ip, family: 4, hostname, isLiteral: hostname === ip });

try {
  // 2) Happy path: POST body is forwarded and the response comes back intact.
  {
    const res = await serveProxyRequest(
      {
        target_url: `http://127.0.0.1:${port}/echo`,
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "hello",
      },
      { ssrfCheck: allow("127.0.0.1") },
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.toString(), "echo:POST:hello");
    assert.match(res.headers["content-type"] ?? "", /text\/plain/);
    assert.equal(res.headers["x-host-seen"], `127.0.0.1:${port}`);
    checks += 4;
  }

  // 3) IP-pin + Host preservation: a hostname mapped to the loopback IP still
  // reaches the server (proves we connect to the verified IP, not the name) and
  // the upstream sees the ORIGINAL Host (vhost routing survives the rewrite).
  {
    const res = await serveProxyRequest(
      { target_url: `http://example.test:${port}/echo`, method: "GET" },
      { ssrfCheck: allow("example.test") },
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.toString(), "echo:GET:");
    assert.equal(res.headers["x-host-seen"], `example.test:${port}`, "upstream sees the original Host");
    checks += 3;
  }

  // 4) Redirects are not followed (a Location could bypass the SSRF check): the
  // 3xx is returned verbatim for the caller to re-route.
  {
    const res = await serveProxyRequest(
      { target_url: `http://127.0.0.1:${port}/redirect` },
      { ssrfCheck: allow("127.0.0.1") },
    );
    assert.equal(res.status, 302, "redirect is returned, not followed");
    assert.match(res.headers["location"] ?? "", /169\.254\.169\.254/);
    checks += 2;
  }
} finally {
  server.stop(true);
}

console.log(`proxy-serve.test.ts: ${checks} checks passed — SSRF-gated, IP-pinned serve; redirects not followed`);
