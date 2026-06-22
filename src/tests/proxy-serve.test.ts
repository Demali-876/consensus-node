import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";

import { serveProxyRequest, type SsrfCheck } from "../runtime/proxy-serve";
import type { SafeResolution } from "../runtime/ssrf";

const allow =
  (hostname: string, ip = "127.0.0.1"): SsrfCheck =>
  async (): Promise<SafeResolution> => ({ ip, family: 4, hostname, isLiteral: hostname === ip });

function genSelfSignedCert(commonName: string): { key: string; cert: string } | null {
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "consensus-cert-"));
    const cnf = path.join(dir, "san.cnf");
    fs.writeFileSync(
      cnf,
      `[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=${commonName}\n[v3]\nsubjectAltName=DNS:${commonName}\n`,
    );
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-keyout", path.join(dir, "k.pem"), "-out", path.join(dir, "c.pem"), "-days", "1", "-nodes", "-config", cnf],
      { stdio: "ignore" },
    );
    const key = fs.readFileSync(path.join(dir, "k.pem"), "utf8");
    const cert = fs.readFileSync(path.join(dir, "c.pem"), "utf8");
    fs.rmSync(dir, { recursive: true, force: true });
    return { key, cert };
  } catch {
    return null;
  }
}

let checks = 0;

// 1) SSRF gate (real guard): private/loopback/invalid targets refused up front.
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

// A local HTTP upstream. The real guard blocks loopback, so tests inject a
// permissive ssrfCheck (same pattern as the server suite's noSsrf helper).
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
      headers: {
        "content-type": "text/plain",
        "x-host-seen": req.headers.get("host") ?? "ABSENT",
        "x-secret-seen": req.headers.get("x-secret") ?? "ABSENT",
        "x-keep-seen": req.headers.get("x-keep") ?? "ABSENT",
      },
    });
  },
});
const port = server.port;

try {
  // 2) Happy path: POST body forwarded, response intact.
  {
    const res = await serveProxyRequest(
      { target_url: `http://127.0.0.1:${port}/echo`, method: "POST", headers: { "content-type": "text/plain" }, body: "hello" },
      { ssrfCheck: allow("127.0.0.1") },
    );
    assert.equal(res.status, 200);
    assert.equal(res.body.toString(), "echo:POST:hello");
    assert.match(res.headers["content-type"] ?? "", /text\/plain/);
    assert.equal(res.headers["x-host-seen"], `127.0.0.1:${port}`);
    checks += 4;
  }

  // 3) IP-pin + Host preservation: a hostname mapped to loopback still reaches
  // the server and the upstream sees the ORIGINAL Host.
  {
    const res = await serveProxyRequest(
      { target_url: `http://example.test:${port}/echo`, method: "GET" },
      { ssrfCheck: allow("example.test") },
    );
    assert.equal(res.status, 200);
    assert.equal(res.headers["x-host-seen"], `example.test:${port}`, "upstream sees the original Host");
    checks += 2;
  }

  // 4) Redirects are returned, not followed (a Location could bypass SSRF).
  {
    const res = await serveProxyRequest({ target_url: `http://127.0.0.1:${port}/redirect` }, { ssrfCheck: allow("127.0.0.1") });
    assert.equal(res.status, 302);
    assert.match(res.headers["location"] ?? "", /169\.254\.169\.254/);
    checks += 2;
  }

  // 5) Hop-by-hop stripping incl. headers NAMED by Connection (RFC 7230): a
  // header listed in Connection must not traverse the proxy.
  {
    const res = await serveProxyRequest(
      {
        target_url: `http://127.0.0.1:${port}/echo`,
        headers: { connection: "x-secret, keep-alive", "x-secret": "leak", "x-keep": "ok" },
      },
      { ssrfCheck: allow("127.0.0.1") },
    );
    assert.equal(res.headers["x-secret-seen"], "ABSENT", "header named by Connection is stripped");
    assert.equal(res.headers["x-keep-seen"], "ok", "ordinary header is forwarded");
    checks += 2;
  }
} finally {
  server.stop(true);
}

// 6) HTTPS: connect to the pinned IP but validate the cert against the original
// hostname (the codex case). Requires openssl to mint a SAN cert; skipped if absent.
const tlsCert = genSelfSignedCert("example.test");
if (tlsCert) {
  const tlsServer = https.createServer({ key: tlsCert.key, cert: tlsCert.cert }, (_req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("secure-ok");
  });
  await new Promise<void>((r) => tlsServer.listen(0, "127.0.0.1", () => r()));
  const tlsPort = (tlsServer.address() as { port: number }).port;
  try {
    // Hostname matches the cert SAN, pinned to loopback, trusted via the test CA.
    const ok = await serveProxyRequest(
      { target_url: `https://example.test:${tlsPort}/` },
      { ssrfCheck: allow("example.test"), tls: { ca: tlsCert.cert } },
    );
    assert.equal(ok.status, 200);
    assert.equal(ok.body.toString(), "secure-ok");
    checks += 2;

    // Hostname does NOT match the cert SAN — identity validated against the name.
    await assert.rejects(
      () =>
        serveProxyRequest(
          { target_url: `https://evil.test:${tlsPort}/` },
          { ssrfCheck: allow("evil.test"), tls: { ca: tlsCert.cert } },
        ),
      /altname|does not match|identity/i,
      "cert identity is checked against the hostname, not the IP",
    );
    checks++;

    // Untrusted chain (no CA) must fail closed even though the hostname matches.
    await assert.rejects(
      () => serveProxyRequest({ target_url: `https://example.test:${tlsPort}/` }, { ssrfCheck: allow("example.test") }),
      /self.?signed|unable to (get|verify)|certificate/i,
      "untrusted chain fails closed",
    );
    checks++;
  } finally {
    tlsServer.close();
  }
} else {
  console.log("proxy-serve.test.ts: openssl unavailable — skipped HTTPS identity assertions");
}

console.log(`proxy-serve.test.ts: ${checks} checks passed — SSRF-gated, IP-pinned serve; HTTPS validated vs hostname; hop-by-hop stripped`);
