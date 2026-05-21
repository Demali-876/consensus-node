/**
 * BUG: SSRF - Unconstrained Proxy URL
 *
 * Both executeProxyCommand (tunnel-driven) and the /proxy HTTP route call
 * fetch(target_url) with no validation of the URL's scheme, host, or IP.
 *
 * A server that controls this node can direct it to make requests to:
 *   - http://127.0.0.1/...  (services on the node's own loopback)
 *   - http://169.254.169.254/ (cloud metadata endpoints on AWS/GCP/Azure)
 *   - file:///etc/passwd (file scheme, depending on runtime)
 *   - any internal network host unreachable from the outside
 *
 * This test proves the vulnerability is present by:
 *   1. Starting a local-only HTTP server on 127.0.0.1 (simulates a private service)
 *   2. Calling executeProxyCommand with a target_url pointing at that server
 *   3. Asserting the response is returned successfully
 *
 * If SSRF protection were in place, step 2 should throw with a
 * "blocked private address" error. Currently it does not.
 */

import assert from "node:assert/strict";
import net from "node:net";
import { executeProxyCommand } from "../runtime/proxy-command";
import { MESSAGE_TYPE, nowSeconds } from "../tunnel/messages";

// ---- Stand up a minimal HTTP server on the loopback only ------------------

function startLocalServer(): Promise<{ port: number; close(): void }> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.once("data", () => {
        const body = JSON.stringify({ secret: "internal-data" });
        socket.write(
          `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
        );
        socket.end();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      resolve({
        port: addr.port,
        close: () => server.close(),
      });
    });
    server.once("error", reject);
  });
}

const { port, close } = await startLocalServer();

try {
  // This call should be blocked if SSRF protection exists.
  // Currently it succeeds, proving the bug.
  const response = await executeProxyCommand({
    type: MESSAGE_TYPE.PROXY_REQUEST,
    id: "ssrf-test",
    timestamp: nowSeconds(),
    target_url: `http://127.0.0.1:${port}/`,
    method: "GET",
  });

  // If we reach here the request was NOT blocked — SSRF is present.
  assert.equal(response.status, 200, "SSRF: loopback request should have been blocked but got HTTP 200");

  const body = Buffer.from(response.body ?? "", "base64").toString("utf8");
  const parsed = JSON.parse(body) as { secret?: string };
  assert.equal(
    parsed.secret,
    "internal-data",
    "SSRF: node returned data from a loopback-only service",
  );

  console.log(
    "BUG CONFIRMED — ssrf-proxy: executeProxyCommand reached a loopback service " +
    `(port ${port}) without any block. ` +
    "Fix: validate target_url hostname/IP against an allowlist or RFC-1918 blocklist.",
  );
} finally {
  close();
}
