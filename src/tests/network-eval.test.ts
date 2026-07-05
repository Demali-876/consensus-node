import assert from "node:assert/strict";
import { runTunnelEcho, runSpeedtestFetch } from "../runtime/network-eval";
import type { SsrfCheck } from "../runtime/proxy-serve";
import type { SafeResolution } from "../runtime/ssrf";

// ---------------------------------------------------------------------------
// tunnel_echo — returns the payload verbatim with a decoded byte count.
// ---------------------------------------------------------------------------

const payload = Buffer.from("consensus-echo-payload".repeat(8)).toString("base64");
const echo = runTunnelEcho({ payload, nonce: "n-1" });
assert.equal(echo.ok, true, "echo ok");
assert.equal(echo.echo, payload, "payload returned verbatim");
assert.equal(echo.bytes, Buffer.from(payload, "base64").length, "byte count is the decoded length");
assert.equal(echo.nonce, "n-1", "nonce echoed for correlation");

const empty = runTunnelEcho({});
assert.equal(empty.bytes, 0, "missing payload → 0 bytes, no throw");

assert.throws(
  () => runTunnelEcho({ payload: Buffer.alloc(600 * 1024).toString("base64") }),
  /exceeds max/,
  "oversized echo payload is rejected",
);

// ---------------------------------------------------------------------------
// speedtest_fetch — fetches the orchestrator target through the real serve path
// (SSRF injected permissive so the test can hit a local server), returns
// metadata only. Body is never echoed back.
// ---------------------------------------------------------------------------

const BODY_BYTES = 16384;
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch() {
    return new Response(Buffer.alloc(BODY_BYTES, 0x61), {
      headers: { "content-type": "application/octet-stream" },
    });
  },
});

const allowLoopback: SsrfCheck = async (): Promise<SafeResolution> => ({
  ip: "127.0.0.1",
  family: 4,
  hostname: "127.0.0.1",
  isLiteral: true,
});

try {
  const url = `http://127.0.0.1:${server.port}/speedtest/${BODY_BYTES}`;
  const result = await runSpeedtestFetch({ target_url: url }, { ssrfCheck: allowLoopback });
  assert.equal(result.ok, true, "2xx counts as ok");
  assert.equal(result.status, 200, "status surfaced");
  assert.equal(result.bytes, BODY_BYTES, "byte count is the fetched body length");
  assert.ok(result.node_ms >= 0, "node_ms present as a cross-check");
  assert.equal(result.content_type, "application/octet-stream", "content-type surfaced");

  await assert.rejects(
    () => runSpeedtestFetch({}, { ssrfCheck: allowLoopback }),
    /requires a target_url/,
    "missing target_url is rejected",
  );
} finally {
  server.stop(true);
}

console.log("network-eval ok");
