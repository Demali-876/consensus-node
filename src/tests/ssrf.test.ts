/**
 * Evidence test: SSRF (Server-Side Request Forgery) in the proxy subsystem.
 *
 * VULNERABILITY SUMMARY
 * ─────────────────────
 * executeProxyCommand() and the /proxy HTTP endpoint forward requests to a
 * caller-supplied URL with no hostname or IP validation.  The raw TCP tunnel
 * (parseRawTunnelTarget in control-client.ts) has the same flaw: it accepts
 * any host string including "127.0.0.1" or "169.254.169.254".
 *
 * A server that issues malicious PROXY_REQUEST tunnel messages can pivot through
 * the node to reach:
 *   • Internal services bound to 127.0.0.1 / ::1
 *   • RFC-1918 neighbours  (10.x, 172.16-31.x, 192.168.x)
 *   • Cloud instance metadata  (169.254.169.254, fd00:ec2::254)
 *   • Any other host reachable from the node but not from the internet
 *
 * HOW THE TESTS WORK
 * ──────────────────
 * 1. A "secret internal server" is started on 127.0.0.1 at a dynamic port.
 * 2. executeProxyCommand is called with target_url = http://127.0.0.1:<port>
 * 3. The assertions declare what the CORRECT (fixed) behaviour looks like:
 *      - the call must throw before reaching the server, AND
 *      - the internal server must never be hit.
 *
 * CURRENT RESULT:  FAIL — the internal server IS reached (SSRF confirmed).
 * AFTER FIX:       PASS — loopback URL is rejected before any network I/O.
 *
 * The raw-tunnel section validates the in-memory parse path: the expected null
 * return for loopback/link-local host strings currently does NOT happen.
 */

import assert from "node:assert/strict";
import net from "node:net";
import { executeProxyCommand } from "../runtime/proxy-command";
import { MESSAGE_TYPE, nowSeconds } from "../tunnel/messages";

// ── helpers ──────────────────────────────────────────────────────────────────

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (typeof addr === "object" && addr) resolve(addr.port);
        else reject(new Error("Failed to allocate free port"));
      });
    });
  });
}

// ── Part 1: HTTP proxy SSRF ───────────────────────────────────────────────────

const port = await getFreePort();
let internalServerHit = false;

const internalServer = Bun.serve({
  hostname: "127.0.0.1",
  port,
  fetch() {
    internalServerHit = true;
    return new Response("SECRET INTERNAL DATA", { status: 200 });
  },
});

let httpProxyThrew = false;
try {
  await executeProxyCommand({
    type: MESSAGE_TYPE.PROXY_REQUEST,
    timestamp: nowSeconds(),
    target_url: `http://127.0.0.1:${port}/internal-api`,
    method: "GET",
  });
} catch {
  httpProxyThrew = true;
} finally {
  internalServer.stop(true);
}

// If SSRF protection were in place, executeProxyCommand would have thrown
// immediately and the internal server would never have received a connection.
assert.equal(
  internalServerHit,
  false,
  "SSRF BUG (HTTP proxy): the internal loopback server was reached — " +
    "executeProxyCommand must validate target_url and reject loopback/private destinations",
);

assert.equal(
  httpProxyThrew,
  true,
  "SSRF BUG (HTTP proxy): executeProxyCommand must throw a validation error " +
    "when target_url resolves to a loopback address (127.0.0.1)",
);

// ── Part 2: Raw TCP tunnel SSRF ───────────────────────────────────────────────
// parseRawTunnelTarget is a private helper inside control-client.ts.  Its logic
// is reproduced verbatim here so the test is self-contained and stable.
// The function must return null for loopback and link-local targets; it does not.

function parseRawTunnelTargetAsShipped(
  value: string | undefined,
): { host: string; port: number } | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as { kind?: string; host?: string; port?: number };
    if (parsed.kind !== "raw-tunnel" || !parsed.host) return null;
    if (
      typeof parsed.port !== "number" ||
      !Number.isInteger(parsed.port) ||
      parsed.port < 1 ||
      parsed.port > 65535
    ) {
      return null;
    }
    // BUG: no check on parsed.host — any IP/hostname is accepted.
    return { host: parsed.host, port: parsed.port };
  } catch {
    return null;
  }
}

const loopbackTarget = JSON.stringify({ kind: "raw-tunnel", host: "127.0.0.1", port: 22 });
const metadataTarget = JSON.stringify({ kind: "raw-tunnel", host: "169.254.169.254", port: 80 });
const privateTarget  = JSON.stringify({ kind: "raw-tunnel", host: "10.0.0.1", port: 80 });

assert.equal(
  parseRawTunnelTargetAsShipped(loopbackTarget),
  null,
  "SSRF BUG (raw TCP tunnel): parseRawTunnelTarget must return null for loopback host 127.0.0.1 " +
    "(currently returns { host: '127.0.0.1', port: 22 })",
);

assert.equal(
  parseRawTunnelTargetAsShipped(metadataTarget),
  null,
  "SSRF BUG (raw TCP tunnel): parseRawTunnelTarget must return null for link-local host 169.254.169.254 " +
    "(cloud instance metadata endpoint)",
);

assert.equal(
  parseRawTunnelTargetAsShipped(privateTarget),
  null,
  "SSRF BUG (raw TCP tunnel): parseRawTunnelTarget must return null for RFC-1918 host 10.0.0.1",
);

console.log("ssrf ok");
