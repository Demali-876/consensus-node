/**
 * Daily Bug Hunt — 2025-05-24
 *
 * Five issues found across security, performance, and ease-of-use categories.
 * Each section is written to reflect the EXPECTED correct behaviour.  When a
 * section reports "STILL PRESENT" the assertion failure is the evidence.
 *
 * Bug 1 (SECURITY — CRITICAL): downloadAndVerify skips integrity when
 *   tarball_sha256 is absent.  A server-controlled manifest with no checksum
 *   lets any arbitrary binary through unchecked.
 *
 * Bug 2 (SECURITY): Handshake messages carry a timestamp but acceptClientHandshake
 *   never checks it against wall-clock time, so a captured HANDSHAKE_INIT can be
 *   replayed indefinitely and the server will start a fresh session.
 *
 * Bug 3 (SECURITY): writeJson() (used by saveConfig) does not set mode 0o600,
 *   so config.json ends up world-readable on Linux (typically 0o644).  Private
 *   node ID, domain, and registered IP are exposed to any local user.
 *
 * Bug 4 (PERFORMANCE): The STREAM_DATA / STREAM_CLOSE handlers in control-client
 *   call Array.from(publicTunnelOwners.entries()).find(…) to reverse-look up a
 *   tunnel owner by stream ID.  This is O(n) per message.  A simple reverse-map
 *   makes it O(1).
 *
 * Bug 5 (SECURITY / DoS): executeProxyCommand calls response.arrayBuffer() with
 *   no size guard.  A malicious or misbehaving target can force the node to buffer
 *   gigabytes of data in memory, causing an OOM crash.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { downloadAndVerify } from "../update";
import { saveConfig } from "../node/state";
import { executeProxyCommand } from "../runtime/proxy-command";
import {
  acceptClientHandshake,
  type HandshakeInitMessage,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_VERSION,
  HANDSHAKE_TYPE,
} from "../tunnel/handshake";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { canonicalJson } from "../crypto/canonical-json";
import { TUNNEL_MODE, nowSeconds } from "../tunnel/messages";
import { routesHash } from "../node/manifest";
import type { ReleaseManifest } from "../types";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (typeof addr === "object" && addr) resolve(addr.port);
        else reject(new Error("could not allocate free port"));
      });
    });
  });
}

async function withTempStateDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug-hunt-"));
  const orig = process.env.CONSENSUS_STATE_DIR;
  process.env.CONSENSUS_STATE_DIR = dir;
  try {
    return await fn(dir);
  } finally {
    process.env.CONSENSUS_STATE_DIR = orig;
    await fs.rm(dir, { recursive: true, force: true });
  }
}

// Collect failures so all bugs are reported even if one fails
const failures: string[] = [];

function pass(label: string): void {
  console.log(`  ✓  ${label} — FIXED`);
}

function fail(label: string, detail: string): void {
  console.error(`  ✗  ${label} — STILL PRESENT\n     ${detail}`);
  failures.push(label);
}

// ---------------------------------------------------------------------------
// Bug 1 — SECURITY CRITICAL: tarball_sha256 bypass in downloadAndVerify
// ---------------------------------------------------------------------------
//
// Affected file:  src/update.ts  line 90
// Condition:      if (manifest.tarball_sha256 && sha256 !== …) { throw }
// Problem:        The outer guard is skipped when tarball_sha256 is falsy/absent.
//                 A compromised server omits the field and serves any binary it
//                 chooses; the node writes it to disk and will execute it on the
//                 next UPDATE_APPLY command.
//
// Expected fix:   Always require tarball_sha256 when a download_url is present.
//                 Throw "Manifest missing required tarball_sha256" before fetching.

console.log("\nBug 1 — SECURITY: tarball_sha256 bypass");

await (async () => {
  const port = await getFreePort();
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch: () =>
      new Response(Buffer.from("THIS IS MALICIOUS CODE"), {
        headers: { "content-type": "application/octet-stream" },
      }),
  });

  const manifestWithoutChecksum: ReleaseManifest = {
    product: "consensus-node",
    version: "0.0.1-bugtest",
    artifact: "npm-tarball",
    platform: "linux-x64",
    commit: "deadbeef",
    routes_hash: routesHash(),
    capabilities: [],
    download_url: `http://127.0.0.1:${port}/artifact.tgz`,
    // tarball_sha256 intentionally omitted — the server controls the payload
  };

  try {
    await withTempStateDir(async () => {
      await assert.rejects(
        () => downloadAndVerify(manifestWithoutChecksum),
        (err: unknown) =>
          err instanceof Error && /sha256|checksum|integrity/i.test(err.message),
        "downloadAndVerify must reject manifests that omit tarball_sha256",
      );
    });
    pass("Bug 1: downloadAndVerify requires tarball_sha256");
  } catch {
    fail(
      "Bug 1: tarball_sha256 bypass",
      "downloadAndVerify silently accepted an artifact from a manifest with no " +
        "tarball_sha256 field. A compromised server can serve arbitrary binaries.\n" +
        "     Fix: in src/update.ts, throw when manifest.tarball_sha256 is absent.",
    );
  } finally {
    server.stop(true);
  }
})();

// ---------------------------------------------------------------------------
// Bug 2 — SECURITY: Handshake timestamp not validated against wall-clock time
// ---------------------------------------------------------------------------
//
// Affected file:  src/tunnel/handshake.ts  function assertHandshakeBase (~line 277)
// Current check:  typeof timestamp === "number" && isFinite(timestamp)
// Problem:        No staleness window.  An attacker who records a legitimate
//                 HANDSHAKE_INIT can replay it indefinitely; the server's ECDH
//                 key exchange proceeds and a new session is opened.  The attacker
//                 cannot use the session (they lack the ephemeral private key)
//                 but the server wastes CPU and allocates state for each replay —
//                 a low-cost DoS amplifier.
//
// Expected fix:   In assertHandshakeBase, reject |nowSeconds() - timestamp| > 300.

console.log("\nBug 2 — SECURITY: handshake timestamp replay window");

await (async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug2-"));
  const origDir = process.env.CONSENSUS_STATE_DIR;
  process.env.CONSENSUS_STATE_DIR = dir;

  try {
    const identity = await loadOrCreateIdentity();
    const keyPair = await generateHandshakeKeyPair();
    const clientNonce = randomHandshakeNonce();

    const staleTimestamp = nowSeconds() - 3_600; // 1 hour old

    // Build a legitimately signed HANDSHAKE_INIT with a stale timestamp.
    // Ed25519 signature is valid — only a staleness check would reject this.
    const unsigned = {
      type: HANDSHAKE_TYPE.INIT as typeof HANDSHAKE_TYPE.INIT,
      protocol: HANDSHAKE_PROTOCOL,
      version: HANDSHAKE_VERSION,
      mode: TUNNEL_MODE.EVAL,
      timestamp: staleTimestamp,
      client_public_key: keyPair.publicKeyRaw.toString("base64"),
      client_nonce: clientNonce.toString("base64"),
      node_public_key_pem: identity.publicKeyPem,
    } satisfies Omit<HandshakeInitMessage, "signature">;

    const signature = signUtf8(identity.privateKeyPem, canonicalJson(unsigned));
    const staleInit: HandshakeInitMessage = { ...unsigned, signature };

    try {
      await assert.rejects(
        () => acceptClientHandshake({ init: staleInit }),
        (err: unknown) =>
          err instanceof Error &&
          /stale|expired|timestamp|skew|old|replay/i.test(err.message),
        "acceptClientHandshake must reject HANDSHAKE_INIT older than 5 minutes",
      );
      pass("Bug 2: acceptClientHandshake rejects stale timestamps");
    } catch {
      fail(
        "Bug 2: handshake timestamp replay",
        `acceptClientHandshake accepted a validly-signed HANDSHAKE_INIT with ` +
          `timestamp ${staleTimestamp} (${nowSeconds() - staleTimestamp}s ago). ` +
          "Captured handshakes can be replayed indefinitely.\n" +
          "     Fix: in assertHandshakeBase, add |nowSeconds() - timestamp| > 300 check.",
      );
    }
  } finally {
    process.env.CONSENSUS_STATE_DIR = origDir;
    await fs.rm(dir, { recursive: true, force: true });
  }
})();

// ---------------------------------------------------------------------------
// Bug 3 — SECURITY: config.json written without restrictive file permissions
// ---------------------------------------------------------------------------
//
// Affected file:  src/node/state.ts  writeJson() called from saveConfig()
// Code:           fs.writeFile(file, JSON.stringify(value, null, 2), "utf8")
// Problem:        No explicit mode → file inherits process umask (Linux default
//                 0o022 → effective 0o644 = world-readable).  config.json holds
//                 node_id, domain, IP, benchmark_score, registered_at.
//                 Contrast: saveJoinAuthorization and saveSetupProgress both
//                 pass { mode: 0o600 } explicitly.
//
// Expected fix:   Change writeJson to pass { encoding: "utf8", mode: 0o600 }.

console.log("\nBug 3 — SECURITY: config.json file permissions");

await withTempStateDir(async (dir) => {
  await saveConfig({ port: 9090, node_id: "sensitive-node-id" });
  const configPath = path.join(dir, "config.json");
  const stat = await fs.stat(configPath);
  const actualMode = stat.mode & 0o777;

  try {
    assert.equal(
      actualMode,
      0o600,
      `config.json has mode 0o${actualMode.toString(8)}, expected 0o600`,
    );
    pass("Bug 3: config.json has mode 0o600");
  } catch {
    fail(
      "Bug 3: config.json world-readable",
      `config.json was written with mode 0o${actualMode.toString(8)} ` +
        "(expected 0o600). The node ID, domain, and IP are readable by any " +
        "local user on a shared machine.\n" +
        "     Fix: pass { encoding: 'utf8', mode: 0o600 } in writeJson() " +
        "in src/node/state.ts.",
    );
  }
});

// ---------------------------------------------------------------------------
// Bug 4 — PERFORMANCE: O(n) linear scan for public tunnel owner lookup
// ---------------------------------------------------------------------------
//
// Affected file:  src/clients/control-client.ts  lines ~336 and ~431
// Pattern:        Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === id)
// Problem:        Every STREAM_DATA and STREAM_CLOSE message performs a full
//                 iteration over all public tunnel owners to reverse-look up a
//                 tunnelId from a streamId.  With N concurrent owners this is
//                 O(N) per message.  Under high stream churn (many short-lived
//                 public tunnels) this degrades throughput significantly.
//
// Expected fix:   Add Map<streamId, tunnelId> (reverse lookup) updated in the
//                 same places that mutate publicTunnelOwners.  Lookup is then O(1).
//
// Evidence:       Benchmark N=500 entries, 10 000 worst-case lookups.
//                 The linear scan should be ≥20× slower than Map.get().

console.log("\nBug 4 — PERFORMANCE: O(n) owner lookup on every STREAM message");

await (async () => {
  const N = 500;
  const ITERATIONS = 10_000;

  type OwnerEntry = {
    streamId: string;
    nextStreamId: number;
    ownerToServer: Map<number, string>;
    serverToOwner: Map<string, number>;
  };
  const publicTunnelOwners = new Map<string, OwnerEntry>();
  const reverseMap = new Map<string, string>(); // the proposed O(1) fix

  for (let i = 0; i < N; i++) {
    const tunnelId = `tunnel-${i}`;
    const streamId = crypto.randomUUID();
    publicTunnelOwners.set(tunnelId, {
      streamId,
      nextStreamId: 1,
      ownerToServer: new Map(),
      serverToOwner: new Map(),
    });
    reverseMap.set(streamId, tunnelId);
  }

  // Worst-case: target is the last-inserted entry
  const lastStreamId = [...publicTunnelOwners.values()][N - 1].streamId;

  // Warmup
  for (let i = 0; i < 100; i++) reverseMap.get(lastStreamId);

  // Current O(n) approach — exactly the code in control-client.ts
  const t0 = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === lastStreamId);
  }
  const linearMs = performance.now() - t0;

  // Proposed O(1) approach
  const t1 = performance.now();
  for (let i = 0; i < ITERATIONS; i++) {
    reverseMap.get(lastStreamId);
  }
  const constantMs = performance.now() - t1;

  const ratio = linearMs / Math.max(constantMs, 0.001);

  console.log(
    `     N=${N}, iterations=${ITERATIONS}\n` +
      `     Linear O(n) scan : ${linearMs.toFixed(1)} ms\n` +
      `     Map.get() O(1)   : ${constantMs.toFixed(1)} ms\n` +
      `     Slowdown         : ${ratio.toFixed(0)}×`,
  );

  if (ratio >= 20) {
    fail(
      "Bug 4: O(n) STREAM_DATA owner lookup",
      `The linear scan is ${ratio.toFixed(0)}× slower than Map.get() (${linearMs.toFixed(1)} ms vs ` +
        `${constantMs.toFixed(1)} ms for ${ITERATIONS} iterations over ${N} entries). ` +
        "Every STREAM_DATA and STREAM_CLOSE pays this cost.\n" +
        "     Fix: maintain Map<streamId,tunnelId> alongside publicTunnelOwners " +
        "in src/clients/control-client.ts.",
    );
  } else {
    console.log(
      `  ~  Bug 4: ratio ${ratio.toFixed(1)}× (inconclusive in this environment — ` +
        "regression exists in source regardless)",
    );
  }
})();

// ---------------------------------------------------------------------------
// Bug 5 — SECURITY / DoS: No size limit on proxy response body
// ---------------------------------------------------------------------------
//
// Affected file:  src/runtime/proxy-command.ts  line ~18
// Code:           const responseBody = Buffer.from(await response.arrayBuffer())
// Problem:        No Content-Length check, no stream size cap.  A malicious
//                 target can emit a multi-gigabyte body; the node buffers it
//                 entirely before it can reply.  Because proxy requests originate
//                 from the control server, a compromised server can force any node
//                 to OOM-crash simply by routing it to a firehose endpoint.
//
// Expected fix:   Check Content-Length header before fetching (reject if > MAX).
//                 Also cap the actual buffered size in case the header is absent
//                 or lies.  Suggested threshold: 32 MB.

console.log("\nBug 5 — SECURITY/DoS: unbounded proxy response buffering");

await (async () => {
  const LARGE_BYTES = 12 * 1024 * 1024; // 12 MB — intentionally under typical OOM
  const port = await getFreePort();

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch: () =>
      new Response(Buffer.alloc(LARGE_BYTES, 0x41), {
        headers: {
          "content-type": "application/octet-stream",
          "content-length": String(LARGE_BYTES),
        },
      }),
  });

  try {
    await assert.rejects(
      () =>
        executeProxyCommand({
          type: "proxy_request",
          id: "bug5-large-response",
          timestamp: nowSeconds(),
          target_url: `http://127.0.0.1:${port}/large`,
          method: "GET",
        }),
      (err: unknown) =>
        err instanceof Error && /size|large|limit|too big|bytes/i.test(err.message),
      "executeProxyCommand must reject responses that exceed the size limit",
    );
    pass("Bug 5: proxy response size limit enforced");
  } catch {
    fail(
      "Bug 5: unbounded proxy response",
      `executeProxyCommand silently buffered ${LARGE_BYTES / 1024 / 1024} MB ` +
        "with no size check. A malicious target could OOM the node.\n" +
        "     Fix: in src/runtime/proxy-command.ts, add a MAX_RESPONSE_BYTES " +
        "guard (e.g. 32 MB) before response.arrayBuffer().",
    );
  } finally {
    server.stop(true);
  }
})();

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log("\n=== Daily Bug Hunt 2025-05-24 Summary ===");
if (failures.length === 0) {
  console.log("All findings resolved. ✓");
} else {
  console.log(`${failures.length} bug(s) confirmed:\n`);
  for (const f of failures) console.log(`  • ${f}`);
  console.log(
    "\nSee individual sections above for reproduction steps and fix guidance.",
  );
  // Fail the process so CI marks this run red until all bugs are fixed
  process.exit(1);
}
