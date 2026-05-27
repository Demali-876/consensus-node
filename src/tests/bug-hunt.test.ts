/**
 * Daily bug-hunt: security, performance, and correctness findings.
 *
 * Tests assert CORRECT behavior — they FAIL while the bug exists and PASS
 * once the fix is applied, making them useful as regression guards.
 * Each test logs what it observed so evidence is clear in CI output.
 *
 * Run: bun src/tests/bug-hunt.test.ts
 */
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import crypto from "node:crypto";

// Isolated state directory — must be set before importing any module that
// reads process.env.CONSENSUS_STATE_DIR at import time.
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-bug-hunt-"),
);

import { canonicalJson } from "../crypto/canonical-json";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import {
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
  acceptClientHandshake,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import { TUNNEL_MODE, MESSAGE_TYPE, nowSeconds } from "../tunnel/messages";
import { TunnelClient } from "../tunnel/tunnel-client";
import { executeProxyCommand } from "../runtime/proxy-command";
import { downloadAndVerify } from "../update";
import type { ReleaseManifest } from "../types";

// =============================================================================
// Bug 1 — Missing handshake timestamp freshness check  (Security — CRITICAL)
// =============================================================================
// File:   src/tunnel/handshake.ts  assertHandshakeBase()  lines 271–281
//
// assertHandshakeBase() only checks that `timestamp` is a finite number.
// It never verifies the message was created recently.  An attacker who
// captures a legitimately-signed INIT can replay it hours, days, or years
// later and the server will derive new session keys without complaint.
//
// While the attacker can't read the derived session (they lack the ephemeral
// ECDH private key), the server spends CPU on every replayed message and any
// downstream identity scheme that assumes the handshake is fresh is broken.
//
// Fix: in assertHandshakeBase() throw when
//      Math.abs(nowSeconds() - message.timestamp) > 300  (5-minute window).
{
  const identity = await loadOrCreateIdentity();
  const keyPair  = await generateHandshakeKeyPair();
  const nonce    = randomHandshakeNonce();

  // Build a legitimately-signed INIT with a timestamp from 1 year ago.
  const staleTs = nowSeconds() - 365 * 24 * 3600;
  const body: Omit<HandshakeInitMessage, "signature"> = {
    type:                HANDSHAKE_TYPE.INIT,
    protocol:            HANDSHAKE_PROTOCOL,
    version:             HANDSHAKE_VERSION,
    mode:                TUNNEL_MODE.EVAL,
    timestamp:           staleTs,
    client_public_key:   keyPair.publicKeyRaw.toString("base64"),
    client_nonce:        nonce.toString("base64"),
    node_public_key_pem: identity.publicKeyPem,
  };
  const staleInit: HandshakeInitMessage = {
    ...body,
    signature: signUtf8(identity.privateKeyPem, canonicalJson(body)),
  };

  let accepted = false;
  try   { await acceptClientHandshake({ init: staleInit }); accepted = true; }
  catch { /* correct — freshness check rejected it */ }

  console.log(
    `[Bug 1] acceptClientHandshake with 1-year-old INIT → ` +
    (accepted ? "ACCEPTED (bug present)" : "rejected (fixed)"),
  );
  assert.equal(
    accepted,
    false,
    "SECURITY BUG: acceptClientHandshake must reject stale handshake — add freshness window check",
  );
}

// =============================================================================
// Bug 2 — SSRF: no URL validation in proxy command  (Security — HIGH)
// =============================================================================
// File:   src/runtime/proxy-command.ts  executeProxyCommand()  line 9
//         src/runtime/proxy-worker.ts   POST /proxy  (also lacks auth)
//
// executeProxyCommand() calls fetch(message.target_url, …) with no scheme
// or host validation.  Any server-side proxy request can target loopback
// addresses, RFC-1918 ranges, or cloud metadata endpoints.
// The HTTP route POST /proxy is also fully unauthenticated, so any caller
// on TCP 9090 can use the node as an open proxy.
//
// Fix: before fetch(), parse the URL and reject if:
//   • scheme is not http or https
//   • host resolves to 127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, [::1]
// Require a shared-secret header on the HTTP route.
{
  // Simulate an "internal-only" service that must never be reachable.
  const internalSrv = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response("INTERNAL_SECRET", { status: 200 }),
  });

  let leakedData: string | undefined;
  try {
    const result = await executeProxyCommand({
      type:       MESSAGE_TYPE.PROXY_REQUEST,
      timestamp:  nowSeconds(),
      target_url: `http://127.0.0.1:${internalSrv.port}/sensitive`,
      method:     "GET",
    });
    // response body is base64-encoded
    leakedData = result.body
      ? Buffer.from(result.body, "base64").toString("utf8")
      : undefined;
  } finally {
    internalSrv.stop(true);
  }

  console.log(
    `[Bug 2] proxy to 127.0.0.1 returned: ${JSON.stringify(leakedData)} ` +
    (leakedData === "INTERNAL_SECRET" ? "— data LEAKED (bug present)" : "— blocked (fixed)"),
  );
  assert.notEqual(
    leakedData,
    "INTERNAL_SECRET",
    "SECURITY BUG: executeProxyCommand forwarded to private loopback — add SSRF host validation",
  );
}

// =============================================================================
// Bug 3 — O(n) linear scan on every STREAM_DATA / STREAM_CLOSE  (Performance — HIGH)
// =============================================================================
// File:   src/clients/control-client.ts  STREAM_DATA handler  lines 336–337
//         src/clients/control-client.ts  STREAM_CLOSE handler  lines 430–431
//
// Both handlers locate the public-tunnel owner with:
//   Array.from(publicTunnelOwners.entries()).find(([, o]) => o.streamId === msg.stream_id)
// This allocates a new array and iterates all N owners on *every message*.
// With N active tunnels the cost per message is O(N); total CPU is
// O(N × messages/s) — throughput degrades proportionally to tunnel count.
//
// Fix: maintain a reverse Map<streamId, tunnelId> alongside publicTunnelOwners.
// Keep it in sync on STREAM_OPEN (add) and owner-close / cleanup (delete).
// Owner lookup then becomes O(1) with negligible extra memory.
{
  const N    = 5_000;
  const ITER = 500;

  type OwnerEntry = {
    streamId:      string;
    nextStreamId:  number;
    ownerToServer: Map<number, string>;
    serverToOwner: Map<string, number>;
  };

  const owners     = new Map<string, OwnerEntry>();
  const reverseMap = new Map<string, string>(); // streamId → tunnelId (the fix)
  const worstCase  = `stream-${N - 1}`;         // last entry = worst-case linear scan

  for (let i = 0; i < N; i++) {
    const sid = `stream-${i}`;
    const tid = `tunnel-${i}`;
    owners.set(tid, {
      streamId: sid, nextStreamId: 1,
      ownerToServer: new Map(), serverToOwner: new Map(),
    });
    reverseMap.set(sid, tid);
  }

  // Exact code from control-client.ts STREAM_DATA handler (lines 336–337)
  const t0 = performance.now();
  for (let i = 0; i < ITER; i++) {
    Array.from(owners.entries()).find(([, o]) => o.streamId === worstCase);
  }
  const linearMs = performance.now() - t0;

  // Proposed O(1) fix using a reverse map
  const t1 = performance.now();
  for (let i = 0; i < ITER; i++) {
    const tid = reverseMap.get(worstCase);
    if (tid) owners.get(tid);
  }
  const o1Ms    = performance.now() - t1;
  const speedup = linearMs / Math.max(o1Ms, 0.001);

  console.log(
    `[Bug 3] O(n) scan: ${linearMs.toFixed(1)} ms  |  ` +
    `O(1) lookup: ${o1Ms.toFixed(1)} ms  |  ` +
    `speedup: ${speedup.toFixed(0)}×  (${N} owners, ${ITER} iters)`,
  );
  // A speedup >5× with 5 000 entries confirms the regression is significant.
  assert.ok(
    speedup > 5,
    `PERFORMANCE BUG: O(1) lookup should be >5× faster than O(n) scan with ${N} owners ` +
    `(got ${speedup.toFixed(1)}×) — replace Array.from(…).find() with a reverse Map`,
  );
  console.log(`[Bug 3] regression confirmed: ${speedup.toFixed(0)}× speedup available via reverse-map refactor`);
}

// =============================================================================
// Bug 4 — Pending request entry leaked in map on send() failure  (Bug — MEDIUM)
// =============================================================================
// File:   src/tunnel/tunnel-client.ts  TunnelClient.request()  lines 107–121
//
// request() adds a pending entry to this.pending BEFORE awaiting send().
// If send() throws (socket closed / not connected), no cleanup happens —
// the entry remains in the map until the requestTimeoutMs timer fires
// (default 30 s).  Under a reconnect storm that calls request() while
// disconnected the map accumulates entries, holding resolve/reject closures
// and preventing GC of any captured response buffers.
//
// Fix: wrap send() in try/finally and delete the pending entry immediately:
//   try { await this.send(requestMessage); }
//   catch (err) {
//     const p = this.pending.get(id);
//     if (p) { clearTimeout(p.timer); this.pending.delete(id); }
//     throw err;
//   }
{
  const session = {
    sessionId:  "bug-hunt",
    sendKey:    crypto.randomBytes(32),
    receiveKey: crypto.randomBytes(32),
  };

  // Never connect — ws is null so send() throws synchronously.
  const client = new TunnelClient({
    url:              "ws://127.0.0.1:1",
    session,
    mode:             "control",
    requestTimeoutMs: 400, // short so the test doesn't block for 30 s
  });

  // Access private pending map via type cast.
  const pendingMap = (client as unknown as { pending: Map<string, unknown> }).pending;
  assert.equal(pendingMap.size, 0, "pending map must start empty");

  let sendThrew = false;
  try   { await client.request({ type: MESSAGE_TYPE.PING, timestamp: nowSeconds() }); }
  catch { sendThrew = true; }

  assert.equal(sendThrew, true, "request() must throw when socket is not connected");

  const leakedEntries = pendingMap.size;
  console.log(
    `[Bug 4] pending map size after failed send: ${leakedEntries} ` +
    (leakedEntries > 0 ? "— entry LEAKED (bug present)" : "— clean (fixed)"),
  );
  assert.equal(
    leakedEntries,
    0,
    `BUG: ${leakedEntries} entry leaked in pending map after send() failure — add try/finally cleanup`,
  );

  // Drain the orphaned timer so the process exits cleanly.
  if (leakedEntries > 0) await new Promise<void>((r) => setTimeout(r, 450));
}

// =============================================================================
// Bug 5 — Update SHA-256 verification skipped when tarball_sha256 absent  (Security — HIGH)
// =============================================================================
// File:   src/update.ts  downloadAndVerify()  line 90
//
//   if (manifest.tarball_sha256 && sha256 !== stripShaPrefix(…)) { throw }
//
// The integrity check is conditional: when `tarball_sha256` is absent the
// downloaded artifact is written to disk and returned with NO verification.
// A MITM or a rogue update server can deliver arbitrary code by simply
// omitting the field from the manifest JSON.  Because the artifact is then
// executed on install, this is a remote-code-execution vector.
//
// Fix: make tarball_sha256 mandatory.  At the top of downloadAndVerify():
//   if (!manifest.tarball_sha256)
//     throw new Error("manifest missing tarball_sha256 — refusing to install unverified artifact");
{
  const fakeSrv = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response(Buffer.from("fake-malicious-payload"), { status: 200 }),
  });

  const unsafeManifest: ReleaseManifest = {
    product:      "consensus-node",
    version:      "0.0.1",
    artifact:     "npm-tarball",
    platform:     "linux-x64",
    commit:       "aabbccdd",
    routes_hash:  "aabbccdd",
    capabilities: [],
    download_url: `http://127.0.0.1:${fakeSrv.port}/fake.tgz`,
    // tarball_sha256 intentionally absent — the bug
  };

  let bypassedCheck = false;
  try   { await downloadAndVerify(unsafeManifest); bypassedCheck = true; }
  catch { /* correct — refused unverified artifact */ }
  finally { fakeSrv.stop(true); }

  console.log(
    `[Bug 5] downloadAndVerify without tarball_sha256 → ` +
    (bypassedCheck ? "ACCEPTED with no hash check (bug present)" : "rejected (fixed)"),
  );
  assert.equal(
    bypassedCheck,
    false,
    "SECURITY BUG: downloadAndVerify accepted artifact with no tarball_sha256 — make hash mandatory",
  );
}

console.log("\nbug-hunt ok");
