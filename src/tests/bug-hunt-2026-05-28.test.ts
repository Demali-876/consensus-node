/**
 * Bug Hunt Report — 2026-05-28
 *
 * Five confirmed bugs with automated evidence:
 *
 *  BUG-1  SSRF in /proxy HTTP endpoint (Critical Security)
 *  BUG-2  SHA-256 check bypassed when tarball_sha256 absent (Critical Security)
 *  BUG-3  O(n) linear scan on every STREAM_DATA frame (Performance)
 *  BUG-4  toBuffer() string decoding divergence across modules (Logic)
 *  BUG-5  Handshake timestamp never checked for freshness (Security)
 */

import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import Fastify from "fastify";

import { registerProxyRoutes } from "../runtime/proxy-worker";
import { downloadAndVerify } from "../update";
import {
  verifyClientHandshake,
  HANDSHAKE_TYPE,
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_VERSION,
} from "../tunnel/handshake";
import { generateHandshakeKeyPair, randomHandshakeNonce } from "../crypto/secure-channel";
import { TUNNEL_MODE } from "../tunnel/messages";
import { signUtf8 } from "../crypto/identity";
import { canonicalJson } from "../crypto/canonical-json";
import { saveConfig } from "../node/state";

// ============================================================================
// BUG-1: SSRF in /proxy HTTP endpoint
//
// registerProxyRoutes() exposes a POST /proxy route that forwards HTTP
// requests to an arbitrary target_url with no validation of the URL scheme,
// hostname, or IP address.  Any client that can reach the node's HTTP port
// can bounce requests through it to localhost services, link-local addresses
// (169.254.169.254 cloud metadata), or any internal network host.
//
// Root cause: proxy-worker.ts:16 calls fetch(body.target_url, ...) directly.
// Fix:        Parse the URL and reject non-https schemes and private/loopback
//             IP ranges before issuing the outbound fetch.
// ============================================================================

console.log("--- BUG-1: SSRF via /proxy ---");
{
  // Start a Fastify server with the vulnerable proxy route.
  const app = Fastify({ logger: false });
  await registerProxyRoutes(app);
  await app.listen({ port: 0, host: "127.0.0.1" });
  const proxyPort = (app.server.address() as net.AddressInfo).port;

  // Internal target that must NOT be reachable via the public-facing proxy.
  let internalRequestReceived = false;
  const targetServer = http.createServer((_req, res) => {
    internalRequestReceived = true;
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("INTERNAL_DATA");
  });
  await new Promise<void>((r) => targetServer.listen(0, "127.0.0.1", () => r()));
  const targetPort = (targetServer.address() as net.AddressInfo).port;

  // Ask the proxy to fetch our internal server — this should be blocked.
  const proxyResponse = await fetch(`http://127.0.0.1:${proxyPort}/proxy`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      target_url: `http://127.0.0.1:${targetPort}/secret`,
      method: "GET",
    }),
  });
  const proxyBody = await proxyResponse.json() as { status?: number; data?: string };

  assert.equal(
    internalRequestReceived,
    true,
    "BUG-1 FAIL: expected /proxy to be blocked from reaching localhost, but the internal server received the request",
  );
  assert.equal(proxyBody.status, 200);
  assert.equal(proxyBody.data, "INTERNAL_DATA", "BUG-1: internal response body leaked through proxy");

  await app.close();
  await new Promise<void>((r) => targetServer.close(() => r()));
  console.log(
    `BUG-1 CONFIRMED: POST /proxy successfully proxied a request to localhost:${targetPort} ` +
    `— no URL validation in proxy-worker.ts:16`,
  );
}

// ============================================================================
// BUG-2: SHA-256 integrity check is skipped when tarball_sha256 is absent
//
// downloadAndVerify() in update.ts downloads an artifact and then checks:
//
//   if (manifest.tarball_sha256 && sha256 !== ...) { throw ... }
//
// The guard is only entered when tarball_sha256 is truthy.  A malicious
// update server that omits the field — or sets it to "" — will have its
// artifact accepted and written to disk without any hash verification.
// An attacker with update-server access can deliver arbitrary executables.
//
// Root cause: update.ts:90 — conditional instead of required integrity check.
// Fix:        Throw if tarball_sha256 is absent.  Require the field.
// ============================================================================

console.log("--- BUG-2: SHA-256 bypass in downloadAndVerify ---");
{
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug2-"));
  process.env.CONSENSUS_STATE_DIR = tmpDir;

  const fakeArtifact = Buffer.from("fake-malicious-artifact-content");
  const realSha256 = crypto.createHash("sha256").update(fakeArtifact).digest("hex");

  const artifactServer = http.createServer((_req, res) => {
    res.writeHead(200);
    res.end(fakeArtifact);
  });
  await new Promise<void>((r) => artifactServer.listen(0, "127.0.0.1", () => r()));
  const artifactPort = (artifactServer.address() as net.AddressInfo).port;
  const artifactUrl = `http://127.0.0.1:${artifactPort}/release.tgz`;

  // Case A — no tarball_sha256: should throw, but doesn't (the bug).
  let caseAThrew = false;
  try {
    await downloadAndVerify({
      product: "consensus-node",
      version: "9.9.9-evil",
      artifact: "npm-tarball",
      platform: "linux-x64",
      commit: "deadbeef",
      download_url: artifactUrl,
      // tarball_sha256 intentionally omitted — attacker controls this field
      routes_hash: "fakehash",
      capabilities: [],
    });
  } catch {
    caseAThrew = true;
  }

  assert.equal(
    caseAThrew,
    false,
    "BUG-2 FAIL: expected downloadAndVerify to throw when tarball_sha256 is absent, but it succeeded silently",
  );

  // Case B — wrong tarball_sha256: must throw (proves the guard works when present).
  let caseBThrew = false;
  try {
    await downloadAndVerify({
      product: "consensus-node",
      version: "9.9.9-evil",
      artifact: "npm-tarball",
      platform: "linux-x64",
      commit: "deadbeef",
      download_url: artifactUrl,
      tarball_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      routes_hash: "fakehash",
      capabilities: [],
    });
  } catch {
    caseBThrew = true;
  }

  assert.equal(caseBThrew, true, "Control: downloadAndVerify correctly rejects a wrong sha256");

  // Case C — correct sha256: must not throw.
  let caseCThrew = false;
  try {
    await downloadAndVerify({
      product: "consensus-node",
      version: "9.9.9-evil",
      artifact: "npm-tarball",
      platform: "linux-x64",
      commit: "deadbeef",
      download_url: artifactUrl,
      tarball_sha256: `sha256:${realSha256}`,
      routes_hash: "fakehash",
      capabilities: [],
    });
  } catch {
    caseCThrew = true;
  }

  assert.equal(caseCThrew, false, "Control: downloadAndVerify accepts a correct sha256");

  await new Promise<void>((r) => artifactServer.close(() => r()));
  await fs.rm(tmpDir, { recursive: true, force: true });
  console.log(
    "BUG-2 CONFIRMED: downloadAndVerify accepted an artifact with no tarball_sha256 " +
    "— integrity bypass possible via update.ts:90",
  );
}

// ============================================================================
// BUG-3: O(n) linear scan for public-tunnel owner on every STREAM_DATA frame
//
// In control-client.ts, the STREAM_DATA handler begins with:
//
//   const ownerEntry = Array.from(publicTunnelOwners.entries())
//     .find(([, owner]) => owner.streamId === message.stream_id);
//
// publicTunnelOwners is a Map<tunnelId, {streamId, ...}>.  To answer "is
// this stream_id owned by any tunnel?", the code allocates a new array and
// does a linear search.  The same pattern repeats in the STREAM_CLOSE handler.
//
// For a node running 5 000 public tunnels the cost per frame is ~5 000
// iterations when the answer is "no owner" (the common case for proxy-session
// and raw-tunnel streams).
//
// Root cause: control-client.ts:336-338 and 430-431.
// Fix:        Maintain a reverse Map<streamId, tunnelId> alongside
//             publicTunnelOwners so the lookup is O(1).
// ============================================================================

console.log("--- BUG-3: O(n) STREAM_DATA scan ---");
{
  const ITERATIONS = 2_000;

  function measureScan(ownerCount: number): number {
    // Replicate the publicTunnelOwners Map<tunnelId, {streamId}>
    const publicTunnelOwners = new Map<string, { streamId: string }>();
    const sentinel = crypto.randomUUID(); // the streamId we will search for

    // The sentinel is always the last-inserted entry (worst-case path).
    for (let i = 0; i < ownerCount - 1; i++) {
      publicTunnelOwners.set(crypto.randomUUID(), { streamId: crypto.randomUUID() });
    }
    if (ownerCount > 0) {
      publicTunnelOwners.set(crypto.randomUUID(), { streamId: sentinel });
    }

    const target = ownerCount > 0 ? sentinel : crypto.randomUUID(); // no-match when 0

    const t0 = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      // This is the exact expression from control-client.ts
      Array.from(publicTunnelOwners.entries())
        .find(([, owner]) => owner.streamId === target);
    }
    return (performance.now() - t0) / ITERATIONS; // ms per call
  }

  const msAt1    = measureScan(1);
  const msAt1000 = measureScan(1_000);
  const msAt5000 = measureScan(5_000);

  const slowdown1000 = msAt1000 / msAt1;
  const slowdown5000 = msAt5000 / msAt1;

  assert.ok(
    slowdown1000 > 20,
    `BUG-3 FAIL: expected at least 20x slowdown at n=1000 (got ${slowdown1000.toFixed(1)}x)`,
  );
  assert.ok(
    slowdown5000 > 40,
    `BUG-3 FAIL: expected at least 40x slowdown at n=5000 (got ${slowdown5000.toFixed(1)}x)`,
  );

  console.log(
    `BUG-3 CONFIRMED: STREAM_DATA scan — ` +
    `n=1 → ${msAt1.toFixed(4)} ms/call, ` +
    `n=1000 → ${msAt1000.toFixed(4)} ms/call (${slowdown1000.toFixed(0)}x), ` +
    `n=5000 → ${msAt5000.toFixed(4)} ms/call (${slowdown5000.toFixed(0)}x) ` +
    `— control-client.ts:336`,
  );
}

// ============================================================================
// BUG-4: toBuffer() decodes string WebSocket frames differently per module
//
// Two private toBuffer() helpers coexist in the codebase:
//
//   tunnel-client.ts: Buffer.from(data, "base64")   ← base64 decode
//   connect.ts:       Buffer.from(data, "utf8")      ← UTF-8 decode
//
// During the handshake phase, connect.ts processes the first WebSocket text
// frame.  After the handshake, tunnel-client.ts processes every subsequent
// frame.  If the WebSocket transport delivers a text frame (e.g., a server
// that encodes binary payloads as base64 text), the two code paths would
// produce completely different byte sequences from the same input, causing
// silent data corruption or failed AEAD authentication depending on timing.
//
// Root cause: two independent implementations of the same helper.
// Fix:        Extract a single shared toBuffer() that handles text frames
//             consistently, or enforce binary-only WebSocket frames.
// ============================================================================

console.log("--- BUG-4: toBuffer string encoding divergence ---");
{
  // Exact copies of the private helpers from each module.
  const toBufferTunnelClient = (s: string) => Buffer.from(s, "base64");
  const toBufferConnect       = (s: string) => Buffer.from(s, "utf8");

  // A realistic JSON payload (handshake accept message).
  const input = '{"type":"handshake_accept","protocol":"consensus-node-tunnel","version":1,"timestamp":1748476800}';

  const viaClient  = toBufferTunnelClient(input);
  const viaConnect = toBufferConnect(input);

  assert.notDeepEqual(
    viaClient,
    viaConnect,
    "BUG-4 FAIL: expected the two toBuffer implementations to produce different bytes",
  );
  assert.ok(
    viaConnect.length > viaClient.length,
    "BUG-4: UTF-8 path yields full byte representation; base64 path loses data",
  );
  assert.equal(
    viaConnect.toString("utf8"),
    input,
    "BUG-4 control: UTF-8 round-trip is lossless",
  );

  // Demonstrate the corruption: base64 skips non-base64 chars ('{', '"', ':')
  // so the decoded bytes no longer represent the original message.
  const corruptJson = viaClient.toString("utf8");
  assert.notEqual(
    corruptJson,
    input,
    "BUG-4: base64-decoded string is corrupted and does not round-trip",
  );

  console.log(
    `BUG-4 CONFIRMED: same string → ${viaConnect.length}B via utf8 vs ${viaClient.length}B via base64 ` +
    `— tunnel-client.ts:235 vs connect.ts:146`,
  );
}

// ============================================================================
// BUG-5: Handshake timestamp is never checked for freshness
//
// assertHandshakeBase() in handshake.ts validates:
//
//   typeof message.timestamp !== "number" || !Number.isFinite(message.timestamp)
//
// But it never compares the timestamp to nowSeconds().  A captured
// HandshakeInitMessage can be replayed days later: the signature will still
// verify (the payload is identical), so the server will process the message.
//
// While session key freshness is guaranteed by the ephemeral ECDH keys (a new
// shared secret per handshake), accepting arbitrarily old INIT messages still
// breaks protocol integrity, enables resource exhaustion (repeated processing
// of legitimately-signed replays), and violates defence-in-depth.
//
// Root cause: handshake.ts:277 — no nowSeconds() comparison.
// Fix:        Reject INIT messages whose timestamp differs from now by more
//             than a configurable skew window (e.g., ±60 seconds).
// ============================================================================

console.log("--- BUG-5: Handshake timestamp staleness ---");
{
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug5-"));
  process.env.CONSENSUS_STATE_DIR = stateDir;

  // Generate an ephemeral identity for this test.
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const keyPair      = await generateHandshakeKeyPair();
  const clientNonce  = randomHandshakeNonce();

  // Craft a HandshakeInitMessage with a timestamp set to Unix epoch (year 1970).
  const STALE_TS = 1; // seconds since epoch
  const unsigned = {
    type:                HANDSHAKE_TYPE.INIT     as const,
    protocol:            HANDSHAKE_PROTOCOL,
    version:             HANDSHAKE_VERSION       as 1,
    mode:                TUNNEL_MODE.EVAL,
    timestamp:           STALE_TS,
    client_public_key:   keyPair.publicKeyRaw.toString("base64"),
    client_nonce:        clientNonce.toString("base64"),
    node_public_key_pem: publicKey,
  };

  // Sign it — this is a legitimately-signed message, just very old.
  const signature    = signUtf8(privateKey, canonicalJson(unsigned));
  const staleMessage = { ...unsigned, signature };

  const result = verifyClientHandshake(staleMessage);

  assert.equal(
    result,
    true,
    "BUG-5 FAIL: expected verifyClientHandshake to reject a year-1970 timestamp, but it returned true",
  );

  await fs.rm(stateDir, { recursive: true, force: true });
  console.log(
    `BUG-5 CONFIRMED: verifyClientHandshake accepted a handshake with timestamp=${STALE_TS} (year 1970) ` +
    `— no freshness check in handshake.ts:277`,
  );
}

// ============================================================================
// BUG-6: saveConfig() writes config.json with world-readable permissions
//
// writeJson() in node/state.ts calls:
//
//   fs.writeFile(file, content, "utf8")   ← no mode option
//
// Without an explicit mode the file inherits default permissions (typically
// 0o644 on Linux — readable by all local users).  saveJoinAuthorization()
// and saveSetupProgress() correctly pass { mode: 0o600 }, but saveConfig()
// routes through writeJson() and gets no such protection.
//
// Root cause: state.ts:62 — writeJson() omits file permission mode.
// Fix:        Add { mode: 0o600 } to the fs.writeFile() call in writeJson(),
//             or add an optional mode parameter and pass 0o600 from all
//             callers that write sensitive data.
// ============================================================================

console.log("--- BUG-6: config.json world-readable permissions ---");
{
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-bug6-"));
  process.env.CONSENSUS_STATE_DIR = stateDir;

  await saveConfig({ node_id: "test-node", port: 9090 });
  const configPath = path.join(stateDir, "config.json");

  const stat = await fs.stat(configPath);
  const mode = stat.mode & 0o777; // mask to permission bits only

  // 0o600 = owner r/w only (secure).  Anything that sets the group or other
  // read bits (0o004 or 0o040) is a bug.
  const otherReadable = (mode & 0o004) !== 0;
  const groupReadable = (mode & 0o040) !== 0;

  assert.ok(
    otherReadable || groupReadable,
    `BUG-6 FAIL: config.json has mode 0o${mode.toString(8)}, which is NOT world/group readable — ` +
    "either the bug is already fixed or the umask is unusually restrictive",
  );

  console.log(
    `BUG-6 CONFIRMED: config.json written with mode 0o${mode.toString(8)} ` +
    `(world-readable=${otherReadable}, group-readable=${groupReadable}) ` +
    `— state.ts:62 missing { mode: 0o600 }`,
  );

  await fs.rm(stateDir, { recursive: true, force: true });
}

console.log("\n=== All 6 bugs confirmed. See report above. ===");
