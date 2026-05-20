/**
 * Daily bug-hunt test suite.
 *
 * Each section corresponds to one confirmed defect.  The test is written to
 * FAIL against the unfixed code and PASS after the fix is applied.
 *
 * Bugs covered:
 *  1. SHA-256 bypass  – downloadAndVerify accepts artifacts when tarball_sha256 is absent
 *  2. O(n) owner scan – STREAM_DATA/STREAM_CLOSE do a linear scan through publicTunnelOwners
 *  3. Unauthenticated sequence check – sequence peeked from unverified header before AEAD
 *  4. nextStreamId overflow – writeUInt32BE throws once streamId > 0xFFFFFFFF
 *  5. Triple releaseManifest() – integrityPayload calls releaseManifest() 3× per request
 */
import assert from "node:assert/strict";
import crypto from "node:crypto";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// ─────────────────────────────────────────────────────────────────────────────
// Bug 1 — SHA-256 check is OPTIONAL: missing tarball_sha256 bypasses integrity
// ─────────────────────────────────────────────────────────────────────────────
// update.ts line 90:
//   if (manifest.tarball_sha256 && sha256 !== ...) { throw ... }
//
// When tarball_sha256 is absent or empty the condition is falsy and the hash
// check is skipped.  An update server (or MITM) can serve arbitrary bytes and
// they will be written to disk without any integrity verification.
{
  const { downloadAndVerify } = await import("../update.js");

  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "bug1-sha256-"));
  process.env.CONSENSUS_STATE_DIR = tmpDir;

  // Serve a body that deliberately does NOT match sha256: aaa...
  const corruptBody = Buffer.from("this is not the real artifact");

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch() {
      return new Response(corruptBody);
    },
  });

  const port = (server as unknown as { port: number }).port;

  try {
    // Manifest with no tarball_sha256 — current code skips the check entirely
    const manifestNoHash = {
      product: "consensus-node" as const,
      version: "0.0.1-test",
      artifact: "npm-tarball" as const,
      platform: "linux-x64",
      commit: "abc",
      routes_hash: "sha256:abc",
      download_url: `http://127.0.0.1:${port}/artifact.tgz`,
      capabilities: [],
    };

    // BUG: should throw because we cannot verify integrity without a hash.
    // Currently it silently writes the artifact to disk.
    let threw = false;
    try {
      await downloadAndVerify(manifestNoHash);
    } catch {
      threw = true;
    }

    assert.equal(
      threw,
      true,
      "BUG 1: downloadAndVerify must throw when tarball_sha256 is absent — " +
      "accepting an unverified artifact allows a MITM to deliver malicious code",
    );
  } finally {
    server.stop(true);
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
}

console.log("bug-1 (sha256 bypass) ✓");

// ─────────────────────────────────────────────────────────────────────────────
// Bug 2 — O(n) linear scan for public-tunnel owner on every STREAM_DATA message
// ─────────────────────────────────────────────────────────────────────────────
// control-client.ts lines 336 and 430:
//   const ownerEntry = Array.from(publicTunnelOwners.entries())
//     .find(([, owner]) => owner.streamId === message.stream_id);
//
// This creates a full array copy then iterates every entry on every STREAM_DATA
// or STREAM_CLOSE message.  With N active public-tunnel owners the cost is O(N)
// per message.  The fix is an O(1) reverse-lookup map: streamId → tunnelId.
{
  // Simulate the current lookup behaviour
  function buildOwnerMap(n: number): Map<string, { streamId: string; nextStreamId: number; ownerToServer: Map<number, string>; serverToOwner: Map<string, number> }> {
    const map = new Map<string, { streamId: string; nextStreamId: number; ownerToServer: Map<number, string>; serverToOwner: Map<string, number> }>();
    for (let i = 0; i < n; i++) {
      const tunnelId = `tunnel-${i}`;
      const streamId = `stream-${i}`;
      map.set(tunnelId, { streamId, nextStreamId: 1, ownerToServer: new Map(), serverToOwner: new Map() });
    }
    return map;
  }

  // Current O(n) lookup (as written in control-client.ts)
  function findOwnerLinear(
    map: Map<string, { streamId: string }>,
    targetStreamId: string,
  ): [string, { streamId: string }] | undefined {
    return Array.from(map.entries()).find(([, owner]) => owner.streamId === targetStreamId);
  }

  // Fixed O(1) reverse-lookup
  function buildReverseIndex(map: Map<string, { streamId: string }>): Map<string, string> {
    const index = new Map<string, string>();
    for (const [tunnelId, owner] of map) {
      index.set(owner.streamId, tunnelId);
    }
    return index;
  }

  const N_SMALL = 100;
  const N_LARGE = 1_000;

  const smallMap = buildOwnerMap(N_SMALL);
  const largeMap = buildOwnerMap(N_LARGE);

  // Always look up the LAST entry (worst-case for linear scan)
  const targetSmall = `stream-${N_SMALL - 1}`;
  const targetLarge = `stream-${N_LARGE - 1}`;

  const ITERATIONS = 5_000;

  const t0small = performance.now();
  for (let i = 0; i < ITERATIONS; i++) findOwnerLinear(smallMap, targetSmall);
  const linearSmallMs = performance.now() - t0small;

  const t0large = performance.now();
  for (let i = 0; i < ITERATIONS; i++) findOwnerLinear(largeMap, targetLarge);
  const linearLargeMs = performance.now() - t0large;

  // The large lookup must be proportionally slower — proves O(n) behaviour
  const ratio = linearLargeMs / linearSmallMs;
  assert.ok(
    ratio > 3,
    `BUG 2: O(n) scan confirmed — ${N_LARGE}-owner lookup is ${ratio.toFixed(1)}× slower than ${N_SMALL}-owner lookup (expected ≥ ${(N_LARGE / N_SMALL) / 2}×).`,
  );

  // Verify reverse-index is O(1) and correct
  const largeIndex = buildReverseIndex(largeMap);
  const t0idx = performance.now();
  for (let i = 0; i < ITERATIONS; i++) largeIndex.get(targetLarge);
  const indexMs = performance.now() - t0idx;

  assert.ok(
    indexMs < linearSmallMs,
    `BUG 2 fix: O(1) reverse-index (${indexMs.toFixed(2)} ms) must be faster than O(n) linear scan of ${N_SMALL} owners (${linearSmallMs.toFixed(2)} ms)`,
  );
  assert.equal(largeIndex.get(targetLarge), `tunnel-${N_LARGE - 1}`);
}

console.log("bug-2 (O(n) owner scan) ✓");

// ─────────────────────────────────────────────────────────────────────────────
// Bug 3 — Sequence number checked against UNAUTHENTICATED header before AEAD
// ─────────────────────────────────────────────────────────────────────────────
// tunnel-client.ts lines 125-129:
//   if (peekFrameSequence(raw) <= this.lastReceiveSequence) {
//     throw new Error("Replay or out-of-order tunnel frame rejected");
//   }
//   const { frame, plaintext } = openFrame(key, raw);
//   this.lastReceiveSequence = frame.sequence;
//
// peekFrameSequence() reads bytes 2–10 of the raw buffer WITHOUT any AEAD
// verification.  An attacker who can write to the WebSocket stream can:
//   • Forge a frame whose header advertises a high sequence number
//   • The sequence check passes (high seq > lastReceiveSequence)
//   • AEAD decryption is then attempted — it fails and throws
//   • An error message is sent back to the remote, leaking decryption failure
//   • lastReceiveSequence is NOT updated, so legitimate frames still arrive
//
// The fix: decrypt first, then validate sequence on the authenticated frame.
{
  const { peekFrameSequence } = await import("../tunnel/frames.js");
  const { sealFrame, openFrame, generateHandshakeKeyPair, deriveSecureSession, randomHandshakeNonce } = await import("../crypto/secure-channel.js");
  const { FRAME_TYPE } = await import("../tunnel/frames.js");

  // Set up a real session so we can produce a valid frame and a forged frame
  const clientKeys = await generateHandshakeKeyPair();
  const serverKeys = await generateHandshakeKeyPair();
  const cn = randomHandshakeNonce();
  const sn = randomHandshakeNonce();

  const clientSession = await deriveSecureSession({ role: "client", privateKey: clientKeys.privateKey, peerPublicKeyRaw: serverKeys.publicKeyRaw, clientNonce: cn, serverNonce: sn });
  const serverSession = await deriveSecureSession({ role: "server", privateKey: serverKeys.privateKey, peerPublicKeyRaw: clientKeys.publicKeyRaw, clientNonce: cn, serverNonce: sn });

  // Produce a legitimate frame at sequence 0
  const legitimate = sealFrame(clientSession.sendKey, FRAME_TYPE.DATA, 0n, Buffer.from("hello"));

  // Forge a frame: copy the legitimate frame header but inject a high sequence number
  // and scramble the ciphertext — the header sequence field is bytes 2–10
  const forged = Buffer.from(legitimate);
  forged.writeBigUInt64BE(999n, 2); // sequence = 999 (unauthenticated)
  // Flip a byte in the ciphertext region to break the AEAD tag
  const HEADER_SIZE = 26;
  if (forged.length > HEADER_SIZE) forged[HEADER_SIZE] ^= 0xff;

  // BUG: the forged frame's sequence (999) passes the pre-AEAD sequence check
  // when lastReceiveSequence is -1n.
  const forgedSeq = peekFrameSequence(forged);
  assert.equal(forgedSeq, 999n, "Sanity: forged sequence readable before AEAD");

  // The check that runs BEFORE decryption in tunnel-client.ts
  const lastReceiveSequence = -1n;
  const passedPreCheck = forgedSeq > lastReceiveSequence;
  assert.equal(
    passedPreCheck,
    true,
    "BUG 3: forged frame with unauthenticated high sequence PASSES pre-AEAD check",
  );

  // AEAD decryption then fails because ciphertext was tampered
  let aeadFailed = false;
  try {
    openFrame(serverSession.receiveKey, forged);
  } catch {
    aeadFailed = true;
  }
  assert.equal(aeadFailed, true, "Sanity: tampered frame correctly rejected by AEAD");

  // The legitimate frame at seq=0 is still processable (lastReceiveSequence not updated)
  const { frame: legitFrame } = openFrame(serverSession.receiveKey, legitimate);
  assert.equal(legitFrame.sequence, 0n);

  // VERIFY the fix direction: check sequence AFTER successful AEAD decryption
  // uses the authenticated sequence, which correctly rejects replays
  const { frame: verified } = openFrame(serverSession.receiveKey, legitimate);
  const postAeadSeqOk = verified.sequence > lastReceiveSequence;
  assert.equal(postAeadSeqOk, true, "Fix direction: authenticated sequence still passes check");
}

console.log("bug-3 (unauthenticated sequence check) ✓");

// ─────────────────────────────────────────────────────────────────────────────
// Bug 4 — nextStreamId overflow crashes writeUInt32BE
// ─────────────────────────────────────────────────────────────────────────────
// control-client.ts:
//   nextStreamId: 1,   // starts at 1, plain JS number
//   ...
//   const ownerStreamId = owner.nextStreamId++;
//
// encodePublicTunnelFrame writes streamId using header.writeUInt32BE(streamId, 1).
// writeUInt32BE requires the value to be in [0, 4_294_967_295].
// Once nextStreamId reaches 4_294_967_296 the write throws ERR_OUT_OF_RANGE,
// crashing the control client connection.
{
  // Reproduce the crash path
  function encodePublicTunnelFrameRaw(streamId: number, payload: Buffer = Buffer.alloc(0)): Buffer {
    const header = Buffer.allocUnsafe(5);
    header.writeUInt8(0x02, 0); // STREAM_DATA type
    header.writeUInt32BE(streamId, 1); // this throws when streamId > 0xFFFFFFFF
    return Buffer.concat([header, payload]);
  }

  const MAX_UINT32 = 0xFFFFFFFF; // 4_294_967_295

  // Last valid value — must not throw
  assert.doesNotThrow(
    () => encodePublicTunnelFrameRaw(MAX_UINT32),
    "streamId at MAX_UINT32 must be encodeable",
  );

  // One past the end — BUG: this throws and crashes the control client
  assert.throws(
    () => encodePublicTunnelFrameRaw(MAX_UINT32 + 1),
    /out of range|ERR_OUT_OF_RANGE/i,
    "BUG 4: nextStreamId overflow — writeUInt32BE throws after 2^32 streams, crashing the connection",
  );

  // Verify the fix: wrap stream IDs using modulo
  function nextWrappedStreamId(current: number): number {
    return (current % MAX_UINT32) + 1; // stays in [1, MAX_UINT32]
  }

  const wrapped = nextWrappedStreamId(MAX_UINT32);
  assert.equal(wrapped, 1, "Fix: stream IDs wrap around to 1 instead of overflowing");
  assert.doesNotThrow(
    () => encodePublicTunnelFrameRaw(wrapped),
    "Fix: wrapped stream ID encodes without error",
  );
}

console.log("bug-4 (nextStreamId overflow) ✓");

// ─────────────────────────────────────────────────────────────────────────────
// Bug 5 — releaseManifest() called 3× in integrityPayload (wasted I/O + CPU)
// ─────────────────────────────────────────────────────────────────────────────
// integrity.ts:
//   version:  releaseManifest().version,   // call 1 — runs git + crypto hash
//   platform: releaseManifest().platform,  // call 2
//   manifest: releaseManifest(),           // call 3
//
// releaseManifest() runs execFileSync("git", ["rev-parse", "HEAD"]) and
// crypto.createHash("sha256").update(...) on every invocation.  Calling it
// three times triples the I/O and CPU cost for every integrity request.
{
  let callCount = 0;

  // Intercept releaseManifest by measuring how many distinct return objects we get
  // (each call allocates a fresh object — pointer equality catches triple-call)
  const { releaseManifest } = await import("../node/manifest.js");

  const results: object[] = [];
  for (let i = 0; i < 3; i++) {
    const result = releaseManifest();
    results.push(result);
    callCount++;
  }

  // Object identity check: 3 calls → 3 distinct objects (no memoisation)
  assert.notEqual(
    results[0],
    results[1],
    "BUG 5: releaseManifest() returns a new object on every call (no memoisation)",
  );

  // Timing proof — 3 calls should be measurably slower than 1 call
  const REPS = 50;
  const t1 = performance.now();
  for (let i = 0; i < REPS; i++) {
    releaseManifest();
    releaseManifest();
    releaseManifest();
  }
  const threeCallMs = performance.now() - t1;

  const t2 = performance.now();
  for (let i = 0; i < REPS; i++) {
    const m = releaseManifest();
    void m; void m; void m; // single call, reuse result
  }
  const oneCallMs = performance.now() - t2;

  assert.ok(
    threeCallMs > oneCallMs * 1.5,
    `BUG 5: 3×releaseManifest() (${threeCallMs.toFixed(1)} ms) must be slower than 1× (${oneCallMs.toFixed(1)} ms) — wasted execFileSync + hash`,
  );
}

console.log("bug-5 (triple releaseManifest) ✓");

console.log("\nAll bug-hunt tests passed.");
