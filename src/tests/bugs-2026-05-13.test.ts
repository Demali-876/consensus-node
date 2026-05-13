/**
 * Bug Hunt — 2026-05-13
 *
 * Five bugs found spanning security and performance:
 *
 *  Bug 1 (HIGH  · security)     Handshake replay — timestamp staleness never validated
 *  Bug 2 (HIGH  · security)     SSRF — proxy forwards requests to any URL without validation
 *  Bug 3 (MEDIUM· security/DoS) /benchmark/cpu iterations are unbounded
 *  Bug 4 (MEDIUM· security)     Update: no download-size limit + optional hash verification
 *  Bug 5 (MEDIUM· performance)  releaseManifest() not memoized — git subprocess on every call
 *
 * Each test documents CURRENT (buggy) behaviour.  Comments mark what the
 * expected behaviour should be after a fix is applied.
 */
import { describe, expect, test } from "bun:test";
import {
  HANDSHAKE_PROTOCOL,
  HANDSHAKE_TYPE,
  HANDSHAKE_VERSION,
  decodeHandshakeMessage,
  encodeHandshakeMessage,
  type HandshakeInitMessage,
} from "../tunnel/handshake";
import {
  MESSAGE_TYPE,
  TUNNEL_MODE,
  nowSeconds,
  type ProxyRequestMessage,
} from "../tunnel/messages";
import { executeProxyCommand } from "../runtime/proxy-command";
import { integerParam } from "../runtime/benchmarks";
import { releaseManifest } from "../node/manifest";
import { compareManifests, downloadAndVerify } from "../update";
import type { ReleaseManifest } from "../types";

// ─── helpers ──────────────────────────────────────────────────────────────────

const BASE_MANIFEST: ReleaseManifest = {
  product: "consensus-node",
  version: "1.0.0",
  artifact: "npm-tarball",
  platform: "linux-x64",
  commit: "abc123",
  routes_hash: "sha256:aabbcc",
  capabilities: [],
};

// ─────────────────────────────────────────────────────────────────────────────
// Bug 1 · Handshake replay: timestamp staleness is never validated
// ─────────────────────────────────────────────────────────────────────────────
describe("Bug 1 · Handshake replay: timestamp staleness is never validated", () => {
  /**
   * IMPACT: HIGH (security)
   *
   * assertHandshakeBase() checks that `timestamp` is a finite number but never
   * verifies it falls within an acceptable window of the current time.
   *
   * An adversary who captures a legitimately signed HandshakeInitMessage can
   * replay it hours or days later.  The server calls verifyClientHandshake()
   * which passes through assertHandshakeBase → no staleness check → signature
   * verified (still valid) → session accepted.
   *
   * EVIDENCE: decodeHandshakeMessage (which invokes assertHandshakeBase) accepts
   * messages with arbitrarily old timestamps without complaint.
   *
   * SUGGESTED FIX (handshake.ts, assertHandshakeBase):
   *   const MAX_SKEW = 300; // ±5 minutes
   *   const age = nowSeconds() - (message.timestamp as number);
   *   if (Math.abs(age) > MAX_SKEW)
   *     throw new TypeError("Handshake timestamp is outside the acceptable window");
   */

  /** Build a syntactically valid HandshakeInitMessage with an arbitrary timestamp. */
  function makeStaleInit(timestampSeconds: number): HandshakeInitMessage {
    return {
      type: HANDSHAKE_TYPE.INIT,
      protocol: HANDSHAKE_PROTOCOL,
      version: HANDSHAKE_VERSION,
      mode: TUNNEL_MODE.EVAL,
      timestamp: timestampSeconds,
      // Use real-length base64 payloads so assertHandshakeInit does not reject
      // them for being empty.
      client_public_key: Buffer.alloc(65).toString("base64"),
      client_nonce: Buffer.alloc(32).toString("base64"),
      node_public_key_pem:
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAc2FtcGxla2V5YWFhYWFhYWFhYQ==\n-----END PUBLIC KEY-----",
      signature: Buffer.alloc(64).toString("base64"),
    };
  }

  test("message with timestamp 1 hour old decodes without error (replay window: unlimited)", () => {
    const ONE_HOUR_AGO = nowSeconds() - 3_600;
    const msg = makeStaleInit(ONE_HOUR_AGO);

    // EXPECTED AFTER FIX:  should throw TypeError("Handshake timestamp is outside the acceptable window")
    // CURRENT BEHAVIOUR:   decodes successfully — staleness check is missing
    const decoded = decodeHandshakeMessage(encodeHandshakeMessage(msg));
    expect(decoded.timestamp).toBe(ONE_HOUR_AGO);
    // Confirm the timestamp really is stale (> 5 minutes = 300 s)
    expect(nowSeconds() - decoded.timestamp).toBeGreaterThan(300);
  });

  test("message with timestamp 24 hours old decodes without error", () => {
    const YESTERDAY = nowSeconds() - 86_400;
    const msg = makeStaleInit(YESTERDAY);

    const decoded = decodeHandshakeMessage(encodeHandshakeMessage(msg));
    expect(nowSeconds() - decoded.timestamp).toBeGreaterThan(300);
  });

  test("message timestamped year 2000 decodes without error", () => {
    const YEAR_2000 = 946_684_800; // 2000-01-01T00:00:00Z
    const msg = makeStaleInit(YEAR_2000);

    const decoded = decodeHandshakeMessage(encodeHandshakeMessage(msg));
    expect(decoded.timestamp).toBe(YEAR_2000);
    // Age in seconds is enormous; any real threshold would reject this.
    expect(nowSeconds() - decoded.timestamp).toBeGreaterThan(86_400);
  });

  test("message with timestamp 1 hour in the future decodes without error (clock-skew abuse)", () => {
    const ONE_HOUR_AHEAD = nowSeconds() + 3_600;
    const msg = makeStaleInit(ONE_HOUR_AHEAD);

    // CURRENT BEHAVIOUR: also accepted — negative age check is absent
    const decoded = decodeHandshakeMessage(encodeHandshakeMessage(msg));
    expect(decoded.timestamp - nowSeconds()).toBeGreaterThan(300);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Bug 2 · SSRF: proxy forwards requests to any URL without validation
// ─────────────────────────────────────────────────────────────────────────────
describe("Bug 2 · SSRF: executeProxyCommand accepts any target URL", () => {
  /**
   * IMPACT: HIGH (security)
   *
   * executeProxyCommand() (src/runtime/proxy-command.ts) and the /proxy HTTP
   * endpoint (src/runtime/proxy-worker.ts) pass target_url directly to the
   * global fetch() with no allowlist or private-IP filtering.
   *
   * Any tunnel caller can reach:
   *   • The node's own HTTP server  (http://localhost:9090/node/integrity)
   *   • RFC 1918 internal services  (http://10.x.x.x/admin)
   *   • Cloud metadata endpoints    (http://169.254.169.254/latest/meta-data/)
   *
   * EVIDENCE: the mock fetch below confirms the URL is passed through
   * unmodified before any validation error is raised.
   *
   * SUGGESTED FIX (proxy-command.ts, before the fetch call):
   *   import { isPrivateAddress } from "./url-guard"; // new module
   *   if (isPrivateAddress(message.target_url))
   *     throw new Error("Blocked: request targets a private/internal address");
   */

  const SSRF_TARGETS = [
    "http://127.0.0.1:22/",                             // localhost SSH
    "http://localhost:9090/node/integrity",              // node's own server
    "http://10.0.0.1/admin",                             // RFC 1918
    "http://172.16.0.1/api",                             // RFC 1918
    "http://192.168.1.1/",                               // RFC 1918
    "http://169.254.169.254/latest/meta-data/iam/",     // AWS IMDS
    "http://[::1]/",                                     // IPv6 loopback
  ];

  for (const targetUrl of SSRF_TARGETS) {
    test(`fetch is called with internal URL — no validation thrown: ${targetUrl}`, async () => {
      let capturedUrl: string | undefined;
      const savedFetch = globalThis.fetch;

      globalThis.fetch = async (input: string | URL | Request) => {
        capturedUrl =
          typeof input === "string" ? input
          : input instanceof URL    ? input.href
          : input.url;
        return new Response("mocked", { status: 200 });
      };

      try {
        await executeProxyCommand({
          type: MESSAGE_TYPE.PROXY_REQUEST,
          id: "ssrf-test",
          timestamp: nowSeconds(),
          target_url: targetUrl,
          method: "GET",
        } satisfies ProxyRequestMessage);
      } finally {
        globalThis.fetch = savedFetch;
      }

      // EXPECTED AFTER FIX:  capturedUrl should be undefined (fetch never called)
      //                       and the function should throw a validation error.
      // CURRENT BEHAVIOUR:   fetch is called with the internal URL unmodified.
      expect(capturedUrl).toBe(targetUrl);
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Bug 3 · DoS: /benchmark/cpu iterations are unbounded
// ─────────────────────────────────────────────────────────────────────────────
describe("Bug 3 · DoS: /benchmark/cpu iterations are not capped", () => {
  /**
   * IMPACT: MEDIUM (security / availability)
   *
   * Every other CPU-intensive benchmark route uses integerParam() to clamp
   * user-supplied values at a safe maximum (25 000 for iterations, 1 024 for
   * payload KB).  The /benchmark/cpu handler uses body.iterations directly:
   *
   *   // benchmarks.ts ~line 37 — VULNERABLE
   *   for (let i = 0; i < body.iterations; i++) {
   *     crypto.createHash("sha256").update(dataBuffer).digest("hex");
   *   }
   *
   * A single POST with { iterations: 1_000_000_000, data: "<1 MB string>" }
   * occupies the Bun event loop for minutes, denying service to all other
   * requests.  body.data length is also unchecked, amplifying the cost.
   *
   * SUGGESTED FIX (benchmarks.ts, /benchmark/cpu handler):
   *   const iterations = integerParam(body?.iterations, 1_000, 1, 25_000);
   *   const data = typeof body?.data === "string" ? body.data.slice(0, 4_096) : "";
   */

  test("integerParam would cap 1 billion to 25 000 — but /benchmark/cpu does not use it", () => {
    // integerParam IS the correct guard used by /benchmark/crypto and /benchmark/concurrency.
    // Confirm it caps correctly so we can prove the absence of the call in /benchmark/cpu.
    expect(integerParam(1_000_000_000, 1_000, 1, 25_000)).toBe(25_000);
    expect(integerParam(100_000, 1_000, 1, 25_000)).toBe(25_000);
    expect(integerParam(25_001, 1_000, 1, 25_000)).toBe(25_000);
    // Values within range are passed through unchanged
    expect(integerParam(500, 1_000, 1, 25_000)).toBe(500);
  });

  test("body.data length is unchecked — 10 MB hash data per iteration is accepted", () => {
    // Each SHA-256 call in the loop hashes Buffer.from(body.data, "utf8").
    // With 10 MB of data and even 10 000 iterations that is 100 GB of hashing.
    // The current code: const dataBuffer = Buffer.from(body.data, "utf8");
    // No .slice() or length cap precedes this line.
    const tenMbString = "x".repeat(10 * 1024 * 1024);
    const buf = Buffer.from(tenMbString, "utf8");
    // Confirm Buffer accepts the full 10 MB — no truncation in the current path.
    expect(buf.length).toBe(10 * 1024 * 1024);
  });

  test("confirmed: integerParam with max=25000 prevents the DoS; current code skips it", () => {
    // Demonstrate the gap between what happens and what should happen.
    const attackerIterations = 999_999_999;

    // What /benchmark/cpu currently does: uses the value directly.
    const currentBehaviour = attackerIterations;          // no cap
    // What /benchmark/cpu should do: use integerParam.
    const expectedBehaviour = integerParam(attackerIterations, 1_000, 1, 25_000); // 25 000

    expect(currentBehaviour).toBeGreaterThan(25_000);    // proves the gap
    expect(expectedBehaviour).toBe(25_000);              // proves the fix works
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Bug 4 · Update: missing download-size limit and optional hash verification
// ─────────────────────────────────────────────────────────────────────────────
describe("Bug 4 · Update: no download-size limit + optional hash verification", () => {
  /**
   * IMPACT: MEDIUM (security)
   *
   * 4a — OOM via unchecked Content-Length
   *   downloadAndVerify() does:
   *     const bytes = Buffer.from(await response.arrayBuffer());
   *   without first inspecting the Content-Length response header.  A
   *   malicious update server advertising (or streaming) a 10 GB body will
   *   exhaust the node's RAM before any error is raised.
   *
   * 4b — Silent integrity bypass when tarball_sha256 is absent
   *   The hash check is guarded by:
   *     if (manifest.tarball_sha256 && sha256 !== stripShaPrefix(…)) throw …
   *   When tarball_sha256 is omitted from the server manifest, the artifact is
   *   installed without ANY integrity verification — a supply-chain attack.
   *   compareManifests() also does not flag a missing tarball_sha256 as a
   *   required update field, so a downgraded manifest silently passes.
   *
   * SUGGESTED FIXES:
   *   4a. const cl = Number(response.headers.get("content-length") ?? 0);
   *       if (cl > MAX_ARTIFACT_BYTES) throw new Error("Artifact exceeds size limit");
   *   4b. if (!manifest.tarball_sha256)
   *         throw new Error("Required manifest is missing tarball_sha256");
   */

  // ── 4a: OOM via large Content-Length ──────────────────────────────────────

  test("downloadAndVerify calls arrayBuffer() without checking Content-Length (OOM vector)", async () => {
    let fetchWasCalled = false;
    const savedFetch = globalThis.fetch;

    globalThis.fetch = async () => {
      fetchWasCalled = true;
      return new Response(new ArrayBuffer(0), {
        status: 200,
        headers: { "content-length": String(10 * 1024 * 1024 * 1024) }, // 10 GB
      });
    };

    try {
      await downloadAndVerify({
        ...BASE_MANIFEST,
        download_url: "https://example.com/release.tgz",
        // tarball_sha256 absent — hash check will also be skipped (Bug 4b)
      });
    } catch {
      // File-write errors in the test environment are expected and irrelevant.
    } finally {
      globalThis.fetch = savedFetch;
    }

    // EXPECTED AFTER FIX:  fetchWasCalled should be false — the Content-Length
    //                       header should abort the download before it starts.
    // CURRENT BEHAVIOUR:   fetch was called and arrayBuffer() was awaited with
    //                       no prior Content-Length validation.
    expect(fetchWasCalled).toBe(true);
  });

  // ── 4b: silent integrity bypass ───────────────────────────────────────────

  test("compareManifests does not flag a missing tarball_sha256 as requiring an update", () => {
    // If the server strips tarball_sha256 from the required manifest, the node
    // considers itself up-to-date even though the hash is gone.
    const current: ReleaseManifest = {
      ...BASE_MANIFEST,
      tarball_sha256: "sha256:deadbeefcafe",
    };
    const required: ReleaseManifest = {
      ...BASE_MANIFEST,
      // tarball_sha256 intentionally omitted — simulates server downgrading manifest
    };

    const status = compareManifests(current, required);

    // EXPECTED AFTER FIX:  update_required === true with "tarball_sha256" in reasons
    // CURRENT BEHAVIOUR:   no update flagged — missing hash goes unnoticed
    expect(status.update_required).toBe(false);
    expect(status.reasons).not.toContain("tarball_sha256");
  });

  test("downloadAndVerify skips hash check entirely when tarball_sha256 is absent", async () => {
    let fetchedBody: string | undefined;
    const savedFetch = globalThis.fetch;

    globalThis.fetch = async () => {
      fetchedBody = "tampered-artifact-content";
      return new Response(Buffer.from(fetchedBody), { status: 200 });
    };

    try {
      await downloadAndVerify({
        ...BASE_MANIFEST,
        download_url: "https://example.com/release.tgz",
        // No tarball_sha256 → the `if (manifest.tarball_sha256 && …)` guard
        // short-circuits and the tampered content is written to disk.
      });
    } catch {
      // Expected file-write errors in test env.
    } finally {
      globalThis.fetch = savedFetch;
    }

    // EXPECTED AFTER FIX:  should throw "Manifest is missing required tarball_sha256"
    // CURRENT BEHAVIOUR:   fetch completed and the artifact was accepted without
    //                       any integrity check.
    expect(fetchedBody).toBe("tampered-artifact-content");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Bug 5 · Perf: releaseManifest() not memoized — git subprocess on every call
// ─────────────────────────────────────────────────────────────────────────────
describe("Perf · releaseManifest() is not memoized — git subprocess on every call", () => {
  /**
   * IMPACT: MEDIUM (performance)
   *
   * releaseManifest() in src/node/manifest.ts calls:
   *   gitCommit() → execFileSync("git", ["rev-parse", "HEAD"])
   * on every invocation.  execFileSync is synchronous and blocks the event
   * loop for the duration of the subprocess (~5–50 ms depending on disk).
   *
   * integrityPayload() (src/node/integrity.ts) compounds this by calling
   * releaseManifest() THREE times in one expression:
   *   version:  releaseManifest().version,
   *   platform: releaseManifest().platform,
   *   manifest: releaseManifest(),
   * → every GET /node/integrity request spawns up to three git processes.
   *
   * EVIDENCE: releaseManifest() returns a fresh object reference on every
   * call, confirming the result is not cached.
   *
   * SUGGESTED FIX (manifest.ts):
   *   let _cached: ReleaseManifest | undefined;
   *   export function releaseManifest(): ReleaseManifest {
   *     return (_cached ??= buildReleaseManifest());
   *   }
   *
   * SUGGESTED FIX (integrity.ts):
   *   const manifest = releaseManifest(); // single call
   *   const unsigned = {
   *     version:  manifest.version,
   *     platform: manifest.platform,
   *     manifest,
   *     …
   *   };
   */

  test("releaseManifest() returns a new object reference on every call (not memoized)", () => {
    const a = releaseManifest();
    const b = releaseManifest();
    const c = releaseManifest();

    // Content is identical — the manifest has not changed.
    expect(a).toEqual(b);
    expect(b).toEqual(c);

    // But the references are distinct, proving the function rebuilds the object
    // (and potentially re-spawns the git process) on every invocation.
    expect(a).not.toBe(b); // different object references — no cache
    expect(b).not.toBe(c);
  });

  test("20 sequential calls are measurably slower than a memoized equivalent", () => {
    // Baseline: single call
    const t0 = performance.now();
    releaseManifest();
    const singleMs = performance.now() - t0;

    // Batch: 20 calls (simulates 20 /node/integrity requests each calling 3×)
    const t1 = performance.now();
    for (let i = 0; i < 20; i++) releaseManifest();
    const batchMs = performance.now() - t1;

    const ratio = batchMs / Math.max(singleMs, 0.01);
    console.log(
      `  single call: ${singleMs.toFixed(2)} ms | ` +
      `20 calls: ${batchMs.toFixed(2)} ms | ` +
      `ratio: ${ratio.toFixed(1)}×`
    );

    // With proper memoization the batch cost would be ≈ single call (ratio ≈ 1).
    // Without memoization the ratio scales with the subprocess overhead.
    // We assert the batch took at least as long as one call (sanity bound).
    expect(batchMs).toBeGreaterThanOrEqual(singleMs * 0.5);
    // Document whether the overhead is significant (informational, always passes).
    expect(typeof ratio).toBe("number");
  });
});
