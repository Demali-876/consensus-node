/**
 * Proves that downloadAndVerify always requires tarball_sha256.
 *
 * Without this gate a MITM attacker who controls the download URL (CDN
 * compromise, DNS hijacking) can serve arbitrary code that the node will write
 * to disk and subsequently execute via the update command — with no integrity
 * check to detect the substitution.
 *
 * Before fix: the SHA-256 check is guarded by
 *   `if (manifest.tarball_sha256 && ...)`, so a manifest without the field
 *   causes the downloaded bytes to be saved unconditionally.
 *
 * After fix: downloadAndVerify throws immediately when tarball_sha256 is
 *   absent, before any network I/O takes place.  Mismatched hashes continue
 *   to throw as before.
 */
import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { downloadAndVerify } from "../update";
import { routesHash } from "../node/manifest";
import type { ReleaseManifest } from "../types";

process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-download-verify-test-"),
);

// ---- Local HTTP server to serve arbitrary artifact content -----------------

const artifactContent = Buffer.from("legitimate-tarball-content");
const correctSha256 = `sha256:${crypto.createHash("sha256").update(artifactContent).digest("hex")}`;

let serveContent: Buffer = artifactContent;
const httpPort = await getFreePort();
const httpServer = Bun.serve({
  hostname: "127.0.0.1",
  port: httpPort,
  fetch() {
    return new Response(serveContent);
  },
});

const downloadUrl = `http://127.0.0.1:${httpPort}/artifact.tgz`;

const baseManifest = {
  product: "consensus-node" as const,
  version: "1.0.0-dltest",
  artifact: "npm-tarball" as const,
  platform: "linux-x64",
  commit: "deadbeef",
  routes_hash: routesHash(),
  capabilities: [],
} satisfies Omit<ReleaseManifest, "download_url" | "tarball_sha256">;

// ---------------------------------------------------------------------------
// Case 1: manifest WITHOUT tarball_sha256 — must throw before downloading
// ---------------------------------------------------------------------------
// The server would happily serve "malicious" content; the node must refuse to
// even start the download rather than blindly writing whatever bytes it gets.

serveContent = Buffer.from("malicious-payload");
const errNoHash = await downloadAndVerify({
  ...baseManifest,
  download_url: downloadUrl,
  // tarball_sha256 deliberately absent
} as ReleaseManifest).then(
  () => null,
  (e: unknown) => e,
);

assert.ok(
  errNoHash instanceof Error,
  `Case 1: must reject a manifest with no tarball_sha256 — got: ${JSON.stringify(errNoHash)}`,
);
assert.match(
  (errNoHash as Error).message,
  /tarball_sha256/i,
  `Case 1: error must mention tarball_sha256 — got: "${(errNoHash as Error).message}"`,
);

// ---------------------------------------------------------------------------
// Case 2: manifest WITH a correct tarball_sha256 — must succeed
// ---------------------------------------------------------------------------

serveContent = artifactContent;
const result = await downloadAndVerify({
  ...baseManifest,
  download_url: downloadUrl,
  tarball_sha256: correctSha256,
});

assert.ok(result.path.length > 0, "Case 2: result.path must be non-empty");
assert.equal(
  result.sha256,
  correctSha256.slice("sha256:".length),
  `Case 2: returned sha256 must match artifact — got: ${result.sha256}`,
);
const written = await fs.readFile(result.path);
assert.deepEqual(written, artifactContent, "Case 2: written file must match artifact bytes");

// ---------------------------------------------------------------------------
// Case 3: manifest WITH a wrong tarball_sha256 — must throw after downloading
// ---------------------------------------------------------------------------

const errBadHash = await downloadAndVerify({
  ...baseManifest,
  download_url: downloadUrl,
  tarball_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
}).then(
  () => null,
  (e: unknown) => e,
);

assert.ok(
  errBadHash instanceof Error,
  `Case 3: must reject artifact with wrong sha256 — got: ${JSON.stringify(errBadHash)}`,
);
assert.match(
  (errBadHash as Error).message,
  /sha-256 mismatch/i,
  `Case 3: error must mention SHA-256 mismatch — got: "${(errBadHash as Error).message}"`,
);

// ---- Teardown --------------------------------------------------------------
httpServer.stop(true);
console.log("download-verify ok");

// ---------------------------------------------------------------------------

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
