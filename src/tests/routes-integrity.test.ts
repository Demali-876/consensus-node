/**
 * Evidence test: REQUIRED_ROUTES (routes_hash source-of-truth) does not match
 * the routes actually registered in the HTTP server.
 *
 * BUG SUMMARY
 * ───────────
 * src/node/manifest.ts defines REQUIRED_ROUTES — a hard-coded list that is
 * SHA-256 hashed to produce the `routes_hash` field in every release manifest.
 * That hash is used by the network to verify that the node is running the
 * expected software version.
 *
 * src/runtime/benchmarks/routes.ts registers the actual Fastify routes, but
 * its route names diverge from REQUIRED_ROUTES:
 *
 *   Listed in REQUIRED_ROUTES but NOT registered:
 *     POST /benchmark/fetch         (no implementation exists)
 *     POST /benchmark/concurrency   (no implementation exists)
 *     POST /benchmark/memory-test   (registered as /benchmark/memory instead)
 *     POST /benchmark/memory-pressure (no implementation exists)
 *
 *   Registered but NOT in REQUIRED_ROUTES:
 *     POST /benchmark/memory        (likely a rename of /benchmark/memory-test)
 *     POST /benchmark/event-loop    (unlisted)
 *     POST /benchmark/all           (unlisted)
 *
 * Effect: the routes_hash in every manifest is computed from a spec that the
 * running server does not fulfil.  Any verifier that cross-checks the hash
 * against live route probes will find four 404s and flag the node as tampered.
 *
 * HOW THE TEST WORKS
 * ──────────────────
 * The Fastify server is built and each REQUIRED_ROUTE is probed with an
 * injected request.  A 404 response means the route does not exist.
 *
 * CURRENT RESULT:  FAIL — four routes return 404 (mismatch confirmed).
 * AFTER FIX:       PASS — every REQUIRED_ROUTE returns a non-404 response.
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { buildServer } from "../runtime/server";
import { REQUIRED_ROUTES } from "../node/manifest";
import { saveConfig } from "../node/state";

// Isolated state so /health and other handlers don't fail on missing config
process.env.CONSENSUS_STATE_DIR = await fs.mkdtemp(
  path.join(os.tmpdir(), "consensus-routes-test-"),
);
await saveConfig({ port: 9090 });

const app = await buildServer();
await app.ready();

const missing: string[] = [];

for (const route of REQUIRED_ROUTES) {
  const spaceIdx = route.indexOf(" ");
  const method = route.slice(0, spaceIdx);
  const url    = route.slice(spaceIdx + 1);

  const response = await app.inject({ method, url });

  if (response.statusCode === 404) {
    missing.push(route);
  }
}

await app.close();

assert.deepEqual(
  missing,
  [],
  "ROUTES MISMATCH BUG: the following routes appear in REQUIRED_ROUTES " +
    "(and are therefore included in routes_hash) but are NOT registered in the server:\n  " +
    missing.join("\n  ") +
    "\n\nVerifiers probing these URLs will receive 404, making the node look " +
    "tampered even when running unmodified code.",
);

console.log("routes-integrity ok");
