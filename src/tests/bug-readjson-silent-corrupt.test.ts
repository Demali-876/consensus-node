/**
 * BUG: readJson silently swallows ALL errors, including corrupt JSON
 *
 * node/state.ts readJson<T>(file, fallback):
 *
 *   try {
 *     return JSON.parse(await fs.readFile(file, "utf8")) as T;
 *   } catch {
 *     return fallback;
 *   }
 *
 * This broad catch means:
 *   • A partially-written or truncated config.json (e.g. after a crash) is
 *     silently treated as "not present" and the fallback is returned.
 *   • loadConfig() falls back to { port: 9090 } — missing node_id — which
 *     causes startControlClient to throw "Missing node id" with no hint that
 *     the config file is corrupt.
 *   • The operator sees a misleading startup failure and has no idea their
 *     state directory was damaged.
 *
 * The fix should distinguish between "file does not exist" (return fallback)
 * and "file exists but is malformed" (throw a descriptive error).
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// ---- Inline the current readJson implementation for a self-contained test ----

async function readJson<T>(file: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as T;
  } catch {
    return fallback;
  }
}

// ---- Set up temp dir ----

const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-readjson-test-"));
const configPath = path.join(tmpDir, "config.json");

// ---- Case 1: file does not exist → fallback is correct ----

const missingResult = await readJson<{ port: number; node_id?: string }>(
  configPath,
  { port: 9090 },
);
assert.deepEqual(missingResult, { port: 9090 }, "Missing file: fallback returned (correct)");

// ---- Case 2: file exists with corrupt JSON → BUG: silent fallback ----

// Write truncated JSON — simulates a crash mid-write.
await fs.writeFile(configPath, '{"node_id":"real-node","port":9090', "utf8");

let caughtError: Error | null = null;
let corruptResult: { port: number; node_id?: string } | undefined;

try {
  corruptResult = await readJson<{ port: number; node_id?: string }>(
    configPath,
    { port: 9090 },
  );
} catch (err) {
  caughtError = err instanceof Error ? err : new Error(String(err));
}

// The current code silently returns the fallback instead of throwing.
assert.equal(
  caughtError,
  null,
  "Unexpected: readJson already throws on corrupt JSON",
);

assert.deepEqual(
  corruptResult,
  { port: 9090 },
  "readJson returned fallback for corrupt config (node_id lost silently)",
);

// Confirm that the file EXISTS and contains data (not an absent-file case).
const rawContent = await fs.readFile(configPath, "utf8");
assert.ok(rawContent.length > 0, "Config file exists and has content");

// The real node_id is gone — this would cause "Missing node id" on next run.
assert.equal(
  corruptResult?.node_id,
  undefined,
  "node_id silently lost when config is corrupt",
);

// ---- Cleanup ----
await fs.rm(tmpDir, { recursive: true });

console.log(
  "BUG CONFIRMED — readjson-silent-corrupt: " +
  "readJson swallowed a SyntaxError from truncated JSON in config.json. " +
  "The fallback { port: 9090 } was returned, silently discarding node_id. " +
  "Fix: check fs.access() first; only fall back for ENOENT, throw for parse errors.",
);
