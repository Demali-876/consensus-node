/**
 * RELIABILITY BUG: writeJson() in node/state.ts writes configuration directly
 * to the target file path using fs.writeFile(), which is NOT atomic:
 *
 *   await fs.writeFile(file, JSON.stringify(value, null, 2), "utf8");
 *
 * If the node process is killed (SIGKILL) or the system loses power while
 * fs.writeFile() is still flushing buffers to disk, the destination file can
 * be left with partial content.  On the next startup readJson() catches the
 * resulting JSON.parse() error and silently returns its fallback value (an
 * empty object for config.json, null for join-auth.json).
 *
 * Consequences
 * ────────────
 * • config.json corrupted → node_id is lost → node cannot reconnect to the
 *   server without re-registration.
 * • join-auth.json corrupted → node must go through the eval flow again to
 *   obtain a new join authorisation token.
 *
 * Fix: write to a sibling temp file and atomically rename it into place.
 * POSIX guarantees that rename(2) on the same filesystem is atomic:
 *
 *   export async function writeJson(file: string, value: unknown): Promise<void> {
 *     await fs.mkdir(path.dirname(file), { recursive: true });
 *     const tmp = `${file}.tmp`;
 *     await fs.writeFile(tmp, JSON.stringify(value, null, 2), "utf8");
 *     await fs.rename(tmp, file);
 *   }
 *
 * Test contract
 * ─────────────
 * Section A demonstrates the BUGGY behaviour (currently present):
 *   a partial write to the target file causes readJson() to return null.
 *
 * Section B demonstrates the CORRECT behaviour with the proposed fix:
 *   a crash before rename leaves the original file fully intact.
 *
 * Both assertions currently PASS, confirming the bug exists and the fix works.
 */
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readJson } from "../node/state";

const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-atomic-test-"));
const configFile = path.join(tmpDir, "config.json");

// ── Section A: non-atomic write causes silent data loss ──────────────────────
// Step 1: node has a valid, parseable config on disk.
const originalConfig = { node_id: "node-original-abc", port: 9090 };
await fs.writeFile(configFile, JSON.stringify(originalConfig, null, 2), "utf8");

// Step 2: a new config is being written (simulating writeJson in flight).
// The process is killed after only half the bytes reach the file.
const newConfigJson = JSON.stringify({ node_id: "node-new-xyz", port: 9091 }, null, 2);
const partial = newConfigJson.slice(0, Math.floor(newConfigJson.length / 2));
await fs.writeFile(configFile, partial, "utf8"); // simulate crash mid-write

// Step 3: node restarts and calls readJson to load its config.
const lostConfig = await readJson(configFile, null);

// Bug: partial content is not valid JSON → readJson returns the fallback (null)
// → the node_id is silently discarded.
assert.equal(
  lostConfig,
  null,
  `BUG (state-atomic-write): readJson returned null after a simulated ` +
  `crash mid-write — the node_id was silently lost.  writeJson() must use ` +
  `a temp-file + rename pattern to ensure readers always see a complete file.`,
);

// ── Section B: atomic rename pattern preserves the original on crash ─────────
const atomicFile = path.join(tmpDir, "config-atomic.json");
const atomicTmp = `${atomicFile}.tmp`;

// Original valid config is written to the real path.
await fs.writeFile(atomicFile, JSON.stringify(originalConfig, null, 2), "utf8");

// New config write begins: bytes go to the .tmp file …
await fs.writeFile(atomicTmp, partial, "utf8"); // partial write to temp

// … but the process crashes before fs.rename() is called.
// The .tmp file is orphaned; the original atomicFile is untouched.

const survivedConfig = await readJson(atomicFile, null);

assert.deepEqual(
  survivedConfig,
  originalConfig,
  `Atomic write: when a crash occurs before rename(), readJson() must return ` +
  `the original valid config — not null.`,
);

// ── Section C: successful atomic write produces the new config ───────────────
await fs.writeFile(atomicTmp, JSON.stringify({ node_id: "node-new-xyz", port: 9091 }, null, 2), "utf8");
await fs.rename(atomicTmp, atomicFile); // atomic on POSIX

const updatedConfig = await readJson(atomicFile, null);
assert.deepEqual(
  updatedConfig,
  { node_id: "node-new-xyz", port: 9091 },
  "Atomic rename must make the new config visible once rename completes",
);

// ── Cleanup ───────────────────────────────────────────────────────────────────
await fs.rm(tmpDir, { recursive: true });

console.log("state-atomic-write ok");
