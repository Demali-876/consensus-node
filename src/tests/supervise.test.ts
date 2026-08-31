// Behavioural tests for src/supervise.ts — the unit that runs the runtime server
// and the control tunnel together. Each case builds a throwaway "release" whose
// package.json scripts stand in for `bun run start` / `bun run control`, then runs
// the real supervisor against it and asserts on the unit's exit code and on whether
// anything was left behind.
//
// The orphan assertions are the point of the file: `bun run <script>` is a wrapper,
// so signalling its pid alone leaves a grandchild alive. That regressed once already.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const SUPERVISOR = path.join(import.meta.dir, "..", "supervise.ts");
const GRACE_MS = 300;

const root = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-supervise-"));
const installDir = path.join(root, "node-runtime");
const releaseDir = path.join(installDir, "releases", "r1");

/** A marker embedded in each fake child so we can pgrep for survivors afterwards. */
const MARKER = `consensus-supervise-probe-${process.pid}`;

/** Fake child that stays up and exits cleanly on SIGTERM. */
function longRunning(): string {
  return `bun -e 'process.title=${JSON.stringify(MARKER)};setInterval(()=>{},1000);process.on("SIGTERM",()=>process.exit(0))'`;
}

/** Fake child that stays up and deliberately ignores SIGTERM, forcing the SIGKILL path. */
function wedged(): string {
  return `bun -e 'process.title=${JSON.stringify(MARKER)};setInterval(()=>{},1000);process.on("SIGTERM",()=>{})'`;
}

/** Fake child that exits with a fixed code after a short delay. */
function exitsWith(code: number): string {
  return `bun -e 'setTimeout(()=>process.exit(${code}),200)'`;
}

async function writeRelease(scripts: { start: string; control: string }): Promise<void> {
  await fs.mkdir(releaseDir, { recursive: true });
  await fs.writeFile(
    path.join(releaseDir, "package.json"),
    JSON.stringify({ name: "fake-release", scripts }, null, 2),
  );
  const current = path.join(installDir, "current");
  await fs.rm(current, { force: true });
  await fs.symlink(releaseDir, current);
}

interface RunResult {
  code: number;
  signal: NodeJS.Signals | null;
}

/** Run the supervisor to completion, optionally signalling it partway through. */
function runSupervisor(options: { install?: string; signalAfterMs?: number } = {}): Promise<RunResult> {
  const proc = spawn("bun", [SUPERVISOR], {
    env: {
      ...process.env,
      CONSENSUS_NODE_INSTALL_DIR: options.install ?? installDir,
      CONSENSUS_STATE_DIR: path.join(root, "state"),
      CONSENSUS_SUPERVISE_GRACE_MS: String(GRACE_MS),
    },
    stdio: "ignore",
  });

  if (typeof options.signalAfterMs === "number") {
    setTimeout(() => proc.kill("SIGTERM"), options.signalAfterMs);
  }

  return new Promise<RunResult>((resolve) => {
    proc.once("exit", (code, signal) => {
      resolve({ code: code ?? -1, signal });
    });
  });
}

/** True if any fake child from this test run is still alive. */
async function survivorsExist(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn("pgrep", ["-f", MARKER], { stdio: "ignore" });
    proc.once("exit", (code) => resolve(code === 0));
    proc.once("error", () => resolve(false));
  });
}

/** pgrep can still see a process in the instant between SIGKILL and reaping. */
async function assertNoSurvivors(label: string): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt++) {
    if (!(await survivorsExist())) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail(`${label}: a child outlived the supervisor`);
}

try {
  // The control tunnel exits 75 to request a restart; that code must reach the
  // supervisor (PM2/systemd) unchanged, and the runtime server must be reaped.
  await writeRelease({ start: longRunning(), control: exitsWith(75) });
  const restart = await runSupervisor();
  assert.equal(restart.code, 75, "first child's exit code becomes the unit's exit code");
  await assertNoSurvivors("exit-code propagation");

  // A missing `current` is the one startup precondition, and it keeps run-node.sh's
  // exit code so existing supervisor configs and runbooks stay accurate.
  const missing = await runSupervisor({ install: path.join(root, "absent") });
  assert.equal(missing.code, 70, "missing release exits 70");

  // A supervisor-initiated stop (pm2 restart, systemctl stop) must drain both
  // children and report the signal rather than a child's exit code.
  await writeRelease({ start: longRunning(), control: longRunning() });
  const stopped = await runSupervisor({ signalAfterMs: 1_000 });
  assert.equal(stopped.code, 143, "SIGTERM to the unit reports 128+15");
  await assertNoSurvivors("signalled shutdown");

  // The case that regressed: a child ignoring SIGTERM must be SIGKILLed, and the
  // kill has to reach the whole process group or `bun run`'s grandchild survives.
  await writeRelease({ start: wedged(), control: exitsWith(9) });
  const forced = await runSupervisor();
  assert.equal(forced.code, 9, "a wedged sibling does not change the exit code");
  await assertNoSurvivors("forced kill");
} finally {
  await fs.rm(root, { recursive: true, force: true });
}

console.log("supervise ok");
