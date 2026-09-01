#!/usr/bin/env bun
//
// Supervised node unit — runs BOTH the control tunnel and the runtime server as
// one unit. Replaces scripts/run-node.sh.
//
// The control tunnel (`bun run control`) is the whole data path: it carries
// heartbeats, proxy work, AND the client-facing data plane, which the orchestrator
// node-gateway bridges onto it (target {kind:"data-plane"} streams). The runtime
// server (`bun run start`) binds loopback-only and just serves local operator
// endpoints (/health, /node/*); it needs no inbound port or TLS. Running both under
// one PM2/systemd/launchd unit means a single restart refreshes both from the
// updated `current` symlink.
//
// The unit exits as soon as EITHER child exits: the control tunnel exits on
// `update_apply` (so the whole unit restarts onto the new release), and a crash of
// either child cycles the unit too.
//
// This is a port of run-node.sh, which needed `wait -n` and therefore bash >= 4.3.
// Stock macOS ships bash 3.2, so that script exited 78 on any Mac whose operator
// had not run `brew install bash` — the reason this is TypeScript now.

import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { log } from "./log";
import { headlessBootStatus } from "./node/headless";

/** Same exit code run-node.sh used when `current` is missing. */
const NO_RELEASE_EXIT = 70;

/** How long a child gets to honour SIGTERM before we SIGKILL it. Stays under
 *  PM2's kill_timeout (30s) and systemd's TimeoutStopSec (30s) so the unit
 *  always tears itself down rather than being killed by its supervisor.
 *  Overridable only so the test suite does not have to wait out the real grace. */
const SHUTDOWN_GRACE_MS = (() => {
  const raw = Number(process.env.CONSENSUS_SUPERVISE_GRACE_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : 10_000;
})();

function envOr(name: string, fallback: string): string {
  const value = process.env[name];
  return value && value.length > 0 ? value : fallback;
}

const installDir = envOr(
  "CONSENSUS_NODE_INSTALL_DIR",
  path.join(os.homedir(), ".consensus", "node-runtime"),
);
const stateDir = envOr("CONSENSUS_STATE_DIR", path.join(os.homedir(), ".consensus", "node"));
const serverUrl = envOr("CONSENSUS_SERVER_URL", "https://consensus.canister.software");
const currentDir = path.join(installDir, "current");
const updateCommand = envOr(
  "CONSENSUS_NODE_UPDATE_COMMAND",
  path.join(currentDir, "scripts", "install-release.sh"),
);

// Exported to the children exactly as run-node.sh did, so a release that reads
// these directly sees identical values whether it was started here or by hand.
const childEnv: NodeJS.ProcessEnv = {
  ...process.env,
  CONSENSUS_STATE_DIR: stateDir,
  CONSENSUS_SERVER_URL: serverUrl,
  CONSENSUS_NODE_INSTALL_DIR: installDir,
  CONSENSUS_NODE_UPDATE_COMMAND: updateCommand,
};

// Prefer the interpreter we are already running under. A LaunchDaemon or systemd
// unit gets a minimal PATH that will not contain ~/.bun/bin, so resolving "bun"
// by name is exactly the failure mode this port is meant to remove. Falls back to
// PATH lookup only if something started us under a non-bun runtime.
const bunExecutable = process.versions.bun ? process.execPath : "bun";

interface Child {
  name: string;
  proc: ChildProcess;
}

interface Exit {
  name: string;
  code: number;
}

/** POSIX convention: a process killed by a signal reports 128 + signal number. */
function exitCodeFor(code: number | null, signal: NodeJS.Signals | null): number {
  if (typeof code === "number") return code;
  if (signal) return 128 + (os.constants.signals[signal] ?? 0);
  return 1;
}

function startChild(name: string, script: string): Child {
  // stdio is inherited so both children write straight to the unit's stdout/stderr,
  // where PM2 / systemd / launchd already capture them. Same as the shell version.
  //
  // detached puts each child in its own process group. `bun run <script>` is a
  // wrapper that spawns the real process, so signalling the wrapper's pid alone
  // leaves a grandchild behind: the wrapper forwards SIGTERM, but nothing can
  // forward SIGKILL. Signalling the group reaches the whole tree.
  const proc = spawn(bunExecutable, ["run", script], {
    cwd: currentDir,
    env: childEnv,
    stdio: "inherit",
    detached: true,
  });
  return { name, proc };
}

/** Signal a child's whole process group, falling back to the bare pid if the
 *  group is already gone (ESRCH) or the platform refuses the negative pid. */
function signalChild(child: Child, signal: NodeJS.Signals): void {
  const pid = child.proc.pid;
  if (typeof pid !== "number") return;
  try {
    process.kill(-pid, signal);
  } catch {
    try {
      child.proc.kill(signal);
    } catch {
      /* already reaped */
    }
  }
}

/** Resolves with the first child to exit; the others are left running. */
function firstExit(children: Child[]): Promise<Exit> {
  return Promise.race(
    children.map(
      (child) =>
        new Promise<Exit>((resolve) => {
          child.proc.once("exit", (code, signal) => {
            resolve({ name: child.name, code: exitCodeFor(code, signal) });
          });
          // spawn() failure (missing interpreter) emits 'error', never 'exit'.
          child.proc.once("error", (error) => {
            log.error("supervise", "child-spawn-failed", {
              child: child.name,
              executable: bunExecutable,
              message: error.message,
            });
            resolve({ name: child.name, code: 1 });
          });
        }),
    ),
  );
}

function stillRunning(child: Child): boolean {
  return child.proc.exitCode === null && child.proc.signalCode === null && !child.proc.killed;
}

/** SIGTERM every surviving child, then SIGKILL whatever is left after the grace
 *  period. The shell version waited forever here and relied on the supervisor to
 *  hard-kill a wedged child, which left the unit stuck for the full kill_timeout. */
async function shutdown(children: Child[]): Promise<void> {
  const survivors = children.filter(stillRunning);
  if (survivors.length === 0) return;

  const exits = survivors.map(
    (child) =>
      new Promise<void>((resolve) => {
        child.proc.once("exit", () => resolve());
      }),
  );

  for (const child of survivors) signalChild(child, "SIGTERM");

  let timer: ReturnType<typeof setTimeout> | undefined;
  const grace = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), SHUTDOWN_GRACE_MS);
  });

  const outcome = await Promise.race([Promise.all(exits).then(() => "done" as const), grace]);
  if (timer) clearTimeout(timer);

  if (outcome === "timeout") {
    for (const child of children.filter(stillRunning)) {
      log.warn("supervise", "child-kill-forced", {
        child: child.name,
        grace_ms: SHUTDOWN_GRACE_MS,
      });
      signalChild(child, "SIGKILL");
    }
  }
}

async function main(): Promise<void> {
  if (!fs.existsSync(currentDir) || !fs.statSync(currentDir).isDirectory()) {
    log.error("supervise", "no-installed-release", { current: currentDir });
    process.exit(NO_RELEASE_EXIT);
  }

  const children = [startChild("runtime", "start"), startChild("control", "control")];

  // Existing nodes never revisit the setup wizard, so the only place they learn the
  // node would not survive an unattended reboot is here.
  const headless = headlessBootStatus();
  if (headless.configured) {
    log.info("supervise", "headless-boot-configured", { mechanism: headless.mechanism, unit: headless.unit });
  } else {
    log.warn("supervise", "headless-boot-NOT-configured", {
      mechanism: headless.mechanism,
      detail: headless.detail,
    });
  }

  log.info("supervise", "started", {
    current: currentDir,
    state_dir: stateDir,
    server_url: serverUrl,
    interpreter: bunExecutable,
    children: children.map((child) => child.name),
  });

  // A signal from the supervisor (PM2 restart, systemd stop, launchd unload) means
  // tear down and report the signal, rather than waiting on a child that is also
  // being torn down.
  let signalled: NodeJS.Signals | null = null;
  const onSignal = (signal: NodeJS.Signals) => {
    if (signalled) return;
    signalled = signal;
    log.info("supervise", "signal-received", { signal });
    void shutdown(children);
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  const first = await firstExit(children);
  log.info("supervise", "child-exited", { child: first.name, code: first.code });

  await shutdown(children);

  // Whichever child went down first supplies the unit's exit code, so `update_apply`
  // (control) and crashes alike cycle the unit from the refreshed `current`.
  process.exit(signalled ? exitCodeFor(null, signalled) : first.code);
}

main().catch((error) => {
  log.error("supervise", "fatal", {
    message: error instanceof Error ? error.message : String(error),
  });
  process.exit(1);
});
