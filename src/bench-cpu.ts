// Standalone CPU judgment tool: `bun run bench:cpu [--json] [--quick] [--sustained-seconds N]`
//
// Answers one question — what can this machine's CPU do for Consensus? — with
// zero orchestrator/tunnel/registration involvement, so any machine can be
// judged before (or without) joining the network. The encrypted eval will later
// invoke the same suites; this entry point is their home, the eval a consumer.
//
// Suites run STRICTLY sequentially (never overlapping — concurrent suites
// contend for the CPU and corrupt each other's numbers):
//
//   1. system            hardware/runtime inventory (context, not a score)
//   2. event-loop        baseline scheduling jitter — a noisy baseline means
//                        something else is running; results are flagged
//   3. composite         the headline: the node's real per-request data-plane
//                        pipeline in memory (see suites/composite-request.ts)
//   4. primitives        sha256 + ChaCha20-Poly1305 diagnostics (why-slow detail)
//   5. sustained         60s of continuous composite load, windowed — burst-credit
//                        vCPUs and thermally throttled SBCs decay here
//                        (runs BEFORE multi-core so all-core heat cannot
//                        pre-throttle the single-core steady-state read)
//   6. multi-core        K workers × sequential sha256 chains — real vs
//                        advertised cores, oversubscription, P/E-core mix
//   7. event-loop again  drift vs. baseline — detects contention DURING the run
//
// --quick                composite only, short windows (fast signal while iterating)
// --sustained-seconds N  sustained window length (default 60; 0 skips the suite)
// --json                 full machine-readable report on stdout
//
// A default run takes ~1.5 minutes, dominated by the sustained window — that is
// the point: short benchmarks only ever measure the burst. Exit code is always
// 0 when the run completes: this version measures and reports. Pass/fail
// thresholds come later, calibrated from these reports across reference
// hardware.

import { hrtime } from "node:process";
import {
  runCpuHash,
  runCryptoAead,
  runEventLoop,
  runSystem,
  type CpuHashResult,
  type CryptoAeadResult,
  type EventLoopResult,
  type SystemResult,
} from "./runtime/benchmarks/index";
import {
  runCompositeRequest,
  type CompositeRequestResult,
  type CompositeStageName,
} from "./runtime/benchmarks/suites/composite-request";
import {
  runSustained,
  STEADY_RATIO_FLOOR,
  type SustainedResult,
} from "./runtime/benchmarks/suites/sustained";
import { runMultiCore, type MultiCoreResult } from "./runtime/benchmarks/suites/multi-core";

// Above this baseline p99 the machine is visibly busy with something else and
// per-stage numbers stop being trustworthy. 2ms is ~40x a healthy idle p99.
const BASELINE_P99_WARN_NS = 2_000_000;
// Post-run jitter this much worse than baseline means contention appeared
// mid-run (browser tab, cron job, thermal event) — treat the run as suspect.
const DRIFT_FACTOR_WARN = 4;
// Sustained cpu_time_ratio below this means the process was not getting a full
// core — hypervisor steal or host contention, not necessarily slow silicon.
const CPU_TIME_RATIO_WARN = 0.9;

interface CpuBenchReport {
  meta: {
    tool: "consensus-cpu-bench";
    version: 2;
    started_at: string;
    duration_ms: number;
    quick: boolean;
  };
  system: SystemResult;
  event_loop: { baseline: EventLoopResult; post: EventLoopResult | null };
  composite: CompositeRequestResult;
  primitives: { cpu_hash: CpuHashResult | null; crypto_aead: CryptoAeadResult | null };
  character: { sustained: SustainedResult | null; multi_core: MultiCoreResult | null };
  /** Headline: node-side requests/sec at 16KB responses, single core. */
  requests_per_second: number;
  reliable: boolean;
  warnings: string[];
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    return;
  }
  const json = args.includes("--json");
  const quick = args.includes("--quick");
  const sustainedSeconds = numberFlag(args, "--sustained-seconds", 60);

  const startedAt = new Date().toISOString();
  const t0 = hrtime.bigint();
  const warnings: string[] = [];
  const say = (line: string): void => {
    if (!json) console.log(line);
  };

  say("Consensus CPU bench — judging this machine's per-request capacity\n");

  const system = runSystem();
  say(`  machine    ${system.platform}/${system.arch}, ${system.cpus} cpus, ${gb(system.total_memory_bytes)} RAM, bun ${system.bun_version}`);

  say("  baseline   measuring event-loop jitter...");
  const baseline = await runEventLoop();
  // Note: the event-loop suite's own `reliable` flag is not meaningful here —
  // setImmediate latency is naturally bimodal, so its CV is always high. The
  // p99 threshold below is the actual busy-machine signal.
  say(`             p99 ${us(baseline.ns_per_op.p99)}`);
  if (baseline.ns_per_op.p99 > BASELINE_P99_WARN_NS) {
    warnings.push(
      `baseline event-loop p99 is ${us(baseline.ns_per_op.p99)} (> ${us(BASELINE_P99_WARN_NS)}): the machine looks busy — close other workloads and rerun`,
    );
  }

  say(quick ? "  composite  running (quick windows)..." : "  composite  running...");
  const composite = await runCompositeRequest(
    quick ? { warmupMs: 50, measureMs: 300 } : {},
  );

  let cpuHash: CpuHashResult | null = null;
  let cryptoAead: CryptoAeadResult | null = null;
  let sustained: SustainedResult | null = null;
  let multiCore: MultiCoreResult | null = null;
  let post: EventLoopResult | null = null;

  if (!quick) {
    say("  primitives sha256 + chacha20-poly1305 diagnostics...");
    cpuHash = await runCpuHash();
    cryptoAead = await runCryptoAead();

    if (sustainedSeconds > 0) {
      say(`  sustained  ${sustainedSeconds}s of continuous load @16KB (watching for throttle)...`);
      sustained = await runSustained({ durationMs: sustainedSeconds * 1000 });
      if (!sustained.steady) {
        warnings.push(
          `throttle ratio ${sustained.throttle_ratio} (< ${STEADY_RATIO_FLOOR}): throughput decayed under sustained load — burst credits or thermal throttling`,
        );
      }
      if (sustained.cpu_time_ratio < CPU_TIME_RATIO_WARN) {
        warnings.push(
          `cpu time ratio ${sustained.cpu_time_ratio} (< ${CPU_TIME_RATIO_WARN}): the process was not getting a full core — hypervisor steal or host contention`,
        );
      }
    }

    say("  multi-core scaling across workers...");
    multiCore = await runMultiCore();

    // Let worker teardown settle before the drift check, so a transient from
    // terminating N workers is not misread as background contention. A machine
    // that is genuinely busy will still show elevated p99 after this.
    await new Promise((resolve) => setTimeout(resolve, 250));
    Bun.gc(true);
    post = await runEventLoop();
    if (post.ns_per_op.p99 > baseline.ns_per_op.p99 * DRIFT_FACTOR_WARN) {
      warnings.push(
        `event-loop p99 drifted ${us(baseline.ns_per_op.p99)} -> ${us(post.ns_per_op.p99)} during the run: background contention likely — results are suspect`,
      );
    }
  }

  if (!composite.reliable) {
    warnings.push(
      "composite variance exceeded 10% (reliable: false) — do not act on these numbers; rerun on an idle machine",
    );
  }

  const report: CpuBenchReport = {
    meta: {
      tool: "consensus-cpu-bench",
      version: 2,
      started_at: startedAt,
      duration_ms: Math.round(Number(hrtime.bigint() - t0) / 1e6),
      quick,
    },
    system,
    event_loop: { baseline, post },
    composite,
    primitives: { cpu_hash: cpuHash, crypto_aead: cryptoAead },
    character: { sustained, multi_core: multiCore },
    requests_per_second: composite.requests_per_second,
    reliable: composite.reliable && warnings.length === 0,
    warnings,
  };

  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  printSummary(report);
}

function printSummary(report: CpuBenchReport): void {
  console.log("\n  ── composite: node-side requests/sec (single core) ──");
  for (const sub of report.composite.results) {
    console.log(
      `  ${kb(sub.response_size_bytes).padStart(6)}  ${fmtRps(sub.node_requests_per_second).padStart(9)} req/s   ` +
        `${msPerReq(sub.node_ns_per_request)} ms/req   cv ${(sub.exchange.cv * 100).toFixed(1)}%${sub.reliable ? "" : "  UNRELIABLE"}`,
    );
  }

  const headline = report.composite.results.find((r) => r.response_size_bytes === 16384);
  if (headline) {
    console.log("\n  ── where the time goes (@16KB) ──");
    for (const stage of Object.keys(headline.stages) as CompositeStageName[]) {
      const s = headline.stages[stage];
      console.log(
        `  ${stage.padEnd(16)} ${us(s.mean_ns).padStart(9)}  ${bar(s.share)} ${(s.share * 100).toFixed(0)}%`,
      );
    }
  }

  const sustained = report.character.sustained;
  if (sustained) {
    console.log(`\n  ── sustained: ${Math.round(sustained.duration_ms / 1000)}s continuous @16KB ──`);
    console.log(`  windows (node req/s): ${sustained.windows.map((w) => Math.round(w.node_rps)).join("  ")}`);
    console.log(
      `  early ${Math.round(sustained.node_rps_early)} → late ${Math.round(sustained.node_rps_late)} req/s   ` +
        `throttle ratio ${sustained.throttle_ratio}${sustained.steady ? " (steady)" : "  DECAYING"}`,
    );
    console.log(`  cpu time ratio ${sustained.cpu_time_ratio} — ${sustained.cpu_time_ratio >= CPU_TIME_RATIO_WARN ? "process owned its core" : "CORE WAS SHARED (steal/contention)"}`);
  }

  const multiCore = report.character.multi_core;
  if (multiCore) {
    console.log(`\n  ── multi-core scaling (int-mix chains, ${multiCore.cores} advertised cores) ──`);
    for (const point of multiCore.points) {
      console.log(
        `  ${String(point.workers).padStart(3)} workers  ${fmtOps(point.total_ops_per_second).padStart(10)} ops/s total   efficiency ${(point.efficiency * 100).toFixed(0)}%`,
      );
    }
    console.log(`  effective cores: ~${multiCore.effective_cores} of ${multiCore.cores} advertised`);
  }

  if (report.primitives.cpu_hash && report.primitives.crypto_aead) {
    console.log("\n  ── primitives (diagnostics) ──");
    console.log(`  sha256 @1KB          ${mbps(report.primitives.cpu_hash.bytes_per_second)}`);
    console.log(`  chacha20-poly1305    ${mbps(report.primitives.crypto_aead.total_bytes_per_second)} round-trip @1KB`);
  }

  console.log(`\n  headline: ~${fmtRps(report.requests_per_second)} req/s @16KB, single core`);
  for (const warning of report.warnings) console.log(`  ⚠ ${warning}`);
  console.log(`  ${report.reliable ? "measurement reliable" : "measurement NOT reliable"} — ${(report.meta.duration_ms / 1000).toFixed(1)}s total\n`);
}

function printHelp(): void {
  console.log(`Usage: bun run bench:cpu [options]

Judge what this machine's CPU can do as a Consensus node: runs the real
per-request data-plane pipeline (handshake, ticket verify, AEAD, encode)
in memory and reports single-core requests/sec by response size, then
character tests — sustained load (throttle detection) and multi-core
scaling (real vs advertised cores).

Options:
  --quick                 composite suite only, short measurement windows
  --sustained-seconds N   sustained window length (default 60; 0 skips)
  --json                  print the full machine-readable report to stdout
  --help                  this text

A default run takes ~1.5 minutes; most of it is the sustained window,
deliberately — short benchmarks only ever measure the burst.
`);
}

function numberFlag(args: string[], name: string, fallback: number): number {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  const value = Number(args[index + 1]);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} expects a non-negative number, got: ${args[index + 1] ?? "(nothing)"}`);
  }
  return value;
}

const fmtRps = (v: number): string => (v >= 100 ? Math.round(v).toString() : v.toFixed(1));
const fmtOps = (v: number): string =>
  v >= 1e6 ? `${(v / 1e6).toFixed(2)}M` : v >= 1e3 ? `${(v / 1e3).toFixed(0)}k` : Math.round(v).toString();
const msPerReq = (ns: number): string => (ns / 1e6).toFixed(2);
const us = (ns: number): string => `${(ns / 1000).toFixed(0)}µs`;
const kb = (bytes: number): string => `${Math.round(bytes / 1024)}KB`;
const gb = (bytes: number): string => `${(bytes / 1024 / 1024 / 1024).toFixed(1)}GB`;
const mbps = (bps: number): string => `${(bps / 1024 / 1024).toFixed(0)} MB/s`;
const bar = (share: number): string => "█".repeat(Math.max(1, Math.round(share * 24))).padEnd(24);

await main();
