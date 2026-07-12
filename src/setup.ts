import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { downloadAndVerify, fetchRequiredManifest } from "./update";
import { claimMachineNode } from "./node/machine";
import { loadConfig, loadJoinAuthorization, loadSetupProgress, saveSetupProgress, stateDir, type SetupProgress } from "./node/state";
import { mergeWalletAddresses, openWalletAddressPage, startWalletAddressServer, validateWalletAddresses } from "./registration/wallet-capture";

const DEFAULT_SERVER_URL = "https://consensus.canister.software";
const DEFAULT_INSTALL_DIR = path.join(process.env.HOME ?? ".", ".consensus", "node-runtime");
const DEFAULT_PM2_NAME = "consensus-node-control";

async function main(): Promise<void> {
  const rl = readline.createInterface({ input, output });
  try {
    let progress = await loadSetupProgress();
    printWelcome();
    if (!await confirm(rl, "Continue with node setup?", false)) return;

    const serverUrl = await question(rl, "Consensus server URL", progress.serverUrl ?? DEFAULT_SERVER_URL);
    const installDir = await question(rl, "Runtime install directory", progress.installDir ?? DEFAULT_INSTALL_DIR);
    progress = await remember(progress, { serverUrl, installDir });

    await ensureBunAvailable(rl);
    await ensurePm2Available(rl);
    console.log("\nFetching approved release manifest from Consensus server...");
    const manifest = await fetchRequiredManifest(serverUrl);
    console.log("\nApproved release:");
    console.log(`  version: ${manifest.version}`);
    console.log(`  platform: ${manifest.platform}`);
    console.log(`  commit: ${manifest.commit}`);
    console.log(`  sha256: ${manifest.tarball_sha256 ?? "(not provided)"}`);
    console.log(`  url: ${manifest.download_url ?? "(not provided)"}`);

    const installCurrent = path.join(installDir, "current");
    const canReuseInstall = progress.installedVersion === manifest.version && await pathExists(installCurrent);
    if (canReuseInstall && await confirm(rl, `Use existing installed runtime ${manifest.version}?`, true)) {
      console.log(`Using existing runtime: ${installCurrent}`);
    } else {
      if (!await confirm(rl, "Download and install this approved release?", false)) return;
      console.log("Downloading and verifying release artifact...");
      const artifact = await downloadAndVerify(manifest);
      console.log("Installing verified release artifact...");
      await runScript("scripts/install-release.sh", [], {
        CONSENSUS_NODE_INSTALL_DIR: installDir,
        CONSENSUS_NODE_ARTIFACT_PATH: artifact.path,
        CONSENSUS_NODE_TARGET_VERSION: manifest.version,
      });
      progress = await remember(progress, { installedVersion: manifest.version });
    }

    console.log("\nDetecting public IPv4...");
    const publicIpv4 = await detectPublicIpv4();
    progress = await remember(progress, { publicIpv4 });
    console.log("Scanning for public IPv6...");
    const publicIpv6 = await detectPublicIpv6().catch(() => null);
    progress = await remember(progress, { publicIpv6 });
    console.log("Classifying region from IPv4...");
    const region = await fetchRegion(serverUrl, publicIpv4).catch((error) => {
      console.warn(`Region classification failed: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    });
    progress = await remember(progress, { region });

    console.log("\nDetected network:");
    console.log(`  IPv4: ${publicIpv4}`);
    console.log(`  IPv6: ${publicIpv6 ?? "(none detected)"}`);
    if (region) console.log(`  region: ${region.region} (${region.city ?? "unknown"}, ${region.country_code})`);

    const joinAuth = await loadJoinAuthorization();
    if (joinAuth && joinAuth.expires_at > Math.floor(Date.now() / 1000) + 60 && await confirm(rl, `Reuse valid eval join authorization ${joinAuth.join_id}?`, true)) {
      console.log(`Using existing join authorization. Expires at ${joinAuth.expires_at}.`);
    } else {
      console.log("\nRunning encrypted evaluation. This may take a moment.");
      await runBunInCurrent(installDir, ["run", "eval"], {
        CONSENSUS_SERVER_URL: serverUrl,
        CONSENSUS_STATE_DIR: stateDir(),
      });
      progress = await remember(progress, { evalPassedAt: new Date().toISOString() });
    }

    const contact = await requiredQuestion(rl, "Contact email", progress.contact);
    progress = await remember(progress, { contact });
    const reusableEmailToken = progress.emailVerificationToken &&
      progress.emailVerificationExpiresAt &&
      progress.emailVerificationExpiresAt > Math.floor(Date.now() / 1000) + 60;
    const emailToken = reusableEmailToken && await confirm(rl, `Reuse verified email token for ${contact}?`, true)
      ? progress.emailVerificationToken!
      : await verifyEmail(rl, serverUrl, contact).then(async (verified) => {
        progress = await remember(progress, {
          emailVerificationToken: verified.token,
          emailVerificationExpiresAt: verified.expires_at,
        });
        return verified.token;
      });

    console.log("\nRegistration requires payout addresses.");
    progress = await collectWalletAddresses(rl, progress);
    const evm = await requiredQuestion(rl, "EVM address", progress.evmAddress);
    progress = await remember(progress, { evmAddress: evm });
    const solana = await requiredQuestion(rl, "Solana address", progress.solanaAddress);
    progress = await remember(progress, { solanaAddress: solana });
    const icp = await requiredQuestion(rl, "ICP address", progress.icpAddress);
    progress = await remember(progress, { icpAddress: icp });
    const port = await question(rl, "Node local port", progress.port ?? "9090");
    progress = await remember(progress, { port });

    const existingConfig = await loadConfig();
    if (existingConfig.node_id && await confirm(rl, `Node already registered as ${existingConfig.node_id}; skip registration?`, true)) {
      await claimMachineNode({ nodeId: existingConfig.node_id, installDir });
      console.log("\nSetup complete.");
      console.log(`Node ID: ${existingConfig.node_id}`);
      if (existingConfig.domain) console.log(`Domain: ${existingConfig.domain}`);
      console.log(`Runtime: ${installDir}/current`);
      console.log(`State: ${stateDir()}`);
      await offerStartPm2(rl, installDir, serverUrl);
      return;
    }

    console.log("\nSubmitting node registration...");
    await runBunInCurrent(installDir, ["run", "register"], {
      CONSENSUS_SERVER_URL: serverUrl,
      CONSENSUS_STATE_DIR: stateDir(),
      CONSENSUS_NODE_IPV4: publicIpv4,
      ...(publicIpv6 ? { CONSENSUS_NODE_IPV6: publicIpv6 } : {}),
      CONSENSUS_NODE_PORT: port,
      CONSENSUS_NODE_CONTACT: contact,
      CONSENSUS_EMAIL_VERIFICATION_TOKEN: emailToken,
      CONSENSUS_EVM_ADDRESS: evm,
      CONSENSUS_SOLANA_ADDRESS: solana,
      CONSENSUS_ICP_ADDRESS: icp,
    });

    console.log("\nSetup complete.");
    console.log(`Runtime: ${installDir}/current`);
    console.log(`State: ${stateDir()}`);
    await offerStartPm2(rl, installDir, serverUrl);
  } finally {
    rl.close();
  }
}

function printWelcome(): void {
  console.log(`
Consensus Node Setup

This machine is attempting to become a dedicated node in the Consensus network.
The network provides proxy, websocket, and tunnel services. This machine will be
benchmarked for its ability to serve those requests. If successful, it will be
commissioned into the network and expected to remain available 24/7. If it is
not reliably available, it may be discarded from the network.

IPv4 is required. IPv6 is optional. A custom domain will be issued for this node,
and this machine's public IP may be made available for public network use.
`);
}

async function verifyEmail(rl: readline.Interface, serverUrl: string, email: string): Promise<{ token: string; expires_at: number }> {
  const started = await postJson<{ verification_id: string; expires_at: number; dev_code?: string }>(
    `${trimTrailingSlash(serverUrl)}/node/email/start`,
    { email },
  );
  console.log(`Verification code sent to ${email}.`);
  if (started.dev_code) console.log(`Development code: ${started.dev_code}`);
  const code = await requiredQuestion(rl, "Email verification code");
  const verified = await postJson<{ email_verification_token: string; expires_at: number }>(
    `${trimTrailingSlash(serverUrl)}/node/email/verify`,
    { email, verification_id: started.verification_id, code },
  );
  return { token: verified.email_verification_token, expires_at: verified.expires_at };
}

async function fetchRegion(serverUrl: string, ipv4: string): Promise<{ region: string; city?: string; country_code: string }> {
  const response = await fetch(`${trimTrailingSlash(serverUrl)}/node/region/${encodeURIComponent(ipv4)}`, {
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json() as { region: string; city?: string; country_code: string };
}

async function detectPublicIpv4(): Promise<string> {
  const response = await fetch("https://api4.ipify.org?format=json", { signal: AbortSignal.timeout(10_000) });
  const body = await response.json() as { ip?: string };
  if (!body.ip) throw new Error("Unable to detect public IPv4");
  return body.ip;
}

async function detectPublicIpv6(): Promise<string | null> {
  const response = await fetch("https://api6.ipify.org?format=json", { signal: AbortSignal.timeout(5_000) });
  const body = await response.json() as { ip?: string };
  return body.ip ?? null;
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  const parsed = await response.json().catch(() => null) as (T & { message?: string; error?: string }) | null;
  if (!response.ok) throw new Error(parsed?.message ?? parsed?.error ?? `HTTP ${response.status}`);
  if (!parsed) throw new Error("Malformed JSON response");
  return parsed;
}

async function ensureBunAvailable(rl: readline.Interface): Promise<void> {
  const existing = await resolveExecutable("bun", bunFallbackPaths());
  if (existing) {
    addExecutableDirToPath(existing);
    await run(existing, ["--version"], {});
    return;
  }

  console.log("\nBun is required to install and run the Consensus node runtime.");
  if (!await confirm(rl, "Install Bun now?", false)) {
    throw new Error("Bun is required. Run `scripts/ensure-bun.sh`, then rerun setup.");
  }

  await runScript("scripts/ensure-bun.sh", ["--yes"], {});
  const bun = await resolveExecutable("bun", bunFallbackPaths());
  if (!bun) throw new Error("Bun installed, but bun was not found on PATH or in standard locations.");
  addExecutableDirToPath(bun);
  await run(bun, ["--version"], {});
}

async function ensurePm2Available(rl: readline.Interface): Promise<void> {
  const existing = await resolveExecutable("pm2", pm2FallbackPaths());
  if (existing) {
    addExecutableDirToPath(existing);
    await run(existing, ["--version"], {});
    return;
  }

  console.log("\nPM2 is required for the recommended node process manager.");
  if (!await confirm(rl, "Install PM2 and any missing macOS dependencies now?", false)) {
    throw new Error("PM2 is required. Run `scripts/ensure-pm2.sh`, then rerun setup.");
  }

  await runScript("scripts/ensure-pm2.sh", ["--yes"], {});
  const pm2 = await resolveExecutable("pm2", pm2FallbackPaths());
  if (!pm2) throw new Error("PM2 installed, but pm2 was not found on PATH or in standard Homebrew locations.");
  addExecutableDirToPath(pm2);
  await run(pm2, ["--version"], {});
}

async function offerStartPm2(rl: readline.Interface, installDir: string, serverUrl: string): Promise<void> {
  const appName = process.env.CONSENSUS_PM2_NAME?.trim() || DEFAULT_PM2_NAME;
  const configPath = path.join(installDir, "current", "ecosystem.config.cjs");
  if (!await pathExists(configPath)) {
    console.log(`PM2 config not found at ${configPath}. Start PM2 after installing a release that includes it.`);
    return;
  }

  if (!await confirm(rl, "Start the PM2 supervised control tunnel now?", true)) {
    console.log(`Start later with: ${path.join(installDir, "current", "scripts", "start-pm2.sh")}`);
    return;
  }

  const nodeStateDir = stateDir();
  await fs.mkdir(nodeStateDir, { recursive: true });
  const pm2 = await resolveExecutable("pm2", pm2FallbackPaths());
  if (!pm2) throw new Error("PM2 is not available. Run `scripts/ensure-pm2.sh`, then rerun setup.");
  addExecutableDirToPath(pm2);
  await run(pm2, ["startOrReload", configPath, "--only", appName, "--update-env"], {
    CONSENSUS_SERVER_URL: serverUrl,
    CONSENSUS_STATE_DIR: nodeStateDir,
    CONSENSUS_NODE_INSTALL_DIR: installDir,
    CONSENSUS_NODE_RELEASE_RETENTION: process.env.CONSENSUS_NODE_RELEASE_RETENTION?.trim() || "3",
    CONSENSUS_PM2_NAME: appName,
    CONSENSUS_NODE_UPDATE_COMMAND: path.join(installDir, "current", "scripts", "install-release.sh"),
  });
  await verifyPm2Online(pm2, appName);
  await run(pm2, ["save"], {});

  console.log(`PM2 is managing ${appName}.`);
  console.log(`Logs: pm2 logs ${appName}`);
  console.log("For reboot persistence, run `pm2 startup`, follow its printed command, then run `pm2 save`.");
}

async function collectWalletAddresses(rl: readline.Interface, progress: SetupProgress): Promise<SetupProgress> {
  console.log("A local browser page can connect MetaMask, Phantom, and Plug to read public wallet addresses.");
  if (!await confirm(rl, "Use browser wallet connection?", true)) return progress;

  const session = await startWalletAddressServer({
    initialAddresses: {
      evmAddress: progress.evmAddress,
      solanaAddress: progress.solanaAddress,
      icpAddress: progress.icpAddress,
    },
  });

  console.log(`Wallet address page: ${session.url}`);
  if (shouldOpenWalletAddressPage()) {
    await openWalletAddressPage(session.url).catch((error) => {
      console.warn(`Could not open browser automatically: ${error instanceof Error ? error.message : String(error)}`);
    });
  }

  const abort = new AbortController();
  const submitted = session.done.then((addresses) => {
    abort.abort();
    return { type: "submitted" as const, addresses };
  });
  const skipped = rl.question("Submit addresses in the browser, or press Enter here to type them manually: ", {
    signal: abort.signal,
  }).then(() => ({ type: "skipped" as const })).catch((error) => {
    if (error instanceof Error && error.name === "AbortError") return { type: "aborted" as const };
    throw error;
  });

  try {
    const result = await Promise.race([submitted, skipped]);
    if (result.type !== "submitted") return progress;

    const addresses = mergeWalletAddresses({
      evmAddress: progress.evmAddress,
      solanaAddress: progress.solanaAddress,
      icpAddress: progress.icpAddress,
    }, result.addresses);
    const errors = validateWalletAddresses(addresses);
    if (Object.keys(errors).length > 0) {
      console.warn("Browser wallet submission included invalid addresses; falling back to terminal prompts.");
      for (const message of Object.values(errors)) console.warn(`  ${message}`);
      return progress;
    }

    console.log("Wallet addresses received from browser.");
    return await remember(progress, {
      evmAddress: addresses.evmAddress,
      solanaAddress: addresses.solanaAddress,
      icpAddress: addresses.icpAddress,
    });
  } finally {
    await session.stop().catch(() => {});
  }
}

function shouldOpenWalletAddressPage(): boolean {
  return process.env.CONSENSUS_WALLET_CAPTURE_OPEN?.trim() !== "0";
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function runScript(script: string, args: string[], env: Record<string, string>): Promise<void> {
  await fs.access(script);
  await run(script, args, env);
}

async function runBunInCurrent(installDir: string, args: string[], env: Record<string, string>): Promise<void> {
  await run("bun", args, env, path.join(installDir, "current"));
}

async function run(command: string, args: string[], env: Record<string, string>, cwd = process.cwd()): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: "inherit",
    });
    child.on("exit", (code) => code === 0 ? resolve() : reject(new Error(`${command} exited with code ${code}`)));
    child.on("error", reject);
  });
}

async function verifyPm2Online(pm2: string, appName: string): Promise<void> {
  await sleep(pm2VerifyDelayMs());
  const output = await runForOutput(pm2, ["jlist"]);
  const status = pm2StatusFromJlist(output, appName);
  if (status !== "online") {
    throw new Error(`PM2 accepted ${appName}, but it did not reach online status (status: ${status || "missing"}). Run \`pm2 logs ${appName}\` for details.`);
  }
}

async function runForOutput(command: string, args: string[], cwd = process.cwd()): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on("exit", (code) => code === 0 ? resolve(stdout) : reject(new Error(stderr.trim() || `${command} exited with code ${code}`)));
    child.on("error", reject);
  });
}

function pm2StatusFromJlist(output: string, appName: string): string | null {
  try {
    const apps = JSON.parse(output) as Array<{ name?: string; pm2_env?: { status?: string } }>;
    const app = Array.isArray(apps) ? apps.find((candidate) => candidate.name === appName) : null;
    return app?.pm2_env?.status ?? null;
  } catch {
    return null;
  }
}

function pm2VerifyDelayMs(): number {
  const seconds = Number(process.env.CONSENSUS_PM2_VERIFY_DELAY_SECONDS ?? "2");
  return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : 2000;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function commandSucceeds(command: string, args: string[]): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const child = spawn(command, args, {
      stdio: "ignore",
    });
    child.on("exit", (code) => resolve(code === 0));
    child.on("error", () => resolve(false));
  });
}

async function resolveExecutable(command: string, fallbackPaths: string[] = []): Promise<string | null> {
  const found = await which(command);
  if (found) return found;

  for (const candidate of fallbackPaths) {
    if (await pathExists(candidate)) return candidate;
  }

  return null;
}

function bunFallbackPaths(): string[] {
  return [
    path.join(process.env.HOME ?? ".", ".bun", "bin", "bun"),
    "/opt/homebrew/bin/bun",
    "/usr/local/bin/bun",
  ];
}

function pm2FallbackPaths(): string[] {
  return [
    "/opt/homebrew/bin/pm2",
    "/usr/local/bin/pm2",
  ];
}

function addExecutableDirToPath(executable: string): void {
  const dir = path.dirname(executable);
  const current = process.env.PATH ?? "";
  if (!current.split(path.delimiter).includes(dir)) {
    process.env.PATH = `${dir}${path.delimiter}${current}`;
  }
}

async function which(command: string): Promise<string | null> {
  return await new Promise<string | null>((resolve) => {
    const child = spawn("sh", ["-lc", `command -v ${shellQuote(command)}`], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    let stdout = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.on("exit", (code: number | null) => resolve(code === 0 ? stdout.trim() || null : null));
    child.on("error", () => resolve(null));
  });
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

async function question(rl: readline.Interface, prompt: string, fallback: string): Promise<string> {
  const answer = (await rl.question(`${prompt} [${fallback}]: `)).trim();
  return answer || fallback;
}

async function requiredQuestion(rl: readline.Interface, prompt: string, fallback?: string): Promise<string> {
  while (true) {
    const suffix = fallback ? ` [${fallback}]` : "";
    const answer = (await rl.question(`${prompt}${suffix}: `)).trim();
    if (answer) return answer;
    if (fallback) return fallback;
  }
}

async function confirm(rl: readline.Interface, prompt: string, fallback: boolean): Promise<boolean> {
  const suffix = fallback ? "Y/n" : "y/N";
  const answer = (await rl.question(`${prompt} [${suffix}]: `)).trim().toLowerCase();
  if (!answer) return fallback;
  return answer === "y" || answer === "yes";
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

async function remember(progress: SetupProgress, patch: Partial<SetupProgress>): Promise<SetupProgress> {
  const next = { ...progress, ...patch };
  await saveSetupProgress(next);
  return next;
}

main().catch((error) => {
  console.error("Setup failed:", error);
  process.exit(1);
});
