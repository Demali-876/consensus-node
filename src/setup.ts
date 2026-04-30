import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { downloadAndVerify, fetchRequiredManifest } from "./update";
import { stateDir } from "./node/state";

const DEFAULT_SERVER_URL = "https://consensus.canister.software";
const DEFAULT_INSTALL_DIR = path.join(process.env.HOME ?? ".", ".consensus", "node-runtime");

async function main(): Promise<void> {
  const rl = readline.createInterface({ input, output });
  try {
    printWelcome();
    if (!await confirm(rl, "Continue with node setup?", false)) return;

    const serverUrl = await question(rl, "Consensus server URL", DEFAULT_SERVER_URL);
    const installDir = await question(rl, "Runtime install directory", DEFAULT_INSTALL_DIR);

    await assertBunAvailable();
    const manifest = await fetchRequiredManifest(serverUrl);
    console.log("\nApproved release:");
    console.log(`  version: ${manifest.version}`);
    console.log(`  platform: ${manifest.platform}`);
    console.log(`  commit: ${manifest.commit}`);
    console.log(`  sha256: ${manifest.tarball_sha256 ?? "(not provided)"}`);
    console.log(`  url: ${manifest.download_url ?? "(not provided)"}`);

    if (!await confirm(rl, "Download and install this approved release?", false)) return;
    const artifact = await downloadAndVerify(manifest);
    await runScript("scripts/install-release.sh", [], {
      CONSENSUS_NODE_INSTALL_DIR: installDir,
      CONSENSUS_NODE_ARTIFACT_PATH: artifact.path,
      CONSENSUS_NODE_TARGET_VERSION: manifest.version,
    });

    const publicIpv4 = await detectPublicIpv4();
    const publicIpv6 = await detectPublicIpv6().catch(() => null);
    const region = await fetchRegion(serverUrl, publicIpv4).catch((error) => {
      console.warn(`Region classification failed: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    });

    console.log("\nDetected network:");
    console.log(`  IPv4: ${publicIpv4}`);
    console.log(`  IPv6: ${publicIpv6 ?? "(none detected)"}`);
    if (region) console.log(`  region: ${region.region} (${region.city ?? "unknown"}, ${region.country_code})`);

    console.log("\nRunning encrypted evaluation. This may take a moment.");
    await runBunInCurrent(installDir, ["run", "eval"], {
      CONSENSUS_SERVER_URL: serverUrl,
      CONSENSUS_STATE_DIR: stateDir(),
    });

    const contact = await requiredQuestion(rl, "Contact email");
    const emailToken = await verifyEmail(rl, serverUrl, contact);

    console.log("\nRegistration requires payout addresses.");
    const evm = await requiredQuestion(rl, "EVM address");
    const solana = await requiredQuestion(rl, "Solana address");
    const icp = await requiredQuestion(rl, "ICP address");
    const port = await question(rl, "Node local port", "9090");
    const testEndpoint = await requiredQuestion(rl, "Public benchmark endpoint URL");

    await runBunInCurrent(installDir, ["run", "register"], {
      CONSENSUS_SERVER_URL: serverUrl,
      CONSENSUS_STATE_DIR: stateDir(),
      CONSENSUS_NODE_IPV4: publicIpv4,
      ...(publicIpv6 ? { CONSENSUS_NODE_IPV6: publicIpv6 } : {}),
      CONSENSUS_NODE_PORT: port,
      CONSENSUS_NODE_TEST_ENDPOINT: testEndpoint,
      CONSENSUS_NODE_CONTACT: contact,
      CONSENSUS_EMAIL_VERIFICATION_TOKEN: emailToken,
      CONSENSUS_EVM_ADDRESS: evm,
      CONSENSUS_SOLANA_ADDRESS: solana,
      CONSENSUS_ICP_ADDRESS: icp,
    });

    console.log("\nSetup complete.");
    console.log(`Runtime: ${installDir}/current`);
    console.log(`State: ${stateDir()}`);
    console.log("Next: install the launchd/systemd service, then start the control tunnel.");
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

async function verifyEmail(rl: readline.Interface, serverUrl: string, email: string): Promise<string> {
  const started = await postJson<{ verification_id: string; expires_at: number; dev_code?: string }>(
    `${trimTrailingSlash(serverUrl)}/node/email/start`,
    { email },
  );
  console.log(`Verification code sent to ${email}.`);
  if (started.dev_code) console.log(`Development code: ${started.dev_code}`);
  const code = await requiredQuestion(rl, "Email verification code");
  const verified = await postJson<{ email_verification_token: string }>(
    `${trimTrailingSlash(serverUrl)}/node/email/verify`,
    { email, verification_id: started.verification_id, code },
  );
  return verified.email_verification_token;
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

async function assertBunAvailable(): Promise<void> {
  await run("bun", ["--version"], {});
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

async function question(rl: readline.Interface, prompt: string, fallback: string): Promise<string> {
  const answer = (await rl.question(`${prompt} [${fallback}]: `)).trim();
  return answer || fallback;
}

async function requiredQuestion(rl: readline.Interface, prompt: string): Promise<string> {
  while (true) {
    const answer = (await rl.question(`${prompt}: `)).trim();
    if (answer) return answer;
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

main().catch((error) => {
  console.error("Setup failed:", error);
  process.exit(1);
});
