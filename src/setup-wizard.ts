import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { claimMachineNode } from "./node/machine";
import { loadConfig, loadJoinAuthorization, loadSetupProgress, saveConfig, saveSetupProgress, stateDir, type SetupProgress } from "./node/state";
import { renderConnectionHtml, renderInstallHtml, renderNetworkHtml, renderRegistrationHtml, renderSuccessHtml, renderWelcomeHtml, setupWizardTemplateVersion } from "./setup-wizard/render";
import { downloadAndVerify, fetchRequiredManifest } from "./update";
import { mergeWalletAddresses, startWalletAddressServer, validateWalletAddresses, type WalletAddressSession, type WalletAddresses } from "./registration/wallet-capture";
import type { NodeConfig, ReleaseManifest } from "./types";

const DEFAULT_HOST = "127.0.0.1";
const AGREEMENT_VERSION = "node-operator-good-faith-v2";
const DEFAULT_SERVER_URL = "https://consensus.canister.software";
const DEFAULT_INSTALL_DIR = path.join(os.homedir(), ".consensus", "node-runtime");
const DEFAULT_PM2_NAME = "consensus-node-control";
const SERVER_START_ID = randomUUID();
const DEV_RELOAD = process.env.CONSENSUS_SETUP_WIZARD_DEV_RELOAD?.trim() === "1";
const TEST_FLOW = process.env.CONSENSUS_SETUP_WIZARD_TEST_FLOW?.trim() === "1";
const walletSessions = new Map<string, {
  session: WalletAddressSession;
  status: "pending" | "done" | "error";
  addresses?: WalletAddresses;
  error?: string;
}>();
const ASSETS = new Map([
  ["/assets/consensus-logo-light.svg", new URL("./registration/assets/consensus-logo-light.svg", import.meta.url)],
  ["/assets/consensus-logo-dark.svg", new URL("./registration/assets/consensus-logo-dark.svg", import.meta.url)],
  ["/assets/bun-logo.png", new URL("./setup-wizard/assets/bun-logo.png", import.meta.url)],
  ["/assets/pm2-logo.png", new URL("./setup-wizard/assets/pm2-logo.png", import.meta.url)],
]);

export interface SetupWizardSession {
  url: string;
  stop: () => Promise<void>;
}

export async function startSetupWizardServer(options: { host?: string; port?: number; token?: string } = {}): Promise<SetupWizardSession> {
  const token = options.token ?? randomUUID();
  const host = options.host ?? DEFAULT_HOST;
  const server = http.createServer((request, response) => {
    handleNodeRequest(request, response, async (method, url, body) => {
      return await handleWizardRequest({ method, url, body, token });
    }).catch((error) => {
      sendNodeResponse(response, jsonResponse({
        error: error instanceof Error ? error.message : "Setup wizard failed",
      }, 500)).catch(() => {});
    });
  });

  const port = await listen(server, options.port, host);
  return {
    url: `http://${host}:${port}/?token=${encodeURIComponent(token)}`,
    stop: async () => closeServer(server),
  };
}

async function handleWizardRequest(input: {
  method: string;
  url: URL;
  body: unknown;
  token: string;
}): Promise<Response> {
  const { method, url, token } = input;
  if (url.pathname === "/favicon.ico" || url.pathname === "/favicon.svg") return adaptiveFaviconResponse();
  if (url.searchParams.get("token") !== token) {
    return jsonResponse({ error: "Invalid setup wizard token" }, 403);
  }

  if (method === "GET" && ASSETS.has(url.pathname)) return assetResponse(url.pathname);

  if (method === "GET" && url.pathname === "/api/progress") {
    return jsonResponse(progressView(await loadSetupProgress()));
  }

  if (method === "GET" && url.pathname === "/api/environment") {
    return jsonResponse(await environmentView());
  }

  if (method === "GET" && url.pathname === "/api/install-manifest") {
    return installManifestView();
  }

  if (method === "GET" && url.pathname === "/api/network-status") {
    return networkStatus();
  }

  if (method === "GET" && url.pathname === "/api/registration-status") {
    return registrationStatus();
  }

  if (method === "GET" && url.pathname === "/api/reload-version") {
    return jsonResponse({ serverStartId: await setupWizardTemplateVersion(SERVER_START_ID) });
  }

  if (method === "POST" && url.pathname === "/api/operator-agreement") {
    return recordOperatorAgreement(input.body);
  }

  if (method === "POST" && url.pathname === "/api/connection") {
    return recordConnection(input.body);
  }

  if (method === "POST" && url.pathname === "/api/select-install-dir") {
    return selectInstallDir();
  }

  if (method === "POST" && url.pathname === "/api/install-bun") {
    return installBun();
  }

  if (method === "POST" && url.pathname === "/api/install-pm2") {
    return installPm2();
  }

  if (method === "POST" && url.pathname === "/api/runtime-install") {
    return installRuntime(input.body);
  }

  if (method === "POST" && url.pathname === "/api/network-eval") {
    return runNetworkEval(input.body);
  }

  if (method === "POST" && url.pathname === "/api/email/start") {
    return startEmailVerification(input.body);
  }

  if (method === "POST" && url.pathname === "/api/email/verify") {
    return verifyEmailCode(input.body);
  }

  if (method === "POST" && url.pathname === "/api/wallet-session") {
    return startWalletSession();
  }

  if (method === "GET" && url.pathname === "/api/wallet-status") {
    return walletSessionStatus(url);
  }

  if (method === "POST" && url.pathname === "/api/register-node") {
    return registerNodeFromWizard(input.body);
  }

  if (method === "POST" && url.pathname === "/api/start-pm2") {
    return startPm2FromWizard();
  }

  if (method === "GET" && url.pathname === "/success") {
    const progress = await loadSetupProgress();
    if (!isCurrentAgreementAccepted(progress)) return redirectResponse(`/?token=${encodeURIComponent(token)}`);
    if (!progress.evalPassedAt) return redirectResponse(`/network?token=${encodeURIComponent(token)}`);
    const config = await loadConfig();
    if (!config.node_id) return redirectResponse(`/registration?token=${encodeURIComponent(token)}`);
    const templateVersion = await setupWizardTemplateVersion(SERVER_START_ID);
    return htmlResponse(await renderSuccessHtml({
      progress: progressView(progress),
      logoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(token)}`,
      faviconUrl: `/favicon.svg?token=${encodeURIComponent(token)}`,
      statusUrl: `/api/registration-status?token=${encodeURIComponent(token)}`,
      pm2Url: `/api/start-pm2?token=${encodeURIComponent(token)}`,
      reloadUrl: `/api/reload-version?token=${encodeURIComponent(token)}`,
      serverStartId: templateVersion,
      devReload: DEV_RELOAD,
    }));
  }

  if (method === "GET" && url.pathname === "/registration") {
    const progress = await loadSetupProgress();
    if (!isCurrentAgreementAccepted(progress)) return redirectResponse(`/?token=${encodeURIComponent(token)}`);
    if (!progress.evalPassedAt) return redirectResponse(`/network?token=${encodeURIComponent(token)}`);
    const templateVersion = await setupWizardTemplateVersion(SERVER_START_ID);
    return htmlResponse(await renderRegistrationHtml({
      progress: progressView(progress),
      logoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(token)}`,
      faviconUrl: `/favicon.svg?token=${encodeURIComponent(token)}`,
      backUrl: `/network?token=${encodeURIComponent(token)}`,
      statusUrl: `/api/registration-status?token=${encodeURIComponent(token)}`,
      emailStartUrl: `/api/email/start?token=${encodeURIComponent(token)}`,
      emailVerifyUrl: `/api/email/verify?token=${encodeURIComponent(token)}`,
      walletSessionUrl: `/api/wallet-session?token=${encodeURIComponent(token)}`,
      walletStatusUrl: `/api/wallet-status?token=${encodeURIComponent(token)}`,
      registerUrl: `/api/register-node?token=${encodeURIComponent(token)}`,
      successUrl: `/success?token=${encodeURIComponent(token)}`,
      reloadUrl: `/api/reload-version?token=${encodeURIComponent(token)}`,
      serverStartId: templateVersion,
      devReload: DEV_RELOAD,
    }));
  }

  if (method === "GET" && url.pathname === "/network") {
    const progress = await loadSetupProgress();
    if (!isCurrentAgreementAccepted(progress)) return redirectResponse(`/?token=${encodeURIComponent(token)}`);
    if (!progress.installDir) return redirectResponse(`/connection?token=${encodeURIComponent(token)}`);
    if (!TEST_FLOW && !progress.installedVersion) return redirectResponse(`/install?token=${encodeURIComponent(token)}`);
    const templateVersion = await setupWizardTemplateVersion(SERVER_START_ID);
    return htmlResponse(await renderNetworkHtml({
      progress: progressView(progress),
      logoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(token)}`,
      faviconUrl: `/favicon.svg?token=${encodeURIComponent(token)}`,
      backUrl: `/install?token=${encodeURIComponent(token)}`,
      statusUrl: `/api/network-status?token=${encodeURIComponent(token)}`,
      runUrl: `/api/network-eval?token=${encodeURIComponent(token)}`,
      nextUrl: `/registration?token=${encodeURIComponent(token)}`,
      reloadUrl: `/api/reload-version?token=${encodeURIComponent(token)}`,
      serverStartId: templateVersion,
      devReload: DEV_RELOAD,
    }));
  }

  if (method === "GET" && url.pathname === "/install") {
    const progress = await loadSetupProgress();
    if (!isCurrentAgreementAccepted(progress)) return redirectResponse(`/?token=${encodeURIComponent(token)}`);
    if (!progress.installDir) return redirectResponse(`/connection?token=${encodeURIComponent(token)}`);
    const templateVersion = await setupWizardTemplateVersion(SERVER_START_ID);
    return htmlResponse(await renderInstallHtml({
      progress: progressView(progress),
      logoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(token)}`,
      faviconUrl: `/favicon.svg?token=${encodeURIComponent(token)}`,
      installDir: progress.installDir,
      backUrl: `/connection?token=${encodeURIComponent(token)}`,
      manifestUrl: `/api/install-manifest?token=${encodeURIComponent(token)}`,
      installUrl: `/api/runtime-install?token=${encodeURIComponent(token)}`,
      nextUrl: `/network?token=${encodeURIComponent(token)}`,
      reloadUrl: `/api/reload-version?token=${encodeURIComponent(token)}`,
      serverStartId: templateVersion,
      devReload: DEV_RELOAD,
    }));
  }

  if (method === "GET" && url.pathname === "/connection") {
    const progress = await loadSetupProgress();
    if (!isCurrentAgreementAccepted(progress)) return redirectResponse(`/?token=${encodeURIComponent(token)}`);
    const templateVersion = await setupWizardTemplateVersion(SERVER_START_ID);
    const installDir = progress.installDir ?? DEFAULT_INSTALL_DIR;
    return htmlResponse(await renderConnectionHtml({
      progress: progressView(progress),
      logoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(token)}`,
      faviconUrl: `/favicon.svg?token=${encodeURIComponent(token)}`,
      bunLogoUrl: `/assets/bun-logo.png?token=${encodeURIComponent(token)}`,
      pm2LogoUrl: `/assets/pm2-logo.png?token=${encodeURIComponent(token)}`,
      installDir,
      defaultInstallDir: DEFAULT_INSTALL_DIR,
      backUrl: `/?token=${encodeURIComponent(token)}`,
      connectionUrl: `/api/connection?token=${encodeURIComponent(token)}`,
      installUrl: `/install?token=${encodeURIComponent(token)}`,
      installDirSelectUrl: `/api/select-install-dir?token=${encodeURIComponent(token)}`,
      environmentUrl: `/api/environment?token=${encodeURIComponent(token)}`,
      bunInstallUrl: `/api/install-bun?token=${encodeURIComponent(token)}`,
      pm2InstallUrl: `/api/install-pm2?token=${encodeURIComponent(token)}`,
      reloadUrl: `/api/reload-version?token=${encodeURIComponent(token)}`,
      serverStartId: templateVersion,
      devReload: DEV_RELOAD,
    }));
  }

  if (method === "GET") {
    const progress = await loadSetupProgress();
    const templateVersion = await setupWizardTemplateVersion(SERVER_START_ID);
    return htmlResponse(await renderWelcomeHtml({
      progress: progressView(progress),
      agreementVersion: AGREEMENT_VERSION,
      logoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(token)}`,
      faviconUrl: `/favicon.svg?token=${encodeURIComponent(token)}`,
      progressUrl: `/api/progress?token=${encodeURIComponent(token)}`,
      agreementUrl: `/api/operator-agreement?token=${encodeURIComponent(token)}`,
      nextUrl: `/connection?token=${encodeURIComponent(token)}`,
      reloadUrl: `/api/reload-version?token=${encodeURIComponent(token)}`,
      serverStartId: templateVersion,
      devReload: DEV_RELOAD,
    }));
  }

  return jsonResponse({ error: "Not found" }, 404);
}

async function installManifestView(): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = connectionReady(progress);
  if (ready) return ready;

  const manifest = await setupManifest(progress);
  return jsonResponse(await runtimeInstallView(progress, manifest));
}

async function installRuntime(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = connectionReady(progress);
  if (ready) return ready;

  const body = normalizeRuntimeInstallBody(input);
  const manifest = await setupManifest(progress);
  const canReuse = await canReuseRuntime(progress, manifest);

  if (body.mode === "reuse") {
    if (!canReuse) return jsonResponse({ error: "No matching runtime install is available to reuse" }, 409);
    const next = await rememberRuntimeInstall(progress, manifest.version);
    return jsonResponse({
      success: true,
      mode: "reuse",
      progress: progressView(next),
      install: await runtimeInstallView(next, manifest),
    });
  }

  if (TEST_FLOW) {
    const next = await rememberRuntimeInstall(progress, manifest.version);
    return jsonResponse({
      success: true,
      mode: "test-install",
      output: "Local test flow: runtime install simulated",
      progress: progressView(next),
      install: await runtimeInstallView(next, manifest),
    });
  }

  const artifact = await downloadAndVerify(manifest);
  const result = await runInstaller("scripts/install-release.sh", [], {
    CONSENSUS_NODE_INSTALL_DIR: progress.installDir!,
    CONSENSUS_NODE_ARTIFACT_PATH: artifact.path,
    CONSENSUS_NODE_TARGET_VERSION: manifest.version,
  });
  if (!result.ok) {
    return jsonResponse({
      error: result.output || "Runtime installation failed",
      artifact,
      install: await runtimeInstallView(progress, manifest),
    }, 500);
  }

  const next = await rememberRuntimeInstall(progress, manifest.version);
  return jsonResponse({
    success: true,
    mode: "install",
    artifact,
    output: result.output,
    progress: progressView(next),
    install: await runtimeInstallView(next, manifest),
  });
}

async function setupManifest(progress: SetupProgress): Promise<ReleaseManifest> {
  if (TEST_FLOW) return testReleaseManifest();
  return fetchRequiredManifest(progress.serverUrl ?? DEFAULT_SERVER_URL);
}

function testReleaseManifest(): ReleaseManifest {
  return {
    product: "consensus-node",
    version: "0.1.0-alpha.9-test",
    artifact: "npm-tarball",
    platform: `${process.platform}-${process.arch}`,
    commit: "local-test-flow",
    download_url: "local-test-flow://consensus-node",
    tarball_sha256: "sha256:local-test-flow",
    routes_hash: "local-test-flow",
    capabilities: ["forward_proxy", "reverse_proxy", "websockets", "tunnels", "ip_leasing"],
  };
}

async function networkStatus(): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = installReady(progress);
  if (ready) return ready;
  return jsonResponse(await networkView(progress));
}

async function runNetworkEval(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = installReady(progress);
  if (ready) return ready;

  const body = normalizeNetworkEvalBody(input);
  if (body.mode === "test") {
    if (!TEST_FLOW) return jsonResponse({ error: "Local test flow is not enabled" }, 403);
    const next = await rememberNetworkProgress(progress, {
      publicIpv4: "203.0.113.42",
      publicIpv6: null,
      region: {
        region: "local-test",
        city: "Local Test",
        country_code: "US",
      },
      evalPassedAt: new Date().toISOString(),
    });
    return jsonResponse({
      success: true,
      mode: "test",
      network: await networkView(next),
      progress: progressView(next),
    });
  }

  const publicIpv4 = await detectPublicIpv4();
  let next = await rememberNetworkProgress(progress, { publicIpv4 });
  const publicIpv6 = await detectPublicIpv6().catch(() => null);
  next = await rememberNetworkProgress(next, { publicIpv6 });
  const region = await fetchRegion(next.serverUrl ?? DEFAULT_SERVER_URL, publicIpv4).catch(() => null);
  next = await rememberNetworkProgress(next, { region });

  const joinAuth = await loadJoinAuthorization();
  if (joinAuth && joinAuth.expires_at > Math.floor(Date.now() / 1000) + 60) {
    next = await rememberNetworkProgress(next, { evalPassedAt: new Date().toISOString() });
    return jsonResponse({
      success: true,
      mode: "reuse-join-auth",
      network: await networkView(next),
      progress: progressView(next),
    });
  }

  const currentDir = path.join(next.installDir!, "current");
  if (!await pathExists(currentDir)) return jsonResponse({ error: `Installed runtime not found at ${currentDir}` }, 409);
  const result = await runSetupCommand("bun", ["run", "eval"], {
    CONSENSUS_SERVER_URL: next.serverUrl ?? DEFAULT_SERVER_URL,
    CONSENSUS_STATE_DIR: stateDir(),
  }, currentDir, 90_000);
  if (!result.ok) {
    return jsonResponse({
      error: result.output || "Benchmark evaluation failed",
      network: await networkView(next),
    }, 500);
  }

  next = await rememberNetworkProgress(next, { evalPassedAt: new Date().toISOString() });
  return jsonResponse({
    success: true,
    mode: "real",
    output: result.output,
    network: await networkView(next),
    progress: progressView(next),
  });
}

function installReady(progress: SetupProgress): Response | null {
  const ready = connectionReady(progress);
  if (ready) return ready;
  if (!TEST_FLOW && !progress.installedVersion) {
    return jsonResponse({ error: "Runtime must be installed first" }, 409);
  }
  return null;
}

async function networkView(progress: SetupProgress): Promise<Record<string, unknown>> {
  const joinAuth = await loadJoinAuthorization();
  const joinAuthReusable = Boolean(joinAuth && joinAuth.expires_at > Math.floor(Date.now() / 1000) + 60);
  return {
    testFlow: TEST_FLOW,
    serverUrl: progress.serverUrl ?? DEFAULT_SERVER_URL,
    installDir: progress.installDir ?? null,
    installedVersion: progress.installedVersion ?? null,
    networkDetected: Boolean(progress.publicIpv4),
    publicIpv4: progress.publicIpv4 ?? null,
    publicIpv6: progress.publicIpv6 ?? null,
    region: progress.region ?? null,
    evalPassedAt: progress.evalPassedAt ?? null,
    joinAuthReusable,
    joinAuth: joinAuthReusable && joinAuth ? {
      joinId: joinAuth.join_id,
      expiresAt: joinAuth.expires_at,
    } : null,
  };
}

async function rememberNetworkProgress(progress: SetupProgress, patch: Partial<SetupProgress>): Promise<SetupProgress> {
  const next = {
    ...progress,
    ...patch,
  };
  await saveSetupProgress(next);
  return next;
}

async function registrationStatus(): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;
  return jsonResponse(await registrationView(progress));
}

async function startEmailVerification(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;

  const body = normalizeEmailStartBody(input);
  if (!isValidEmail(body.email)) return jsonResponse({ error: "Enter a valid contact email" }, 422);

  if (TEST_FLOW) {
    return jsonResponse({
      verification_id: "local-test-email",
      expires_at: Math.floor(Date.now() / 1000) + 900,
      dev_code: "123456",
      testFlow: true,
    });
  }

  return jsonResponse(await postJson<Record<string, unknown>>(
    `${trimTrailingSlash(progress.serverUrl ?? DEFAULT_SERVER_URL)}/node/email/start`,
    { email: body.email },
  ));
}

async function verifyEmailCode(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;

  const body = normalizeEmailVerifyBody(input);
  if (!isValidEmail(body.email)) return jsonResponse({ error: "Enter a valid contact email" }, 422);
  if (!body.verificationId) return jsonResponse({ error: "Verification session is missing" }, 422);
  if (!body.code) return jsonResponse({ error: "Enter the email verification code" }, 422);

  const verified = TEST_FLOW
    ? {
      email_verification_token: "local-test-email-token",
      expires_at: Math.floor(Date.now() / 1000) + 3600,
    }
    : await postJson<{ email_verification_token: string; expires_at: number }>(
      `${trimTrailingSlash(progress.serverUrl ?? DEFAULT_SERVER_URL)}/node/email/verify`,
      { email: body.email, verification_id: body.verificationId, code: body.code },
    );

  const next = await rememberRegistrationProgress(progress, {
    contact: body.email,
    emailVerificationToken: verified.email_verification_token,
    emailVerificationExpiresAt: verified.expires_at,
  });
  return jsonResponse({
    success: true,
    progress: progressView(next),
    registration: await registrationView(next),
  });
}

async function startWalletSession(): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;

  if (TEST_FLOW) {
    const next = await rememberRegistrationProgress(progress, testWalletAddresses());
    return jsonResponse({
      success: true,
      done: true,
      testFlow: true,
      addresses: testWalletAddresses(),
      registration: await registrationView(next),
    });
  }

  const sessionId = randomUUID();
  const session = await startWalletAddressServer({
    initialAddresses: {
      evmAddress: progress.evmAddress,
      solanaAddress: progress.solanaAddress,
      icpAddress: progress.icpAddress,
    },
  });
  walletSessions.set(sessionId, { session, status: "pending" });
  session.done.then(async (addresses) => {
    const current = walletSessions.get(sessionId);
    if (!current) return;
    const latest = await loadSetupProgress();
    const merged = mergeWalletAddresses({
      evmAddress: latest.evmAddress,
      solanaAddress: latest.solanaAddress,
      icpAddress: latest.icpAddress,
    }, addresses);
    await rememberRegistrationProgress(latest, merged);
    current.status = "done";
    current.addresses = merged;
    await session.stop().catch(() => {});
  }).catch((error) => {
    const current = walletSessions.get(sessionId);
    if (!current) return;
    current.status = "error";
    current.error = error instanceof Error ? error.message : String(error);
  });

  return jsonResponse({ success: true, sessionId, url: session.url });
}

async function walletSessionStatus(url: URL): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;

  const sessionId = url.searchParams.get("session");
  if (!sessionId) {
    return jsonResponse({
      status: "current",
      addresses: currentWalletAddresses(progress),
      registration: await registrationView(progress),
    });
  }

  const session = walletSessions.get(sessionId);
  if (!session) return jsonResponse({ error: "Wallet session not found" }, 404);
  const latest = await loadSetupProgress();
  return jsonResponse({
    status: session.status,
    error: session.error ?? null,
    addresses: currentWalletAddresses(latest),
    registration: await registrationView(latest),
  });
}

async function registerNodeFromWizard(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;

  const body = normalizeRegisterBody(input);
  const port = normalizePort(body.port);
  if (!port) return jsonResponse({ error: "Enter a valid TCP port" }, 422);
  const registrationErrors = registrationValidationErrors(progress);
  if (registrationErrors.length > 0) return jsonResponse({ error: registrationErrors.join("; ") }, 422);

  let next = await rememberRegistrationProgress(progress, { port: String(port) });
  let config: NodeConfig;
  let pm2: Record<string, unknown> | null = null;

  if (TEST_FLOW) {
    config = testNodeConfig(next, port);
    await saveConfig(config);
  } else {
    const existing = await loadConfig();
    if (!existing.node_id) {
      const currentDir = path.join(next.installDir!, "current");
      if (!await pathExists(currentDir)) return jsonResponse({ error: `Installed runtime not found at ${currentDir}` }, 409);
      const result = await runSetupCommand("bun", ["run", "register"], registrationEnv(next, port), currentDir, 150_000);
      if (!result.ok) return jsonResponse({ error: result.output || "Node registration failed" }, 500);
    } else {
      await claimMachineNode({ nodeId: existing.node_id, installDir: next.installDir });
    }
    config = await loadConfig();
    if (config.node_id) await claimMachineNode({ nodeId: config.node_id, installDir: next.installDir });
  }

  if (body.startPm2) {
    const started = await startPm2Control(next);
    if (!started.ok) return jsonResponse({ error: started.output || "PM2 start failed", config }, 500);
    pm2 = { started: true, output: started.output };
  }

  return jsonResponse({
    success: true,
    config,
    pm2,
    registration: await registrationView(next),
  });
}

async function startPm2FromWizard(): Promise<Response> {
  const progress = await loadSetupProgress();
  const ready = registrationReady(progress);
  if (ready) return ready;
  const config = await loadConfig();
  if (!config.node_id) return jsonResponse({ error: "Node must be registered before starting PM2" }, 409);
  const result = await startPm2Control(progress);
  if (!result.ok) return jsonResponse({ error: result.output || "PM2 start failed" }, 500);
  return jsonResponse({ success: true, output: result.output });
}

function registrationReady(progress: SetupProgress): Response | null {
  const ready = installReady(progress);
  if (ready) return ready;
  if (!progress.evalPassedAt) return jsonResponse({ error: "Network evaluation must pass first" }, 409);
  return null;
}

async function registrationView(progress: SetupProgress): Promise<Record<string, unknown>> {
  const config = await loadConfig();
  return {
    testFlow: TEST_FLOW,
    progress: progressView(progress),
    contact: progress.contact ?? null,
    emailVerified: Boolean(progress.emailVerificationToken && progress.emailVerificationExpiresAt && progress.emailVerificationExpiresAt > Math.floor(Date.now() / 1000) + 60),
    emailVerificationExpiresAt: progress.emailVerificationExpiresAt ?? null,
    wallets: currentWalletAddresses(progress),
    walletErrors: validateWalletAddresses(currentWalletAddresses(progress)),
    port: progress.port ?? "9090",
    network: {
      publicIpv4: progress.publicIpv4 ?? null,
      publicIpv6: progress.publicIpv6 ?? null,
      region: progress.region ?? null,
      evalPassedAt: progress.evalPassedAt ?? null,
    },
    config,
    registered: Boolean(config.node_id),
    stateDir: stateDir(),
    runtimeCurrent: progress.installDir ? path.join(progress.installDir, "current") : null,
  };
}

async function rememberRegistrationProgress(progress: SetupProgress, patch: Partial<SetupProgress>): Promise<SetupProgress> {
  const next = { ...progress, ...patch };
  await saveSetupProgress(next);
  return next;
}

async function recordConnection(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  if (!isCurrentAgreementAccepted(progress)) return jsonResponse({ error: "Operator agreement must be accepted first" }, 409);

  const body = normalizeConnectionBody(input);
  const installDir = normalizeInstallDir(body.installDir);
  if (!installDir) return jsonResponse({ error: "Enter an absolute or ~-relative runtime directory" }, 422);

  const next: SetupProgress = {
    ...progress,
    serverUrl: DEFAULT_SERVER_URL,
    installDir,
  };
  await saveSetupProgress(next);
  return jsonResponse({
    success: true,
    nextStep: "runtime-install",
    nextUrl: "/install",
    progress: progressView(next),
  });
}

function connectionReady(progress: SetupProgress): Response | null {
  if (!isCurrentAgreementAccepted(progress)) {
    return jsonResponse({ error: "Operator agreement must be accepted first" }, 409);
  }
  if (!progress.installDir) {
    return jsonResponse({ error: "Runtime directory must be selected first" }, 409);
  }
  return null;
}

async function runtimeInstallView(progress: SetupProgress, manifest: ReleaseManifest): Promise<Record<string, unknown>> {
  const installDir = progress.installDir ?? DEFAULT_INSTALL_DIR;
  const currentPath = path.join(installDir, "current");
  const canReuse = await canReuseRuntime(progress, manifest);
  return {
    manifest: manifestView(manifest),
    serverUrl: progress.serverUrl ?? DEFAULT_SERVER_URL,
    installDir,
    currentPath,
    installedVersion: progress.installedVersion ?? null,
    canReuse,
    reuseReason: canReuse
      ? `Release ${manifest.version} is already installed at ${currentPath}`
      : null,
  };
}

async function canReuseRuntime(progress: SetupProgress, manifest: ReleaseManifest): Promise<boolean> {
  if (!progress.installDir) return false;
  return progress.installedVersion === manifest.version && await pathExists(path.join(progress.installDir, "current"));
}

function manifestView(manifest: ReleaseManifest): Record<string, unknown> {
  return {
    product: manifest.product,
    version: manifest.version,
    platform: manifest.platform,
    commit: manifest.commit,
    sha256: manifest.tarball_sha256 ?? null,
    source: manifest.download_url ?? null,
    routesHash: manifest.routes_hash,
    capabilities: manifest.capabilities,
    signingKeyId: manifest.signing_key_id ?? null,
  };
}

async function rememberRuntimeInstall(progress: SetupProgress, installedVersion: string): Promise<SetupProgress> {
  const next = {
    ...progress,
    installedVersion,
  };
  await saveSetupProgress(next);
  return next;
}

async function selectInstallDir(): Promise<Response> {
  const progress = await loadSetupProgress();
  if (!isCurrentAgreementAccepted(progress)) return jsonResponse({ error: "Operator agreement must be accepted first" }, 409);
  if (process.platform !== "darwin") return jsonResponse({ error: "Folder selection is only available on macOS" }, 501);

  const result = await runChooser();
  if (!result.ok) return jsonResponse({ error: result.output || "Folder selection cancelled" }, 409);

  const installDir = normalizeChooserPath(result.output);
  if (!installDir) return jsonResponse({ error: "Folder selection did not return an absolute path" }, 422);
  return jsonResponse({ installDir });
}

async function installPm2(): Promise<Response> {
  const progress = await loadSetupProgress();
  if (!isCurrentAgreementAccepted(progress)) return jsonResponse({ error: "Operator agreement must be accepted first" }, 409);

  const result = await runInstaller("scripts/ensure-pm2.sh", ["--yes"], {
    CI: "1",
    NONINTERACTIVE: "1",
  });
  if (!result.ok) {
    return jsonResponse({
      error: result.output || "PM2 installation failed",
      environment: await environmentView(),
    }, 500);
  }

  return jsonResponse({
    success: true,
    output: result.output,
    environment: await environmentView(),
  });
}

async function installBun(): Promise<Response> {
  const progress = await loadSetupProgress();
  if (!isCurrentAgreementAccepted(progress)) return jsonResponse({ error: "Operator agreement must be accepted first" }, 409);

  const result = await runInstaller("scripts/ensure-bun.sh", ["--yes"], {
    CI: "1",
    NONINTERACTIVE: "1",
  });
  if (!result.ok) {
    return jsonResponse({
      error: result.output || "Bun installation failed",
      environment: await environmentView(),
    }, 500);
  }

  return jsonResponse({
    success: true,
    output: result.output,
    environment: await environmentView(),
  });
}

async function runChooser(): Promise<{ ok: boolean; output: string }> {
  const script = 'POSIX path of (choose folder with prompt "Select Consensus runtime directory")';
  return await new Promise((resolve) => {
    const child = spawn("osascript", ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.on("exit", (code) => resolve({ ok: code === 0, output: output.trim() }));
    child.on("error", (error) => resolve({ ok: false, output: error.message }));
  });
}

function normalizeChooserPath(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed.startsWith("/")) return null;
  return trimmed.length > 1 ? trimmed.replace(/\/+$/, "") : trimmed;
}

async function recordOperatorAgreement(input: unknown): Promise<Response> {
  const progress = await loadSetupProgress();
  const body = normalizeAgreementBody(input);
  if (!body.agreementReviewed) return jsonResponse({ error: "Review and accept the Operator Agreement before signing" }, 422);
  if (!body.accepted) return jsonResponse({ error: "Agreement checkbox is required" }, 422);
  if (body.signature.length < 2) return jsonResponse({ error: "Electronic signature is required" }, 422);
  if (body.confirmation !== "I AGREE") return jsonResponse({ error: "Typed confirmation must match I AGREE" }, 422);

  const acceptedAt = new Date().toISOString();
  const next: SetupProgress = {
    ...progress,
    operatorAgreementAccepted: true,
    operatorAgreementAcceptedAt: acceptedAt,
    operatorAgreementSignature: body.signature,
    operatorAgreementVersion: AGREEMENT_VERSION,
  };
  await saveSetupProgress(next);
  return jsonResponse({
    success: true,
    nextStep: "configuration",
    progress: progressView(next),
  });
}

function normalizeConnectionBody(input: unknown): { installDir: string } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    installDir: typeof record.installDir === "string" ? record.installDir.trim() : "",
  };
}

function normalizeRuntimeInstallBody(input: unknown): { mode: "install" | "reuse" } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    mode: record.mode === "reuse" ? "reuse" : "install",
  };
}

function normalizeNetworkEvalBody(input: unknown): { mode: "real" | "test" } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    mode: record.mode === "test" ? "test" : "real",
  };
}

function normalizeEmailStartBody(input: unknown): { email: string } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    email: typeof record.email === "string" ? record.email.trim() : "",
  };
}

function normalizeEmailVerifyBody(input: unknown): { email: string; verificationId: string; code: string } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    email: typeof record.email === "string" ? record.email.trim() : "",
    verificationId: typeof record.verificationId === "string" ? record.verificationId.trim() : "",
    code: typeof record.code === "string" ? record.code.trim() : "",
  };
}

function normalizeRegisterBody(input: unknown): { port: string; startPm2: boolean } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    port: typeof record.port === "string" ? record.port.trim() : "",
    startPm2: record.startPm2 === true,
  };
}

function normalizeAgreementBody(input: unknown): { accepted: boolean; agreementReviewed: boolean; signature: string; confirmation: string } {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    accepted: record.accepted === true,
    agreementReviewed: record.agreementReviewed === true,
    signature: typeof record.signature === "string" ? record.signature.trim() : "",
    confirmation: typeof record.confirmation === "string" ? record.confirmation.trim() : "",
  };
}

function isCurrentAgreementAccepted(progress: SetupProgress): boolean {
  return progress.operatorAgreementAccepted === true && progress.operatorAgreementVersion === AGREEMENT_VERSION;
}

function progressView(progress: SetupProgress): Record<string, unknown> {
  const lastKey = lastCompletedProgressKey(progress);
  const operatorAgreementAccepted = isCurrentAgreementAccepted(progress);
  return {
    hasProgress: Object.keys(progress).length > 0,
    stateDir: stateDir(),
    lastCompletedKey: lastKey,
    lastCompletedLabel: lastKey ? progressLabels[lastKey] : null,
    operatorAgreementAccepted,
    operatorAgreementAcceptedAt: progress.operatorAgreementAcceptedAt ?? null,
    operatorAgreementSignature: progress.operatorAgreementSignature ?? null,
    operatorAgreementVersion: progress.operatorAgreementVersion ?? null,
    serverUrl: progress.serverUrl ?? null,
    installDir: progress.installDir ?? null,
    installedVersion: progress.installedVersion ?? null,
  };
}

async function environmentView(): Promise<Record<string, unknown>> {
  const [bun, pm2] = await Promise.all([
    commandStatus("bun", ["--version"], bunFallbackPaths()),
    commandStatus("pm2", ["--version"], pm2FallbackPaths()),
  ]);
  return {
    bun,
    pm2,
    bunInstallCommand: "scripts/ensure-bun.sh",
    pm2InstallCommand: "scripts/ensure-pm2.sh",
  };
}

function currentWalletAddresses(progress: SetupProgress): WalletAddresses {
  return {
    evmAddress: progress.evmAddress,
    solanaAddress: progress.solanaAddress,
    icpAddress: progress.icpAddress,
  };
}

function testWalletAddresses(): WalletAddresses {
  return {
    evmAddress: "0x0000000000000000000000000000000000000000",
    solanaAddress: "11111111111111111111111111111111",
    icpAddress: "aaaaa-aa",
  };
}

function registrationValidationErrors(progress: SetupProgress): string[] {
  const errors: string[] = [];
  const emailValid = Boolean(progress.contact && progress.emailVerificationToken && progress.emailVerificationExpiresAt && progress.emailVerificationExpiresAt > Math.floor(Date.now() / 1000) + 60);
  if (!emailValid) errors.push("Contact email must be verified");
  if (!progress.publicIpv4) errors.push("Public IPv4 must be detected");
  if (!progress.evalPassedAt) errors.push("Network evaluation must pass");
  const wallets = currentWalletAddresses(progress);
  if (!wallets.evmAddress) errors.push("EVM address is required");
  if (!wallets.solanaAddress) errors.push("Solana address is required");
  if (!wallets.icpAddress) errors.push("ICP address is required");
  const walletErrors = validateWalletAddresses(wallets);
  errors.push(...Object.values(walletErrors));
  return errors;
}

function normalizePort(value: string): number | null {
  const port = Number(value || "9090");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return null;
  return port;
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function testNodeConfig(progress: SetupProgress, port: number): NodeConfig {
  return {
    node_id: "node-local-test",
    domain: "node-local-test.consensus.local",
    region: progress.region?.region ?? "local-test",
    ipv4: progress.publicIpv4 ?? "203.0.113.42",
    ipv6: progress.publicIpv6 ?? null,
    port,
    registered_at: new Date().toISOString(),
    commissioned_at: new Date().toISOString(),
    benchmark_score: 100,
    orchestrator_pubkey: null,
  };
}

function registrationEnv(progress: SetupProgress, port: number): Record<string, string> {
  return {
    CONSENSUS_SERVER_URL: progress.serverUrl ?? DEFAULT_SERVER_URL,
    CONSENSUS_STATE_DIR: stateDir(),
    CONSENSUS_NODE_IPV4: progress.publicIpv4!,
    ...(progress.publicIpv6 ? { CONSENSUS_NODE_IPV6: progress.publicIpv6 } : {}),
    CONSENSUS_NODE_PORT: String(port),
    CONSENSUS_NODE_CONTACT: progress.contact!,
    CONSENSUS_EMAIL_VERIFICATION_TOKEN: progress.emailVerificationToken!,
    CONSENSUS_EVM_ADDRESS: progress.evmAddress!,
    CONSENSUS_SOLANA_ADDRESS: progress.solanaAddress!,
    CONSENSUS_ICP_ADDRESS: progress.icpAddress!,
  };
}

async function startPm2Control(progress: SetupProgress): Promise<{ ok: boolean; output: string }> {
  if (TEST_FLOW) return { ok: true, output: "Local test flow: PM2 start simulated" };
  const installDir = progress.installDir;
  if (!installDir) return { ok: false, output: "Runtime install directory is missing" };
  const appName = process.env.CONSENSUS_PM2_NAME?.trim() || DEFAULT_PM2_NAME;
  const configPath = path.join(installDir, "current", "ecosystem.config.cjs");
  if (!await pathExists(configPath)) return { ok: false, output: `PM2 config not found at ${configPath}` };
  const pm2 = await resolveExecutable("pm2", pm2FallbackPaths());
  if (!pm2) return { ok: false, output: "PM2 is not available" };

  const start = await runSetupCommand(pm2, ["startOrReload", configPath, "--only", appName, "--update-env"], {
    CONSENSUS_SERVER_URL: progress.serverUrl ?? DEFAULT_SERVER_URL,
    CONSENSUS_STATE_DIR: stateDir(),
    CONSENSUS_NODE_INSTALL_DIR: installDir,
    CONSENSUS_NODE_RELEASE_RETENTION: process.env.CONSENSUS_NODE_RELEASE_RETENTION?.trim() || "3",
    CONSENSUS_PM2_NAME: appName,
    CONSENSUS_NODE_UPDATE_COMMAND: path.join(installDir, "current", "scripts", "install-release.sh"),
  }, process.cwd(), 60_000);
  if (!start.ok) return start;
  const online = await verifyPm2Online(pm2, appName);
  if (!online.ok) return online;
  const save = await runSetupCommand(pm2, ["save"], {}, process.cwd(), 30_000);
  return save.ok
    ? { ok: true, output: compactOutput(`${start.output}\n${online.output}\n${save.output}`) }
    : save;
}

async function verifyPm2Online(pm2: string, appName: string): Promise<{ ok: boolean; output: string }> {
  await sleep(pm2VerifyDelayMs());
  const list = await runSetupCommand(pm2, ["jlist"], {}, process.cwd(), 10_000);
  if (!list.ok) return { ok: false, output: list.output || "Could not inspect PM2 process status" };

  const status = pm2StatusFromJlist(list.output, appName);
  if (status === "online") return { ok: true, output: `PM2 ${appName} is online` };
  return {
    ok: false,
    output: `PM2 accepted ${appName}, but it did not reach online status (status: ${status || "missing"}). Check logs with: pm2 logs ${appName}`,
  };
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

function bunFallbackPaths(): string[] {
  return [
    path.join(os.homedir(), ".bun", "bin", "bun"),
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

async function commandStatus(command: string, args: string[], fallbackPaths: string[] = []): Promise<Record<string, unknown>> {
  const executable = await resolveExecutable(command, fallbackPaths);
  const label = `${command} ${args.join(" ")}`;
  if (!executable) {
    return {
      available: false,
      command,
      label: "Not found",
      detail: `${label} · command not found`,
    };
  }

  const result = await runCapture(executable, args);
  if (!result.ok) {
    return {
      available: false,
      command,
      path: executable,
      label: "Failed",
      detail: `${label} · ${result.output || "command failed"}`,
    };
  }

  return {
    available: true,
    command,
    path: executable,
    version: result.output,
    label: "Detected",
    detail: `${label} · ${result.output || "ok"}`,
  };
}

async function resolveExecutable(command: string, fallbackPaths: string[] = []): Promise<string | null> {
  const found = await which(command);
  if (found) return found;

  for (const candidate of fallbackPaths) {
    if (await pathExists(candidate)) return candidate;
  }

  return null;
}

async function which(command: string): Promise<string | null> {
  const result = await runCapture("sh", ["-lc", `command -v ${shellQuote(command)}`]);
  return result.ok && result.output ? result.output : null;
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await access(target);
    return true;
  } catch {
    return false;
  }
}

async function runCapture(command: string, args: string[]): Promise<{ ok: boolean; output: string }> {
  return await new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const timeout = setTimeout(() => child.kill("SIGTERM"), 8_000);
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      resolve({ ok: code === 0, output: output.trim().split(/\s+/)[0] ?? "" });
    });
    child.on("error", () => {
      clearTimeout(timeout);
      resolve({ ok: false, output: "" });
    });
  });
}

async function runInstaller(command: string, args: string[], env: Record<string, string>): Promise<{ ok: boolean; output: string }> {
  if (!await pathExists(command)) return { ok: false, output: `${command} not found` };
  return await new Promise((resolve) => {
    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    const timeout = setTimeout(() => child.kill("SIGTERM"), 5 * 60_000);
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      resolve({ ok: code === 0, output: compactOutput(output) });
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      resolve({ ok: false, output: error.message });
    });
  });
}

async function runSetupCommand(command: string, args: string[], env: Record<string, string>, cwd: string, timeoutMs: number): Promise<{ ok: boolean; output: string }> {
  return await new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    const timeout = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      resolve({ ok: code === 0, output: compactOutput(output) });
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      resolve({ ok: false, output: error.message });
    });
  });
}

function compactOutput(value: string): string {
  return value.trim().split(/\n/).slice(-8).join("\n");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeInstallDir(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed === "~") return os.homedir();
  if (trimmed.startsWith("~/")) return path.join(os.homedir(), trimmed.slice(2));
  if (path.isAbsolute(trimmed)) return path.normalize(trimmed);
  return null;
}

function displayPath(value: string): string {
  const home = os.homedir();
  if (value === home) return "~";
  if (value.startsWith(`${home}${path.sep}`)) return `~/${path.relative(home, value)}`;
  return value;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

const progressLabels: Record<string, string> = {
  operatorAgreementAcceptedAt: "operator agreement",
  serverUrl: "server URL confirmed",
  installDir: "install directory confirmed",
  installedVersion: "runtime install",
  publicIpv4: "network detection",
  evalPassedAt: "benchmark evaluation",
  contact: "contact and email verification",
  evmAddress: "payout wallets",
  port: "node port",
};

function lastCompletedProgressKey(progress: SetupProgress): string | null {
  const order: Array<keyof SetupProgress> = [
    "operatorAgreementAcceptedAt",
    "serverUrl",
    "installDir",
    "installedVersion",
    "publicIpv4",
    "evalPassedAt",
    "contact",
    "evmAddress",
    "port",
  ];
  let last: string | null = null;
  for (const key of order) {
    if (progress[key]) last = key;
  }
  return last;
}

async function handleNodeRequest(
  request: IncomingMessage,
  response: ServerResponse,
  handler: (method: string, url: URL, body: unknown) => Promise<Response>,
): Promise<void> {
  const method = request.method ?? "GET";
  const host = request.headers.host ?? DEFAULT_HOST;
  const url = new URL(request.url ?? "/", `http://${host}`);
  const body = method === "POST" ? await readJsonBody(request) : null;
  const wizardResponse = await handler(method, url, body);
  await sendNodeResponse(response, wizardResponse);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > 64 * 1024) throw new Error("Request body too large");
    chunks.push(buffer);
  }
  if (chunks.length === 0) return null;
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    return null;
  }
}

async function sendNodeResponse(response: ServerResponse, wizardResponse: Response): Promise<void> {
  const headers: Record<string, string> = {};
  wizardResponse.headers.forEach((value, key) => {
    headers[key] = value;
  });
  response.writeHead(wizardResponse.status, headers);
  response.end(wizardResponse.body ? Buffer.from(await wizardResponse.arrayBuffer()) : undefined);
}

async function listen(server: http.Server, requestedPort: number | undefined, host: string): Promise<number> {
  await listenOnce(server, requestedPort ?? 0, host);
  const address = server.address() as AddressInfo;
  return address.port;
}

async function listenOnce(server: http.Server, port: number, host: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => server.off("error", onError);
    const onError = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    server.once("error", onError);
    try {
      server.listen(port, host, () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve();
      });
    } catch (error) {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    }
  });
}

function parseOptionalPort(input: string | undefined): number | undefined {
  if (!input?.trim()) return undefined;
  const port = Number(input);
  if (!Number.isInteger(port) || port <= 0 || port > 65_535) {
    throw new Error(`Invalid setup wizard port: ${input}`);
  }
  return port;
}

async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function assetResponse(pathname: string): Promise<Response> {
  const asset = ASSETS.get(pathname);
  if (!asset) return jsonResponse({ error: "Not found" }, 404);
  const contentType = pathname.endsWith(".png")
    ? "image/png"
    : "image/svg+xml; charset=utf-8";
  return new Response(await readFile(asset), {
    headers: {
      "cache-control": "no-store",
      "content-type": contentType,
      "x-content-type-options": "nosniff",
    },
  });
}

async function adaptiveFaviconResponse(): Promise<Response> {
  const darkLogo = await readSvgAsset("/assets/consensus-logo-dark.svg");
  const lightLogo = await readSvgAsset("/assets/consensus-logo-light.svg");
  const body = `<svg width="33" height="33" viewBox="0 0 33 33" fill="none" xmlns="http://www.w3.org/2000/svg">
<style>
.for-light-browser{display:block}
.for-dark-browser{display:none}
@media (prefers-color-scheme: dark){
  .for-light-browser{display:none}
  .for-dark-browser{display:block}
}
</style>
${withSvgClass(darkLogo, "for-light-browser")}
${withSvgClass(lightLogo, "for-dark-browser")}
</svg>`;
  return new Response(body, {
    headers: {
      "cache-control": "no-store",
      "content-type": "image/svg+xml; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

async function readSvgAsset(pathname: string): Promise<string> {
  const asset = ASSETS.get(pathname);
  if (!asset) throw new Error(`Missing setup wizard asset: ${pathname}`);
  return readFile(asset, "utf8");
}

function withSvgClass(svg: string, className: string): string {
  return svg.replace("<svg ", `<svg class="${className}" `);
}

function htmlResponse(body: string): Response {
  return new Response(body, {
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; img-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      "content-type": "text/html; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

function redirectResponse(location: string): Response {
  return new Response(null, {
    status: 303,
    headers: {
      "cache-control": "no-store",
      location,
    },
  });
}

async function openPage(url: string): Promise<void> {
  const command = process.platform === "darwin"
    ? { command: "open", args: [url] }
    : process.platform === "win32"
      ? { command: "cmd", args: ["/c", "start", "", url] }
      : { command: "xdg-open", args: [url] };
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const child = spawn(command.command, command.args, { detached: true, stdio: "ignore" });
    child.once("spawn", () => {
      if (settled) return;
      settled = true;
      child.unref();
      resolve();
    });
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

if (import.meta.main) {
  const session = await startSetupWizardServer({
    port: parseOptionalPort(process.env.CONSENSUS_SETUP_WIZARD_PORT),
    token: process.env.CONSENSUS_SETUP_WIZARD_TOKEN?.trim() || undefined,
  });
  console.log("Setup wizard page:");
  console.log(session.url);
  if (process.env.CONSENSUS_SETUP_WIZARD_OPEN?.trim() !== "0") {
    await openPage(session.url).catch((error) => {
      console.warn(`Could not open browser automatically: ${error instanceof Error ? error.message : String(error)}`);
    });
  }
}
