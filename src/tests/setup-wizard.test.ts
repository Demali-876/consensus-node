import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const stateRoot = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-setup-wizard-"));
process.env.CONSENSUS_STATE_DIR = stateRoot;
process.env.CONSENSUS_SETUP_WIZARD_TEST_FLOW = "1";

const { startSetupWizardServer } = await import("../setup-wizard");

const session = await startSetupWizardServer();
try {
  const page = await fetch(session.url);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.equal(html.includes("Consensus Node Setup"), true);
  assert.equal(html.includes("Operator Agreement"), true);
  assert.equal(html.includes("Review agreement"), true);
  assert.equal(html.includes("agreement-modal"), true);
  assert.equal(html.includes("Scroll to continue"), true);
  assert.equal(html.includes("I AGREE"), true);
  assert.equal(html.includes("Space+Grotesk"), true);
  assert.equal(html.includes("JetBrains+Mono"), true);
  assert.equal(html.includes("consensus-logo-light.svg"), true);
  assert.equal(html.includes("Good-Faith Node Operator Agreement"), true);
  assert.equal(html.includes("Availability and uptime"), true);
  assert.equal(html.includes("Prohibited conduct"), true);

  const token = new URL(session.url).searchParams.get("token")!;
  const progress = await fetch(new URL(`/api/progress?token=${token}`, session.url));
  assert.equal(progress.status, 200);
  assert.equal((await progress.json() as { operatorAgreementAccepted: boolean }).operatorAgreementAccepted, false);

  const reloadVersion = await fetch(new URL(`/api/reload-version?token=${token}`, session.url));
  assert.equal(reloadVersion.status, 200);
  assert.equal(typeof (await reloadVersion.json() as { serverStartId: string }).serverStartId, "string");

  const rejectedWithoutReview = await fetch(new URL(`/api/operator-agreement?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ accepted: true, signature: "Operator", confirmation: "I AGREE" }),
  });
  assert.equal(rejectedWithoutReview.status, 422);

  const rejectedConfirmation = await fetch(new URL(`/api/operator-agreement?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ accepted: true, agreementReviewed: true, signature: "Operator", confirmation: "AGREE" }),
  });
  assert.equal(rejectedConfirmation.status, 422);

  const accepted = await fetch(new URL(`/api/operator-agreement?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ accepted: true, agreementReviewed: true, signature: "Operator One", confirmation: "I AGREE" }),
  });
  assert.equal(accepted.status, 200);

  const connectionPage = await fetch(new URL(`/connection?token=${token}`, session.url));
  assert.equal(connectionPage.status, 200);
  const connectionHtml = await connectionPage.text();
  assert.equal(connectionHtml.includes("Prepare the runtime environment"), true);
  assert.equal(connectionHtml.includes("Runtime directory"), true);
  assert.equal(connectionHtml.includes("Bun JavaScript runtime"), true);
  assert.equal(connectionHtml.includes("PM2 process manager"), true);
  assert.equal(connectionHtml.includes("Install Bun"), true);
  assert.equal(connectionHtml.includes("Install PM2"), true);
  assert.equal(connectionHtml.includes("/install?token="), true);
  assert.equal(connectionHtml.includes("Consensus server URL"), false);

  const environment = await fetch(new URL(`/api/environment?token=${token}`, session.url));
  assert.equal(environment.status, 200);
  const environmentBody = await environment.json() as {
    bun?: unknown;
    pm2?: unknown;
    bunInstallCommand?: string;
    pm2InstallCommand?: string;
  };
  assert.equal(typeof environmentBody.bun, "object");
  assert.equal(typeof environmentBody.pm2, "object");
  assert.equal(environmentBody.bunInstallCommand, "scripts/ensure-bun.sh");
  assert.equal(environmentBody.pm2InstallCommand, "scripts/ensure-pm2.sh");

  const blockedBunInstall = await fetch(new URL("/api/install-bun?token=invalid", session.url), {
    method: "POST",
  });
  assert.equal(blockedBunInstall.status, 403);

  const blockedPm2Install = await fetch(new URL("/api/install-pm2?token=invalid", session.url), {
    method: "POST",
  });
  assert.equal(blockedPm2Install.status, 403);

  const blockedManifest = await fetch(new URL("/api/install-manifest?token=invalid", session.url));
  assert.equal(blockedManifest.status, 403);

  const blockedRuntimeInstall = await fetch(new URL("/api/runtime-install?token=invalid", session.url), {
    method: "POST",
  });
  assert.equal(blockedRuntimeInstall.status, 403);

  const blockedNetworkStatus = await fetch(new URL("/api/network-status?token=invalid", session.url));
  assert.equal(blockedNetworkStatus.status, 403);

  const blockedNetworkEval = await fetch(new URL("/api/network-eval?token=invalid", session.url), {
    method: "POST",
  });
  assert.equal(blockedNetworkEval.status, 403);

  const blockedRegistrationStatus = await fetch(new URL("/api/registration-status?token=invalid", session.url));
  assert.equal(blockedRegistrationStatus.status, 403);

  const blockedRegisterNode = await fetch(new URL("/api/register-node?token=invalid", session.url), {
    method: "POST",
  });
  assert.equal(blockedRegisterNode.status, 403);

  const installDir = path.join(stateRoot, "runtime");
  const connectionAccepted = await fetch(new URL(`/api/connection?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ installDir }),
  });
  assert.equal(connectionAccepted.status, 200);
  const connectionBody = await connectionAccepted.json() as { nextUrl?: string };
  assert.equal(connectionBody.nextUrl, "/install");

  const installPage = await fetch(new URL(`/install?token=${token}`, session.url));
  assert.equal(installPage.status, 200);
  const installHtml = await installPage.text();
  assert.equal(installHtml.includes("Install the approved node runtime"), true);
  assert.equal(installHtml.includes("Approved release manifest"), true);
  assert.equal(installHtml.includes("Download & install"), true);
  assert.equal(installHtml.includes(installDir), true);

  const installManifest = await fetch(new URL(`/api/install-manifest?token=${token}`, session.url));
  assert.equal(installManifest.status, 200);
  const installManifestBody = await installManifest.json() as { manifest?: { version?: string }; canReuse?: boolean };
  assert.equal(installManifestBody.manifest?.version, "0.1.0-alpha.9-test");
  assert.equal(installManifestBody.canReuse, false);

  const runtimeInstall = await fetch(new URL(`/api/runtime-install?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "install" }),
  });
  assert.equal(runtimeInstall.status, 200);
  const runtimeInstallBody = await runtimeInstall.json() as { mode?: string };
  assert.equal(runtimeInstallBody.mode, "test-install");

  const networkPage = await fetch(new URL(`/network?token=${token}`, session.url));
  assert.equal(networkPage.status, 200);
  const networkHtml = await networkPage.text();
  assert.equal(networkHtml.includes("Confirm network reachability"), true);
  assert.equal(networkHtml.includes("Secure-channel benchmark"), true);

  const networkStatus = await fetch(new URL(`/api/network-status?token=${token}`, session.url));
  assert.equal(networkStatus.status, 200);
  const networkStatusBody = await networkStatus.json() as { testFlow?: boolean };
  assert.equal(networkStatusBody.testFlow, true);

  const networkEval = await fetch(new URL(`/api/network-eval?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ mode: "test" }),
  });
  assert.equal(networkEval.status, 200);
  const networkEvalBody = await networkEval.json() as {
    mode?: string;
    network?: { publicIpv4?: string; evalPassedAt?: string };
  };
  assert.equal(networkEvalBody.mode, "test");
  assert.equal(networkEvalBody.network?.publicIpv4, "203.0.113.42");
  assert.equal(typeof networkEvalBody.network?.evalPassedAt, "string");

  const registrationPage = await fetch(new URL(`/registration?token=${token}`, session.url));
  assert.equal(registrationPage.status, 200);
  const registrationHtml = await registrationPage.text();
  assert.equal(registrationHtml.includes("Register this node"), true);
  assert.equal(registrationHtml.includes("Payout wallets"), true);

  const emailStart = await fetch(new URL(`/api/email/start?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "ops@example.com" }),
  });
  assert.equal(emailStart.status, 200);
  const emailStartBody = await emailStart.json() as { verification_id?: string; dev_code?: string };
  assert.equal(emailStartBody.verification_id, "local-test-email");
  assert.equal(emailStartBody.dev_code, "123456");

  const emailVerify = await fetch(new URL(`/api/email/verify?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "ops@example.com", verificationId: "local-test-email", code: "123456" }),
  });
  assert.equal(emailVerify.status, 200);

  const walletSession = await fetch(new URL(`/api/wallet-session?token=${token}`, session.url), {
    method: "POST",
  });
  assert.equal(walletSession.status, 200);
  const walletSessionBody = await walletSession.json() as { done?: boolean; addresses?: { evmAddress?: string } };
  assert.equal(walletSessionBody.done, true);
  assert.equal(walletSessionBody.addresses?.evmAddress, "0x0000000000000000000000000000000000000000");

  const registerNode = await fetch(new URL(`/api/register-node?token=${token}`, session.url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ port: "9090", startPm2: true }),
  });
  assert.equal(registerNode.status, 200);
  const registerNodeBody = await registerNode.json() as { config?: { node_id?: string }; pm2?: { started?: boolean } };
  assert.equal(registerNodeBody.config?.node_id, "node-local-test");
  assert.equal(registerNodeBody.pm2?.started, true);

  const successPage = await fetch(new URL(`/success?token=${token}`, session.url));
  assert.equal(successPage.status, 200);
  const successHtml = await successPage.text();
  assert.equal(successHtml.includes("This machine is now a Consensus node"), true);
  assert.equal(successHtml.includes("Control tunnel"), true);

  const pm2Start = await fetch(new URL(`/api/start-pm2?token=${token}`, session.url), {
    method: "POST",
  });
  assert.equal(pm2Start.status, 200);

  const saved = JSON.parse(await fs.readFile(path.join(stateRoot, "setup-progress.json"), "utf8")) as {
    operatorAgreementAccepted: boolean;
    operatorAgreementSignature: string;
    operatorAgreementVersion: string;
    serverUrl: string;
    installDir: string;
    installedVersion: string;
    publicIpv4: string;
    evalPassedAt: string;
    contact: string;
    evmAddress: string;
    solanaAddress: string;
    icpAddress: string;
    port: string;
  };
  assert.equal(saved.operatorAgreementAccepted, true);
  assert.equal(saved.operatorAgreementSignature, "Operator One");
  assert.equal(saved.operatorAgreementVersion, "node-operator-good-faith-v2");
  assert.equal(saved.serverUrl, "https://consensus.canister.software");
  assert.equal(saved.installDir, installDir);
  assert.equal(saved.installedVersion, "0.1.0-alpha.9-test");
  assert.equal(saved.publicIpv4, "203.0.113.42");
  assert.equal(typeof saved.evalPassedAt, "string");
  assert.equal(saved.contact, "ops@example.com");
  assert.equal(saved.evmAddress, "0x0000000000000000000000000000000000000000");
  assert.equal(saved.solanaAddress, "11111111111111111111111111111111");
  assert.equal(saved.icpAddress, "aaaaa-aa");
  assert.equal(saved.port, "9090");

  const config = JSON.parse(await fs.readFile(path.join(stateRoot, "config.json"), "utf8")) as { node_id?: string };
  assert.equal(config.node_id, "node-local-test");
} finally {
  await session.stop().catch(() => {});
  await fs.rm(stateRoot, { recursive: true, force: true });
}

console.log("setup wizard ok");
