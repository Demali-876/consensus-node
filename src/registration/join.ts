import { loadOrCreateIdentity } from "../crypto/identity";
import { capabilitiesRecord } from "../runtime/capabilities";
import { assertMachineCanRegister, claimMachineNode } from "../node/machine";
import { loadConfig, loadJoinAuthorization, saveConfig, type JoinAuthorization } from "../node/state";
import { resolvePinnedPubkey } from "../tickets/orchestrator-key";
import type { OrchestratorPublicJwk } from "../types";

export interface RegisterNodeOptions {
  serverUrl: string;
  ipv4: string;
  ipv6?: string | null;
  port: number;
  contact: string;
  emailVerificationToken: string;
  evmAddress: string;
  solanaAddress: string;
  icpAddress: string;
  machineId?: string;
}

export interface JoinPayload {
  pubkey_ed25519_pem: string;
  ipv4: string;
  ipv6?: string | null;
  port: number;
  contact: string;
  email_verification_token: string;
  evm_address: string;
  solana_address: string;
  icp_address: string;
  machine_id?: string;
  capabilities: ReturnType<typeof capabilitiesRecord>;
  join_id: string;
  join_signature: string;
}

export interface JoinResponse {
  success: boolean;
  node_id: string;
  domain: string;
  ipv4: string;
  ipv6: string | null;
  port: number;
  region: string;
  status: string;
  benchmark_score: number;
  orchestrator_pubkey?: OrchestratorPublicJwk | null;
  join_request_id?: string | null;
  processing_time_ms: number;
}

export async function registerNode(options: RegisterNodeOptions): Promise<JoinResponse> {
  const identity = await loadOrCreateIdentity();
  const joinAuth = await requireJoinAuthorization();
  const existing = await loadConfig();
  const machine = await assertMachineCanRegister({ existingNodeId: existing.node_id });
  const payload = buildJoinPayload({
    options: { ...options, machineId: options.machineId ?? machine.machine_id },
    publicKeyPem: identity.publicKeyPem,
    joinAuth,
  });

  const response = await fetch(`${trimTrailingSlash(options.serverUrl)}/node/join`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(120_000),
  });

  const body = await response.json().catch(() => null) as JoinResponse | { error?: string; message?: string } | null;
  if (!response.ok) {
    const detail = body && "message" in body && body.message
      ? body.message
      : body && "error" in body && body.error
        ? body.error
        : `HTTP ${response.status}`;
    throw new Error(`Node join failed: ${detail}`);
  }
  if (!body || !("success" in body) || !body.success) {
    throw new Error("Node join failed: malformed response");
  }

  if (machine.node_id && machine.node_id !== body.node_id) {
    throw new Error(`This machine is already registered as ${machine.node_id}; server returned ${body.node_id}`);
  }

  await saveConfig({
    ...existing,
    node_id: body.node_id,
    machine_id: machine.machine_id,
    domain: body.domain,
    region: body.region,
    ipv4: body.ipv4,
    ipv6: body.ipv6,
    port: body.port,
    registered_at: new Date().toISOString(),
    benchmark_score: body.benchmark_score,
    // Preserve a prior trust anchor unless the response carries a replacement —
    // a key-less response (older server / FREE_MODE) must not wipe the pin.
    orchestrator_pubkey: resolvePinnedPubkey(existing.orchestrator_pubkey, body.orchestrator_pubkey),
  });
  await claimMachineNode({
    nodeId: body.node_id,
    installDir: process.env.CONSENSUS_NODE_INSTALL_DIR?.trim() || undefined,
  });

  return body;
}

export function buildJoinPayload(input: {
  options: RegisterNodeOptions;
  publicKeyPem: string;
  joinAuth: JoinAuthorization;
}): JoinPayload {
  return {
    pubkey_ed25519_pem: input.publicKeyPem,
    ipv4: input.options.ipv4,
    ipv6: input.options.ipv6 ?? null,
    port: input.options.port,
    contact: input.options.contact,
    email_verification_token: input.options.emailVerificationToken,
    evm_address: input.options.evmAddress,
    solana_address: input.options.solanaAddress,
    icp_address: input.options.icpAddress,
    machine_id: input.options.machineId,
    capabilities: capabilitiesRecord(),
    join_id: input.joinAuth.join_id,
    join_signature: input.joinAuth.signature,
  };
}

export function optionsFromEnv(env: NodeJS.ProcessEnv = process.env): RegisterNodeOptions {
  return {
    serverUrl: requiredEnv(env, "CONSENSUS_SERVER_URL"),
    ipv4: requiredEnv(env, "CONSENSUS_NODE_IPV4"),
    ipv6: optionalEnv(env, "CONSENSUS_NODE_IPV6"),
    port: integerEnv(env, "CONSENSUS_NODE_PORT", integerEnv(env, "NODE_PORT", 9090)),
    contact: requiredEnv(env, "CONSENSUS_NODE_CONTACT"),
    emailVerificationToken: requiredEnv(env, "CONSENSUS_EMAIL_VERIFICATION_TOKEN"),
    evmAddress: requiredEnv(env, "CONSENSUS_EVM_ADDRESS"),
    solanaAddress: requiredEnv(env, "CONSENSUS_SOLANA_ADDRESS"),
    icpAddress: requiredEnv(env, "CONSENSUS_ICP_ADDRESS"),
    machineId: optionalEnv(env, "CONSENSUS_MACHINE_ID") ?? undefined,
  };
}

async function requireJoinAuthorization(): Promise<JoinAuthorization> {
  const joinAuth = await loadJoinAuthorization();
  if (!joinAuth) {
    throw new Error("Missing join authorization. Run encrypted eval first so join-auth.json can be created.");
  }
  if (joinAuth.alg !== "ed25519") {
    throw new Error(`Unsupported join authorization algorithm: ${joinAuth.alg}`);
  }
  if (joinAuth.expires_at <= Math.floor(Date.now() / 1000)) {
    throw new Error("Join authorization expired. Run encrypted eval again to get a fresh join request.");
  }
  return joinAuth;
}

function requiredEnv(env: NodeJS.ProcessEnv, key: string): string {
  const value = optionalEnv(env, key);
  if (!value) throw new Error(`Missing required environment variable: ${key}`);
  return value;
}

function optionalEnv(env: NodeJS.ProcessEnv, key: string): string | null {
  const value = env[key]?.trim();
  return value ? value : null;
}

function integerEnv(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const value = optionalEnv(env, key);
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`${key} must be an integer TCP port`);
  }
  return parsed;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
