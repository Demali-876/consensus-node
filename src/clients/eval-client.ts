import { loadOrCreateIdentity, signBytes } from "../crypto/identity";
import { log } from "../log";
import { releaseManifest } from "../node/manifest";
import { saveJoinAuthorization } from "../node/state";
import { runEvalAction } from "../runtime/eval";
import { connectEncryptedTunnel } from "../tunnel/connect";
import { MESSAGE_TYPE, TUNNEL_MODE, nowSeconds, type EvalRequestMessage, type JoinReadyMessage } from "../tunnel/messages";
import type { TunnelClient } from "../tunnel/tunnel-client";

export interface EvalClientOptions {
  gatewayUrl: string;
  candidateId?: string;
  requestTimeoutMs?: number;
}

export async function startEvalClient(options: EvalClientOptions) {
  const manifest = releaseManifest();
  log.info("eval-client", "handshake-start", {
    gateway_url: options.gatewayUrl,
    candidate_id: options.candidateId ?? null,
    version: manifest.version,
  });
  const connected = await connectEncryptedTunnel({
    url: options.gatewayUrl,
    mode: TUNNEL_MODE.EVAL,
    candidateId: options.candidateId,
    releaseVersion: manifest.version,
    requestTimeoutMs: options.requestTimeoutMs,
  });
  log.info("eval-client", "handshake-complete", {
    session_id: connected.sessionId,
    candidate_id: options.candidateId ?? null,
    version: manifest.version,
  });

  connected.client.onMessage(async (message, client) => {
    if (message.type === MESSAGE_TYPE.EVAL_REQUEST) {
      await handleEvalRequest(message, client);
      return;
    }
    if (message.type === MESSAGE_TYPE.JOIN_READY) {
      await handleJoinReady(message);
    }
  });

  return connected;
}

async function handleJoinReady(message: JoinReadyMessage): Promise<void> {
  log.info("eval-client", "join-ready", {
    join_id: message.join_id,
    expires_at: message.expires_at,
  });
  const identity = await loadOrCreateIdentity();
  const nonce = decodeBase64Url(message.nonce);
  const signature = signBytes(identity.privateKeyPem, nonce);

  await saveJoinAuthorization({
    join_id: message.join_id,
    alg: message.alg,
    nonce: message.nonce,
    signature,
    expires_at: message.expires_at,
    saved_at: new Date().toISOString(),
  });
}

function decodeBase64Url(value: string): Buffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=");
  return Buffer.from(padded, "base64");
}

async function handleEvalRequest(message: EvalRequestMessage, client: TunnelClient): Promise<void> {
  log.info("eval-client", "action-start", { action: message.action });
  try {
    const result = await runEvalAction(message.action, message.params ?? {});
    log.info("eval-client", "action-complete", { action: message.action });
    await client.send({
      type: MESSAGE_TYPE.EVAL_RESPONSE,
      timestamp: nowSeconds(),
      reply_to: message.id ?? "",
      action: message.action,
      ok: true,
      result,
    });
  } catch (error) {
    log.error("eval-client", "action-failed", {
      action: message.action,
      message: error instanceof Error ? error.message : String(error),
    });
    await client.send({
      type: MESSAGE_TYPE.EVAL_RESPONSE,
      timestamp: nowSeconds(),
      reply_to: message.id ?? "",
      action: message.action,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}
