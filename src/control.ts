import { startControlClient } from "./clients/control-client";
import { log } from "./log";

async function main(): Promise<void> {
  const gatewayUrl = tunnelUrlFromEnv();
  let attempt = 0;

  while (true) {
    try {
      log.info("control", "connect-start", { gateway_url: gatewayUrl, attempt: attempt + 1 });
      const connected = await startControlClient({ gatewayUrl });
      attempt = 0;

      log.info("control", "connected", {
        node_id: connected.nodeId,
        session_id: connected.sessionId,
      });

      const close = await connected.closed;
      log.warn("control", "closed", {
        code: close.code ?? null,
        reason: close.reason ?? close.error.message,
      });
    } catch (error) {
      log.error("control", "connect-failed", {
        message: error instanceof Error ? error.message : String(error),
      });
    }

    attempt += 1;
    const delayMs = reconnectDelayMs(attempt);
    log.warn("control", "reconnect-scheduled", {
      attempt,
      delay_ms: delayMs,
    });
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

function tunnelUrlFromEnv(): string {
  const explicit = process.env.CONSENSUS_TUNNEL_URL?.trim();
  if (explicit) return explicit;

  const serverUrl = process.env.CONSENSUS_SERVER_URL?.trim();
  if (!serverUrl) {
    throw new Error("Missing CONSENSUS_TUNNEL_URL or CONSENSUS_SERVER_URL");
  }

  const url = new URL(serverUrl);
  url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
  url.pathname = "/node/tunnel";
  url.search = "";
  url.hash = "";
  return url.toString();
}

function reconnectDelayMs(attempt: number): number {
  const capped = Math.min(attempt, 6);
  const base = Math.min(30_000, 1_000 * 2 ** (capped - 1));
  const jitter = Math.floor(Math.random() * 500);
  return base + jitter;
}

main().catch((error) => {
  log.error("control", "fatal", {
    message: error instanceof Error ? error.message : String(error),
  });
  process.exit(1);
});
