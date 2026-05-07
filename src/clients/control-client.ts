import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { log } from "../log";
import { loadConfig } from "../node/state";
import type { ReleaseManifest } from "../types";
import { releaseManifest } from "../node/manifest";
import { capabilitiesRecord } from "../runtime/capabilities";
import { executeProxyCommand } from "../runtime/proxy-command";
import { loadOrCreateIdentity } from "../crypto/identity";
import { executeProxySessionMessage } from "../runtime/proxy-session";
import { connectEncryptedTunnel } from "../tunnel/connect";
import { MESSAGE_TYPE, TUNNEL_MODE, createErrorMessage, nowSeconds } from "../tunnel/messages";
import { compareManifests, downloadAndVerify } from "../update";

export interface ControlClientOptions {
  gatewayUrl: string;
  nodeId?: string;
  heartbeatIntervalMs?: number;
}

export async function startControlClient(options: ControlClientOptions) {
  const config = await loadConfig();
  const identity = await loadOrCreateIdentity();
  const nodeId = options.nodeId ?? config.node_id;
  if (!nodeId) {
    throw new Error("Missing node id. Register the node before starting control mode.");
  }

  const manifest = releaseManifest();
  log.info("control-client", "handshake-start", {
    node_id: nodeId,
    gateway_url: options.gatewayUrl,
    version: manifest.version,
  });
  const connected = await connectEncryptedTunnel({
    url: options.gatewayUrl,
    mode: TUNNEL_MODE.CONTROL,
    nodeId,
    identity,
    releaseVersion: manifest.version,
  });
  log.info("control-client", "handshake-complete", {
    node_id: nodeId,
    session_id: connected.sessionId,
    version: manifest.version,
  });

  const heartbeatIntervalMs = options.heartbeatIntervalMs ?? 30_000;
  let activeRequests = 0;
  const activeStreams = new Set<string>();
  const rawStreams = new Map<string, net.Socket>();
  let preparedUpdate: {
    updateId: string;
    manifest: ReleaseManifest;
    artifactPath: string;
    sha256: string;
  } | null = null;

  const sendHeartbeat = async () => {
    await connected.client.send({
      type: MESSAGE_TYPE.HEARTBEAT,
      timestamp: nowSeconds(),
      node_id: nodeId,
      uptime_seconds: Math.floor(process.uptime()),
      capabilities: capabilitiesRecord(),
      active_requests: activeRequests,
      active_streams: activeStreams.size,
    });
  };

  await sendHeartbeat();
  let stopped = false;
  let resolveClosed!: (event: { code?: number; reason?: string; error: Error }) => void;
  const closed = new Promise<{ code?: number; reason?: string; error: Error }>((resolve) => {
    resolveClosed = resolve;
  });
  connected.client.onClose((event) => {
    clearInterval(timer);
    for (const socket of rawStreams.values()) {
      socket.destroy();
    }
    log.warn("control-client", "connection-closed", {
      node_id: nodeId,
      session_id: connected.sessionId,
      code: event.code ?? null,
      reason: event.reason ?? event.error.message,
    });
    rawStreams.clear();
    activeStreams.clear();
    resolveClosed(event);
  });

  connected.client.onMessage(async (message, client) => {
    if (message.type === MESSAGE_TYPE.PROXY_REQUEST) {
      activeRequests += 1;
      log.info("control-client", "proxy-request", {
        node_id: nodeId,
        session_id: connected.sessionId,
        method: message.method,
        target_url: sanitizeUrl(message.target_url),
      });
      try {
        const response = await executeProxyCommand(message);
        log.info("control-client", "proxy-response", {
          node_id: nodeId,
          session_id: connected.sessionId,
          status: response.status,
        });
        await client.send(response);
      } catch (error) {
        log.error("control-client", "proxy-failed", {
          node_id: nodeId,
          session_id: connected.sessionId,
          message: error instanceof Error ? error.message : String(error),
        });
        await client.send(createErrorMessage({
          reply_to: message.id,
          code: "proxy_failed",
          message: error instanceof Error ? error.message : String(error),
        }));
      } finally {
        activeRequests = Math.max(0, activeRequests - 1);
      }
      return;
    }

    if (message.type === MESSAGE_TYPE.STREAM_OPEN) {
      if (message.target === "proxy-session") {
        activeStreams.add(message.stream_id);
        log.info("control-client", "proxy-stream-open", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
        });
        return;
      }

      const target = parseRawTunnelTarget(message.target);
      if (!target) {
        log.warn("control-client", "stream-open-rejected", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
          target: message.target ?? null,
        });
        await client.send(createErrorMessage({
          code: "unsupported_stream_target",
          message: `Unsupported stream target: ${message.target ?? ""}`,
        }));
        return;
      }

      activeStreams.add(message.stream_id);
      log.info("control-client", "raw-stream-open", {
        node_id: nodeId,
        session_id: connected.sessionId,
        stream_id: message.stream_id,
        target_host: target.host,
        target_port: target.port,
      });
      const socket = net.createConnection({ host: target.host, port: target.port });
      rawStreams.set(message.stream_id, socket);

      socket.on("data", (data) => {
        void client.send({
          type: MESSAGE_TYPE.STREAM_DATA,
          timestamp: nowSeconds(),
          stream_id: message.stream_id,
          data: data.toString("base64"),
          encoding: "base64",
        }).catch(() => undefined);
      });

      socket.on("close", () => {
        rawStreams.delete(message.stream_id);
        activeStreams.delete(message.stream_id);
        log.info("control-client", "raw-stream-closed", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
        });
        void client.send({
          type: MESSAGE_TYPE.STREAM_CLOSE,
          timestamp: nowSeconds(),
          stream_id: message.stream_id,
          reason: "target closed",
        }).catch(() => undefined);
      });

      socket.on("error", (error) => {
        rawStreams.delete(message.stream_id);
        activeStreams.delete(message.stream_id);
        log.error("control-client", "raw-stream-error", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
          message: error.message,
        });
        void client.send(createErrorMessage({
          code: "raw_tunnel_failed",
          message: error.message,
        })).catch(() => undefined);
        void client.send({
          type: MESSAGE_TYPE.STREAM_CLOSE,
          timestamp: nowSeconds(),
          stream_id: message.stream_id,
          reason: error.message,
        }).catch(() => undefined);
      });
      return;
    }

    if (message.type === MESSAGE_TYPE.STREAM_DATA) {
      const rawSocket = rawStreams.get(message.stream_id);
      if (rawSocket) {
        rawSocket.write(Buffer.from(message.data, "base64"));
        return;
      }

      activeRequests += 1;
      try {
        const output = await executeProxySessionMessage(Buffer.from(message.data, "base64"));
        await client.send({
          type: MESSAGE_TYPE.STREAM_DATA,
          timestamp: nowSeconds(),
          stream_id: message.stream_id,
          data: output.toString("base64"),
          encoding: "base64",
        });
      } finally {
        activeRequests = Math.max(0, activeRequests - 1);
      }
      return;
    }

    if (message.type === MESSAGE_TYPE.STREAM_CLOSE) {
      const rawSocket = rawStreams.get(message.stream_id);
      if (rawSocket) {
        rawStreams.delete(message.stream_id);
        rawSocket.destroy();
      }
      activeStreams.delete(message.stream_id);
      return;
    }

    if (message.type === MESSAGE_TYPE.UPDATE_PREPARE) {
      try {
        const current = releaseManifest();
        log.info("node-update", "prepare-received", {
          node_id: nodeId,
          session_id: connected.sessionId,
          update_id: message.update_id,
          current_version: current.version,
          target_version: message.manifest.version,
        });
        const status = compareManifests(current, message.manifest);
        const downloaded = status.update_required
          ? await downloadAndVerify(message.manifest)
          : { path: "", sha256: current.tarball_sha256 ?? "" };
        preparedUpdate = {
          updateId: message.update_id,
          manifest: message.manifest,
          artifactPath: downloaded.path,
          sha256: downloaded.sha256,
        };
        log.info("node-update", "prepare-ready", {
          node_id: nodeId,
          session_id: connected.sessionId,
          update_id: message.update_id,
          update_required: status.update_required,
          artifact_path: downloaded.path,
          sha256: downloaded.sha256,
        });
        await client.send({
          type: MESSAGE_TYPE.UPDATE_READY,
          timestamp: nowSeconds(),
          reply_to: message.id ?? message.update_id,
          update_id: message.update_id,
          artifact_path: downloaded.path,
          sha256: downloaded.sha256,
          current_version: current.version,
          target_version: message.manifest.version,
        });
      } catch (error) {
        log.error("node-update", "prepare-failed", {
          node_id: nodeId,
          session_id: connected.sessionId,
          update_id: message.update_id,
          message: error instanceof Error ? error.message : String(error),
        });
        await client.send({
          type: MESSAGE_TYPE.UPDATE_FAILED,
          timestamp: nowSeconds(),
          reply_to: message.id ?? message.update_id,
          update_id: message.update_id,
          code: "prepare_failed",
          message: error instanceof Error ? error.message : String(error),
        });
      }
      return;
    }

    if (message.type === MESSAGE_TYPE.UPDATE_APPLY) {
      if (!preparedUpdate || preparedUpdate.updateId !== message.update_id) {
        log.warn("node-update", "apply-rejected", {
          node_id: nodeId,
          session_id: connected.sessionId,
          update_id: message.update_id,
          reason: "update not prepared",
        });
        await client.send({
          type: MESSAGE_TYPE.UPDATE_FAILED,
          timestamp: nowSeconds(),
          reply_to: message.id ?? message.update_id,
          update_id: message.update_id,
          code: "update_not_prepared",
          message: "No matching prepared update is available",
        });
        return;
      }

      await client.send({
        type: MESSAGE_TYPE.ACK,
        timestamp: nowSeconds(),
        reply_to: message.id ?? message.update_id,
      });

      const restartAfterMs = Math.max(0, message.restart_after_ms ?? 1_000);
      log.info("node-update", "apply-scheduled", {
        node_id: nodeId,
        session_id: connected.sessionId,
        update_id: message.update_id,
        target_version: preparedUpdate.manifest.version,
        restart_after_ms: restartAfterMs,
      });
      setTimeout(() => {
        void (async () => {
          try {
            await runUpdateCommand(preparedUpdate!);
            log.info("node-update", "apply-complete", {
              node_id: nodeId,
              session_id: connected.sessionId,
              update_id: message.update_id,
              target_version: preparedUpdate!.manifest.version,
            });
            connected.client.close(1012, "node update apply requested");
            process.exit(75);
          } catch (error) {
            log.error("node-update", "apply-failed", {
              node_id: nodeId,
              session_id: connected.sessionId,
              update_id: message.update_id,
              message: error instanceof Error ? error.message : String(error),
            });
            await client.send({
              type: MESSAGE_TYPE.UPDATE_FAILED,
              timestamp: nowSeconds(),
              update_id: message.update_id,
              code: "apply_failed",
              message: error instanceof Error ? error.message : String(error),
            }).catch(() => undefined);
          }
        })();
      }, restartAfterMs).unref();
    }
  });

  async function runUpdateCommand(update: NonNullable<typeof preparedUpdate>): Promise<void> {
    const command = updateCommand();
    if (!command) {
      throw new Error("No node update command is available");
    }

    log.info("node-update", "installer-start", {
      node_id: nodeId,
      session_id: connected.sessionId,
      update_id: update.updateId,
      target_version: update.manifest.version,
      command,
      artifact_path: update.artifactPath,
    });
    const child = Bun.spawn(["sh", "-lc", command], {
      env: {
        ...process.env,
        CONSENSUS_NODE_UPDATE_ID: update.updateId,
        CONSENSUS_NODE_ARTIFACT_PATH: update.artifactPath,
        CONSENSUS_NODE_TARGET_VERSION: update.manifest.version,
      },
      stdout: "inherit",
      stderr: "inherit",
    });
    const code = await child.exited;
    if (code !== 0) {
      throw new Error(`Node update command exited with code ${code}`);
    }
    log.info("node-update", "installer-complete", {
      node_id: nodeId,
      session_id: connected.sessionId,
      update_id: update.updateId,
      target_version: update.manifest.version,
    });
  }

  function updateCommand(): string | null {
    const explicit = process.env.CONSENSUS_NODE_UPDATE_COMMAND?.trim();
    if (explicit) return explicit;

    const localScript = path.join(process.cwd(), "scripts", "install-release.sh");
    if (fs.existsSync(localScript)) return shellQuote(localScript);

    const installDir = process.env.CONSENSUS_NODE_INSTALL_DIR?.trim() ||
      path.join(os.homedir(), ".consensus", "node-runtime");
    const installedScript = path.join(installDir, "current", "scripts", "install-release.sh");
    if (fs.existsSync(installedScript)) return shellQuote(installedScript);

    return null;
  }

  function shellQuote(value: string): string {
    return `'${value.replace(/'/g, `'\\''`)}'`;
  }

  const timer = setInterval(() => {
    void sendHeartbeat().catch((error) => {
      log.error("control-client", "heartbeat-failed", {
        node_id: nodeId,
        session_id: connected.sessionId,
        message: error instanceof Error ? error.message : String(error),
      });
      if (!stopped) connected.client.close(1011, "heartbeat failed");
    });
  }, heartbeatIntervalMs);

  return {
    ...connected,
    nodeId,
    closed,
    stop: () => {
      stopped = true;
      clearInterval(timer);
      log.info("control-client", "stop-requested", {
        node_id: nodeId,
        session_id: connected.sessionId,
      });
      connected.client.close(1000, "control stopped");
    },
  };
}

function sanitizeUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = "";
    url.password = "";
    url.search = url.search ? "?..." : "";
    return url.toString();
  } catch {
    return value.length > 120 ? `${value.slice(0, 117)}...` : value;
  }
}

function parseRawTunnelTarget(value: string | undefined): { host: string; port: number } | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as { kind?: string; host?: string; port?: number };
    if (parsed.kind !== "raw-tunnel" || !parsed.host) return null;
    if (typeof parsed.port !== "number" || !Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) {
      return null;
    }
    return { host: parsed.host, port: parsed.port };
  } catch {
    return null;
  }
}
