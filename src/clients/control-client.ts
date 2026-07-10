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
import { runEvalAction } from "../runtime/eval";
import { compareManifests, downloadAndVerify } from "../update";
import { JtiReplayCache } from "../tickets/replay";
import { loadPinnedOrchestratorKey } from "../tickets/orchestrator-key";
import { startDataPlaneStream, type DataPlaneStream } from "./data-plane-stream";

const PUBLIC_TUNNEL_FRAME = {
  STREAM_OPEN:  0x01,
  STREAM_DATA:  0x02,
  STREAM_END:   0x03,
  STREAM_RESET: 0x04,
  PING:         0x05,
  PONG:         0x06,
} as const;

type PublicTunnelFrameType = typeof PUBLIC_TUNNEL_FRAME[keyof typeof PUBLIC_TUNNEL_FRAME];

function encodePublicTunnelFrame(type: PublicTunnelFrameType, streamId: number, payload: Buffer = Buffer.alloc(0)): Buffer {
  const header = Buffer.allocUnsafe(5);
  header.writeUInt8(type, 0);
  header.writeUInt32BE(streamId, 1);
  return Buffer.concat([header, payload]);
}

function decodePublicTunnelFrame(data: Buffer): { type: PublicTunnelFrameType; streamId: number; payload: Buffer } {
  if (data.length < 5) throw new RangeError(`Public tunnel frame too short: ${data.length} bytes`);
  return {
    type:     data.readUInt8(0) as PublicTunnelFrameType,
    streamId: data.readUInt32BE(1),
    payload:  data.subarray(5),
  };
}

// Process-global jti replay cache for the data plane. It MUST outlive individual
// control connections: src/control.ts recreates the control client on every
// reconnect, so a per-client cache would forget already-spent ticket jtis across a
// transient disconnect and let a still-valid ticket be replayed on the new
// connection. The cache self-prunes by ticket expiry, so a long-lived process
// stays bounded. (Mirrors runtime/data-route.ts's per-process replay cache.)
const dataPlaneReplay = new JtiReplayCache();

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
  const publicTunnelOwners = new Map<string, {
    streamId: string;
    nextStreamId: number;
    ownerToServer: Map<number, string>;
    serverToOwner: Map<string, number>;
  }>();
  const publicTunnelStreams = new Map<string, { tunnelId: string; ownerStreamId: number }>();
  const dataPlaneStreams = new Map<string, DataPlaneStream>();
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
    for (const stream of dataPlaneStreams.values()) {
      stream.fail(new Error("connection closed"));
    }
    rawStreams.clear();
    publicTunnelOwners.clear();
    publicTunnelStreams.clear();
    dataPlaneStreams.clear();
    activeStreams.clear();
    resolveClosed(event);
  });

  const sendStreamData = async (streamId: string, data: Buffer) => {
    await connected.client.send({
      type: MESSAGE_TYPE.STREAM_DATA,
      timestamp: nowSeconds(),
      stream_id: streamId,
      data: data.toString("base64"),
      encoding: "base64",
    });
  };

  const sendStreamClose = async (streamId: string, reason: string) => {
    await connected.client.send({
      type: MESSAGE_TYPE.STREAM_CLOSE,
      timestamp: nowSeconds(),
      stream_id: streamId,
      reason,
    });
  };

  const cleanupPublicTunnelStream = (serverStreamId: string) => {
    const linked = publicTunnelStreams.get(serverStreamId);
    if (!linked) return;
    const owner = publicTunnelOwners.get(linked.tunnelId);
    owner?.ownerToServer.delete(linked.ownerStreamId);
    owner?.serverToOwner.delete(serverStreamId);
    publicTunnelStreams.delete(serverStreamId);
    activeStreams.delete(serverStreamId);
  };

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

    if (message.type === MESSAGE_TYPE.EVAL_REQUEST) {
      // During a stability trial the orchestrator drives two probes over the
      // control tunnel: an occasional sustained-bench sample (thermal) and an
      // integrity re-attestation. Reuse the same runEvalAction dispatch as eval,
      // but only for those read-only actions.
      const allowed = message.action === "benchmark_sustained" || message.action === "integrity";
      if (!allowed) {
        await client.send(createErrorMessage({
          reply_to: message.id,
          code: "eval_action_not_allowed",
          message: `Action not allowed on the control tunnel: ${message.action}`,
        }));
        return;
      }
      log.info("control-client", "trial-probe", {
        node_id: nodeId,
        session_id: connected.sessionId,
        action: message.action,
      });
      try {
        const result = await runEvalAction(message.action, message.params ?? {});
        await client.send({
          type: MESSAGE_TYPE.EVAL_RESPONSE,
          timestamp: nowSeconds(),
          reply_to: message.id ?? "",
          action: message.action,
          ok: true,
          result,
        });
      } catch (error) {
        await client.send({
          type: MESSAGE_TYPE.EVAL_RESPONSE,
          timestamp: nowSeconds(),
          reply_to: message.id ?? "",
          action: message.action,
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        });
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

      const target = parseStreamTarget(message.target);
      if (target?.kind === "public-tunnel-owner") {
        activeStreams.add(message.stream_id);
        publicTunnelOwners.set(target.tunnelId, {
          streamId: message.stream_id,
          nextStreamId: 1,
          ownerToServer: new Map(),
          serverToOwner: new Map(),
        });
        log.info("control-client", "public-tunnel-owner-open", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
          tunnel_id: target.tunnelId,
        });
        return;
      }

      if (target?.kind === "public-tunnel-stream") {
        const owner = publicTunnelOwners.get(target.tunnelId);
        if (!owner) {
          log.warn("control-client", "public-tunnel-stream-rejected", {
            node_id: nodeId,
            session_id: connected.sessionId,
            stream_id: message.stream_id,
            tunnel_id: target.tunnelId,
            reason: "owner tunnel is not connected",
          });
          await sendStreamClose(message.stream_id, "tunnel owner unavailable");
          return;
        }

        const ownerStreamId = owner.nextStreamId++;
        owner.ownerToServer.set(ownerStreamId, message.stream_id);
        owner.serverToOwner.set(message.stream_id, ownerStreamId);
        publicTunnelStreams.set(message.stream_id, {
          tunnelId: target.tunnelId,
          ownerStreamId,
        });
        activeStreams.add(message.stream_id);
        log.info("control-client", "public-tunnel-stream-open", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
          tunnel_id: target.tunnelId,
          owner_stream_id: ownerStreamId,
          initial_bytes: target.initialData.length,
        });
        await sendStreamData(
          owner.streamId,
          encodePublicTunnelFrame(PUBLIC_TUNNEL_FRAME.STREAM_OPEN, ownerStreamId, target.initialData),
        );
        return;
      }

      if (target?.kind === "data-plane") {
        const streamId = message.stream_id;
        activeStreams.add(streamId);
        log.info("control-client", "data-plane-stream-open", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: streamId,
        });
        const stream = startDataPlaneStream({
          resolveDeps: async () => {
            const pinned = await loadPinnedOrchestratorKey();
            if (!pinned) throw new Error("no pinned orchestrator key");
            return { nodeId, identity, pinnedKey: pinned.key, replay: dataPlaneReplay };
          },
          sendData: (data) => sendStreamData(streamId, data),
          sendClose: (reason) => sendStreamClose(streamId, reason),
          onError: (error) => {
            log.warn("control-client", "data-plane-stream-failed", {
              node_id: nodeId,
              session_id: connected.sessionId,
              stream_id: streamId,
              message: error.message,
            });
          },
          onDone: () => {
            dataPlaneStreams.delete(streamId);
            activeStreams.delete(streamId);
            log.info("control-client", "data-plane-stream-closed", {
              node_id: nodeId,
              session_id: connected.sessionId,
              stream_id: streamId,
            });
          },
        });
        dataPlaneStreams.set(streamId, stream);
        return;
      }

      if (!target || target.kind !== "raw-tunnel") {
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
        if (!rawStreams.has(message.stream_id)) return;
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
      const ownerEntry = Array.from(publicTunnelOwners.entries())
        .find(([, owner]) => owner.streamId === message.stream_id);
      if (ownerEntry) {
        const [tunnelId, owner] = ownerEntry;
        try {
          const frame = decodePublicTunnelFrame(Buffer.from(message.data, "base64"));
          if (frame.type === PUBLIC_TUNNEL_FRAME.PING) {
            await sendStreamData(owner.streamId, encodePublicTunnelFrame(PUBLIC_TUNNEL_FRAME.PONG, 0));
            return;
          }
          if (frame.type === PUBLIC_TUNNEL_FRAME.PONG) return;

          const serverStreamId = owner.ownerToServer.get(frame.streamId);
          if (!serverStreamId) return;

          if (frame.type === PUBLIC_TUNNEL_FRAME.STREAM_DATA) {
            await sendStreamData(serverStreamId, frame.payload);
            return;
          }
          if (frame.type === PUBLIC_TUNNEL_FRAME.STREAM_END) {
            cleanupPublicTunnelStream(serverStreamId);
            await sendStreamClose(serverStreamId, "target closed");
            return;
          }
          if (frame.type === PUBLIC_TUNNEL_FRAME.STREAM_RESET) {
            cleanupPublicTunnelStream(serverStreamId);
            await sendStreamClose(serverStreamId, "target reset");
            return;
          }
        } catch (error) {
          log.error("control-client", "public-tunnel-owner-data-failed", {
            node_id: nodeId,
            session_id: connected.sessionId,
            stream_id: message.stream_id,
            tunnel_id: tunnelId,
            message: error instanceof Error ? error.message : String(error),
          });
        }
        return;
      }

      const linkedPublicStream = publicTunnelStreams.get(message.stream_id);
      if (linkedPublicStream) {
        const owner = publicTunnelOwners.get(linkedPublicStream.tunnelId);
        if (!owner) {
          cleanupPublicTunnelStream(message.stream_id);
          await sendStreamClose(message.stream_id, "tunnel owner unavailable");
          return;
        }
        await sendStreamData(
          owner.streamId,
          encodePublicTunnelFrame(
            PUBLIC_TUNNEL_FRAME.STREAM_DATA,
            linkedPublicStream.ownerStreamId,
            Buffer.from(message.data, "base64"),
          ),
        );
        return;
      }

      const rawSocket = rawStreams.get(message.stream_id);
      if (rawSocket) {
        rawSocket.write(Buffer.from(message.data, "base64"));
        return;
      }

      const dataPlaneStream = dataPlaneStreams.get(message.stream_id);
      if (dataPlaneStream) {
        dataPlaneStream.push(Buffer.from(message.data, "base64"));
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
       } catch (error) {
        log.error("control-client", "stream-data-failed", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
          message: error instanceof Error ? error.message : String(error),
        });
        void client.send(createErrorMessage({
          code: "stream_data_failed",
          message: error instanceof Error ? error.message : String(error),
        })).catch(() => undefined);
      } finally {
        activeRequests = Math.max(0, activeRequests - 1);
      }
      return;
    }

    if (message.type === MESSAGE_TYPE.STREAM_CLOSE) {
      const ownerEntry = Array.from(publicTunnelOwners.entries())
        .find(([, owner]) => owner.streamId === message.stream_id);
      if (ownerEntry) {
        const [tunnelId, owner] = ownerEntry;
        for (const serverStreamId of owner.serverToOwner.keys()) {
          publicTunnelStreams.delete(serverStreamId);
          activeStreams.delete(serverStreamId);
          void sendStreamClose(serverStreamId, "tunnel owner closed").catch(() => undefined);
        }
        publicTunnelOwners.delete(tunnelId);
        activeStreams.delete(message.stream_id);
        log.info("control-client", "public-tunnel-owner-closed", {
          node_id: nodeId,
          session_id: connected.sessionId,
          stream_id: message.stream_id,
          tunnel_id: tunnelId,
        });
        return;
      }

      const linkedPublicStream = publicTunnelStreams.get(message.stream_id);
      if (linkedPublicStream) {
        const owner = publicTunnelOwners.get(linkedPublicStream.tunnelId);
        if (owner) {
          await sendStreamData(
            owner.streamId,
            encodePublicTunnelFrame(PUBLIC_TUNNEL_FRAME.STREAM_RESET, linkedPublicStream.ownerStreamId),
          ).catch(() => undefined);
        }
        cleanupPublicTunnelStream(message.stream_id);
        return;
      }

      const dataPlaneStream = dataPlaneStreams.get(message.stream_id);
      if (dataPlaneStream) {
        dataPlaneStreams.delete(message.stream_id);
        activeStreams.delete(message.stream_id);
        dataPlaneStream.fail(new Error("client stream closed"));
        return;
      }

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
            await sleep(250);
            process.exit(0);
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

type StreamTarget =
  | { kind: "raw-tunnel"; host: string; port: number }
  | { kind: "public-tunnel-owner"; tunnelId: string }
  | { kind: "public-tunnel-stream"; tunnelId: string; initialData: Buffer }
  | { kind: "data-plane" };

function parseStreamTarget(value: string | undefined): StreamTarget | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as {
      kind?: string;
      host?: string;
      port?: number;
      tunnel_id?: string;
      initial_data?: string;
    };
    if (parsed.kind === "raw-tunnel") {
      if (!parsed.host) return null;
      if (typeof parsed.port !== "number" || !Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) {
        return null;
      }
      return { kind: "raw-tunnel", host: parsed.host, port: parsed.port };
    }
    if (parsed.kind === "public-tunnel-owner") {
      if (!parsed.tunnel_id) return null;
      return { kind: "public-tunnel-owner", tunnelId: parsed.tunnel_id };
    }
    if (parsed.kind === "public-tunnel-stream") {
      if (!parsed.tunnel_id) return null;
      return {
        kind: "public-tunnel-stream",
        tunnelId: parsed.tunnel_id,
        initialData: parsed.initial_data ? Buffer.from(parsed.initial_data, "base64") : Buffer.alloc(0),
      };
    }
    if (parsed.kind === "data-plane") {
      return { kind: "data-plane" };
    }
    return null;
  } catch {
    return null;
  }
}
