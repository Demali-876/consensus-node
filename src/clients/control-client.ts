import { loadOrCreateIdentity } from "../crypto/identity";
import { releaseManifest } from "../node/manifest";
import { loadConfig } from "../node/state";
import { capabilitiesRecord } from "../runtime/capabilities";
import { executeProxyCommand } from "../runtime/proxy-command";
import { executeProxySessionMessage } from "../runtime/proxy-session";
import { connectEncryptedTunnel } from "../tunnel/connect";
import { MESSAGE_TYPE, TUNNEL_MODE, createErrorMessage, nowSeconds } from "../tunnel/messages";
import { compareManifests, downloadAndVerify } from "../update";
import type { ReleaseManifest } from "../types";

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

  const connected = await connectEncryptedTunnel({
    url: options.gatewayUrl,
    mode: TUNNEL_MODE.CONTROL,
    nodeId,
    identity,
    releaseVersion: releaseManifest().version,
  });

  const heartbeatIntervalMs = options.heartbeatIntervalMs ?? 30_000;
  let activeRequests = 0;
  const activeStreams = new Set<string>();
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
    resolveClosed(event);
  });

  connected.client.onMessage(async (message, client) => {
    if (message.type === MESSAGE_TYPE.PROXY_REQUEST) {
      activeRequests += 1;
      try {
        await client.send(await executeProxyCommand(message));
      } catch (error) {
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
      if (message.target !== "proxy-session") {
        await client.send(createErrorMessage({
          code: "unsupported_stream_target",
          message: `Unsupported stream target: ${message.target ?? ""}`,
        }));
      }
      activeStreams.add(message.stream_id);
      return;
    }

    if (message.type === MESSAGE_TYPE.STREAM_DATA) {
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
      activeStreams.delete(message.stream_id);
      return;
    }

    if (message.type === MESSAGE_TYPE.UPDATE_PREPARE) {
      try {
        const current = releaseManifest();
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
        await client.send({
          type: MESSAGE_TYPE.UPDATE_FAILED,
          timestamp: nowSeconds(),
          reply_to: message.id,
          update_id: message.update_id,
          code: "prepare_failed",
          message: error instanceof Error ? error.message : String(error),
        });
      }
      return;
    }

    if (message.type === MESSAGE_TYPE.UPDATE_APPLY) {
      if (!preparedUpdate || preparedUpdate.updateId !== message.update_id) {
        await client.send({
          type: MESSAGE_TYPE.UPDATE_FAILED,
          timestamp: nowSeconds(),
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
      setTimeout(() => {
        connected.client.close(1012, "node update apply requested");
        const command = process.env.CONSENSUS_NODE_UPDATE_COMMAND;
        if (command) {
          Bun.spawn(["sh", "-lc", command], {
            env: {
              ...process.env,
              CONSENSUS_NODE_UPDATE_ID: preparedUpdate!.updateId,
              CONSENSUS_NODE_ARTIFACT_PATH: preparedUpdate!.artifactPath,
              CONSENSUS_NODE_TARGET_VERSION: preparedUpdate!.manifest.version,
            },
            stdout: "inherit",
            stderr: "inherit",
          });
        }
        process.exit(0);
      }, restartAfterMs).unref();
    }
  });

  const timer = setInterval(() => {
    void sendHeartbeat().catch((error) => {
      console.error("Control heartbeat failed:", error);
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
      connected.client.close(1000, "control stopped");
    },
  };
}
