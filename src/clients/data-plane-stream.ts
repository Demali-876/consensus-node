// Adapts a single control-tunnel stream to the transport-agnostic data-plane
// protocol (tunnel/data-plane.ts → serveDataConnection).
//
// The orchestrator gateway bridges a client's
// wss://<node>.consensus.canister.software/connect socket onto a server-driven
// stream opened with target {kind:"data-plane"}. The node serves that request
// over the outbound control tunnel it already holds — so there is no inbound
// port, TLS terminator, or runtime HTTP listener on the node data path.
//
// This mirrors runtime/data-route.ts's wsServerTransport, except the byte
// channel is a tunnel stream: inbound STREAM_DATA payloads arrive via push(),
// outbound messages go through sendData(), and the session is finished with a
// single STREAM_CLOSE via sendClose(). A peer STREAM_CLOSE or a dropped tunnel
// is signalled with fail(), which aborts the in-flight recv().

import { serveDataConnection, type DataPlaneServeDeps, type MessageTransport } from "../tunnel/data-plane";

export interface DataPlaneStream {
  /** Feed one inbound STREAM_DATA payload (already base64-decoded) to the session. */
  push(data: Buffer): void;
  /** Abort the session: the peer closed the stream, or the tunnel dropped. */
  fail(reason: Error): void;
}

export interface DataPlaneStreamHooks {
  /** Per-connection serve deps (node identity + the pinned orchestrator key). */
  resolveDeps: () => Promise<DataPlaneServeDeps>;
  /** Send one outbound STREAM_DATA payload back to the orchestrator. */
  sendData: (data: Buffer) => void | Promise<void>;
  /** Send STREAM_CLOSE once, when the session ends (success or failure). */
  sendClose: (reason: string) => void | Promise<void>;
  /** Handshake/transport failure. Request-level errors are returned in-band by
   *  serveDataConnection (as an error response), so they do NOT surface here. */
  onError?: (error: Error) => void;
  /** Runs once after teardown; release per-stream bookkeeping here. */
  onDone?: () => void;
}

export function startDataPlaneStream(hooks: DataPlaneStreamHooks): DataPlaneStream {
  const inbox: Buffer[] = [];
  const waiters: Array<{ resolve: (b: Buffer) => void; reject: (e: Error) => void }> = [];
  let failure: Error | null = null;
  let closed = false;

  const closeOnce = (reason: string): void => {
    if (closed) return;
    closed = true;
    void Promise.resolve(hooks.sendClose(reason)).catch(() => undefined);
  };

  const transport: MessageTransport = {
    recv() {
      const buffered = inbox.shift();
      if (buffered) return Promise.resolve(buffered);
      if (failure) return Promise.reject(failure);
      return new Promise<Buffer>((resolve, reject) => waiters.push({ resolve, reject }));
    },
    send(data: Buffer) {
      return hooks.sendData(data);
    },
    close() {
      // serveDataConnection closes after sending the response; map it to STREAM_CLOSE.
      closeOnce("data-plane complete");
    },
  };

  void (async () => {
    try {
      const deps = await hooks.resolveDeps();
      await serveDataConnection(transport, deps);
    } catch (error) {
      hooks.onError?.(error instanceof Error ? error : new Error(String(error)));
    } finally {
      closeOnce("data-plane closed");
      hooks.onDone?.();
    }
  })();

  return {
    push(data: Buffer) {
      const waiter = waiters.shift();
      if (waiter) waiter.resolve(data);
      else inbox.push(data);
    },
    fail(reason: Error) {
      // The peer/tunnel is already gone, so suppress the STREAM_CLOSE echo-back.
      closed = true;
      failure = reason;
      while (waiters.length) waiters.shift()!.reject(reason);
    },
  };
}
