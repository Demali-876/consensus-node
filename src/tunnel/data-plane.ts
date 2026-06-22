// Data-plane connection protocol: the end-to-end glue that lets a client connect
// directly to a node and get a request served. It composes the three primitives
// built in steps 10a–10c over a single ordered message channel:
//
//   1. client -> node : DataInit          (data-handshake)
//   2. node -> client : DataAccept        (encrypted session + signed identity)
//   3. client -> node : ProxyRequest      (encrypted: routing ticket + request)
//   4. node -> client : ProxyResponse     (encrypted: served response, or error)
//
// Steps 1–2 are the handshake JSON (ephemeral keys + a signed proof — safe in the
// clear, like a TLS handshake). Steps 3–4 are sealed frames under the derived
// session key. The node verifies the ticket against its pinned orchestrator key
// and the request binding before serving through the SSRF guard.
//
// The protocol is transport-agnostic (MessageTransport) so it runs over a real
// WebSocket (runtime/data-route.ts) or an in-memory pipe (tests). runDataRequest
// is the client reference consensus-client mirrors in Step 11.

import type { KeyObject } from "node:crypto";
import { openFrame, sealFrame, type SecureSession } from "../crypto/secure-channel";
import { FRAME_TYPE } from "./frames";
import {
  acceptDataInit,
  createDataInit,
  deriveClientDataSession,
  type DataAcceptMessage,
  type DataInitMessage,
} from "./data-handshake";
import { verifyRequestTicket } from "../tickets/request-ticket";
import type { JtiReplayCache } from "../tickets/replay";
import type { DedupeParams } from "../runtime/dedupe";
import { serveProxyRequest, type ProxyResult, type ProxyServeRequest } from "../runtime/proxy-serve";
import type { NodeIdentity } from "../crypto/identity";

export const DATA_PLANE_PATH = "/connect";

/** Ordered, message-framed bidirectional channel. One recv() returns one message. */
export interface MessageTransport {
  recv(): Promise<Buffer>;
  send(data: Buffer): void | Promise<void>;
  close(code?: number): void;
}

export interface ProxyRequestPayload {
  type: "proxy_request";
  token: string; // routing ticket (PASETO)
  target_url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string; // base64 when present
  body_encoding?: "base64";
}

export type ProxyResponsePayload =
  | {
      type: "proxy_response";
      status: number;
      status_text: string;
      headers: Record<string, string>;
      body: string; // base64
      body_encoding: "base64";
    }
  | { type: "error"; code: string; message: string };

export interface DataPlaneServeDeps {
  nodeId: string;
  identity: NodeIdentity;
  pinnedKey: KeyObject; // orchestrator key pinned at registration (Step 8)
  replay: JtiReplayCache;
  /** Injectable for tests; defaults to the SSRF-guarded serve (Step 10c). */
  serve?: (req: ProxyServeRequest) => Promise<ProxyResult>;
}

/** Node side: handshake, then verify + serve exactly one request, then close. */
export async function serveDataConnection(transport: MessageTransport, deps: DataPlaneServeDeps): Promise<void> {
  const init = decodeJson<DataInitMessage>(await transport.recv());
  const { message: accept, session } = await acceptDataInit({
    init,
    identity: deps.identity,
    nodeId: deps.nodeId,
  });
  await transport.send(encodeJson(accept));

  const requestFrame = await transport.recv();
  const response = await resolveProxyResponse(requestFrame, session, deps);
  await transport.send(sealFrame(session.sendKey, FRAME_TYPE.DATA, 0n, encodeJson(response)));
  transport.close(1000);
}

/** Client reference: handshake (verifying the node against its pinned key), send
 *  the ticketed request, return the node's response. */
export async function runDataRequest(
  transport: MessageTransport,
  params: {
    nodeId: string;
    expectedNodePublicKeyPem: string;
    token: string;
    request: { target_url: string; method?: string; headers?: Record<string, string>; body?: string | Buffer | null };
  },
): Promise<ProxyResponsePayload> {
  const client = await createDataInit({ nodeId: params.nodeId });
  await transport.send(encodeJson(client.message));

  const accept = decodeJson<DataAcceptMessage>(await transport.recv());
  const session = await deriveClientDataSession({
    client,
    accept,
    expectedNodeId: params.nodeId,
    expectedNodePublicKeyPem: params.expectedNodePublicKeyPem,
  });

  const body = normalizeBody(params.request.body);
  const payload: ProxyRequestPayload = {
    type: "proxy_request",
    token: params.token,
    target_url: params.request.target_url,
    method: params.request.method,
    headers: params.request.headers,
    body: body ? body.toString("base64") : undefined,
    body_encoding: body ? "base64" : undefined,
  };
  await transport.send(sealFrame(session.sendKey, FRAME_TYPE.DATA, 0n, encodeJson(payload)));

  const { frame, plaintext } = openFrame(session.receiveKey, await transport.recv());
  if (frame.type !== FRAME_TYPE.DATA) throw new Error("data-plane: unexpected response frame type");
  return decodeJson<ProxyResponsePayload>(plaintext);
}

async function resolveProxyResponse(
  requestFrame: Buffer,
  session: SecureSession,
  deps: DataPlaneServeDeps,
): Promise<ProxyResponsePayload> {
  let payload: ProxyRequestPayload;
  try {
    const { frame, plaintext } = openFrame(session.receiveKey, requestFrame);
    if (frame.type !== FRAME_TYPE.DATA) throw new Error("unexpected frame type");
    payload = decodeJson<ProxyRequestPayload>(plaintext);
    if (payload.type !== "proxy_request" || typeof payload.token !== "string" || typeof payload.target_url !== "string") {
      throw new Error("invalid proxy_request payload");
    }
  } catch (err) {
    return { type: "error", code: "bad_request", message: errorMessage(err) };
  }

  const body = decodeBody(payload.body, payload.body_encoding);
  const method = (payload.method ?? "GET").toUpperCase();
  const dedupeParams: DedupeParams = { target_url: payload.target_url, method, headers: payload.headers, body };

  try {
    verifyRequestTicket({
      token: payload.token,
      nodeId: deps.nodeId,
      publicKey: deps.pinnedKey,
      request: dedupeParams,
      replay: deps.replay,
    });
  } catch (err) {
    return { type: "error", code: "unauthorized", message: errorMessage(err) };
  }

  try {
    const serve = deps.serve ?? defaultServe;
    const result = await serve({ target_url: payload.target_url, method, headers: payload.headers, body });
    return {
      type: "proxy_response",
      status: result.status,
      status_text: result.statusText,
      headers: result.headers,
      body: result.body.toString("base64"),
      body_encoding: "base64",
    };
  } catch (err) {
    return { type: "error", code: "upstream_error", message: errorMessage(err) };
  }
}

const defaultServe = (req: ProxyServeRequest): Promise<ProxyResult> => serveProxyRequest(req);

function encodeJson(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function decodeJson<T>(buf: Buffer): T {
  return JSON.parse(buf.toString("utf8")) as T;
}

function normalizeBody(body: string | Buffer | null | undefined): Buffer | undefined {
  if (body == null) return undefined;
  return Buffer.isBuffer(body) ? body : Buffer.from(body);
}

function decodeBody(body: string | undefined, encoding: "base64" | undefined): Buffer | undefined {
  if (body == null) return undefined;
  return encoding === "base64" ? Buffer.from(body, "base64") : Buffer.from(body, "utf8");
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
