// Data-plane handshake: a client connects directly to a node and establishes an
// encrypted session whose peer identity is proven by the node. This is the
// inverse of tunnel/handshake.ts (node -> server): here the client is the
// initiator and the node is the authenticated responder.
//
// It composes two existing pieces:
//   - crypto/secure-channel.ts ECDH session (ChaCha20-Poly1305 keys over HKDF),
//   - tunnel/responder-auth.ts identity proof (node signs with its Ed25519 key).
//
// The glue is the *transcript*: a hash over both ephemeral public keys and both
// nonces. It seeds the session HKDF AND is the responder-auth channel_binding
// the node signs. A man-in-the-middle that swaps the node's ephemeral key changes
// the transcript, so the client's recomputed binding no longer matches the signed
// proof — closing the relay seam that client_nonce alone cannot. The node's key
// is verified against the orchestrator-pinned key (Step 8), never a self-report.
//
// The init is unauthenticated by design — the client proves authorization later
// with a routing ticket (Step 10b). The route should rate-limit to bound the
// per-init ECDH + signature cost.

import crypto from "node:crypto";
import { canonicalJson } from "../crypto/canonical-json";
import {
  deriveSecureSession,
  generateHandshakeKeyPair,
  randomHandshakeNonce,
  type HandshakeKeyPair,
  type SecureSession,
} from "../crypto/secure-channel";
import { createChallenge, signChallenge, verifyProof, type ResponderProof } from "./responder-auth";
import type { NodeIdentity } from "../crypto/identity";

export const DATA_HANDSHAKE_PROTOCOL = "consensus-data-plane";
export const DATA_HANDSHAKE_VERSION = 1;

export const DATA_HANDSHAKE_TYPE = {
  INIT: "data_init",
  ACCEPT: "data_accept",
} as const;

export interface DataInitMessage {
  type: typeof DATA_HANDSHAKE_TYPE.INIT;
  protocol: typeof DATA_HANDSHAKE_PROTOCOL;
  version: typeof DATA_HANDSHAKE_VERSION;
  node_id: string;
  client_public_key: string; // base64 raw ECDH public key
  client_nonce: string; // base64
  timestamp: number;
}

export interface DataAcceptMessage {
  type: typeof DATA_HANDSHAKE_TYPE.ACCEPT;
  protocol: typeof DATA_HANDSHAKE_PROTOCOL;
  version: typeof DATA_HANDSHAKE_VERSION;
  node_public_key: string; // base64 raw ECDH public key
  session_id: string;
  proof: ResponderProof; // carries node_nonce + channel_binding, signed by the node
}

export interface ClientDataHandshake {
  keyPair: HandshakeKeyPair;
  clientNonce: Buffer;
  message: DataInitMessage;
}

export interface NodeDataHandshake {
  message: DataAcceptMessage;
  session: SecureSession;
}

/** Client: build the init (ephemeral key + nonce) for the node it wants to reach. */
export async function createDataInit(input: {
  nodeId: string;
  now?: number;
  clientNonce?: Buffer; // injectable for tests; random otherwise
}): Promise<ClientDataHandshake> {
  const keyPair = await generateHandshakeKeyPair();
  const clientNonce = input.clientNonce ?? randomHandshakeNonce();
  const message: DataInitMessage = {
    type: DATA_HANDSHAKE_TYPE.INIT,
    protocol: DATA_HANDSHAKE_PROTOCOL,
    version: DATA_HANDSHAKE_VERSION,
    node_id: input.nodeId,
    client_public_key: keyPair.publicKeyRaw.toString("base64"),
    client_nonce: clientNonce.toString("base64"),
    timestamp: input.now ?? nowSeconds(),
  };
  return { keyPair, clientNonce, message };
}

/** Node: accept the init — derive the session and sign an identity proof bound to
 *  this exact channel. Rejects an init aimed at a different node_id. */
export async function acceptDataInit(input: {
  init: DataInitMessage;
  identity: NodeIdentity;
  nodeId: string;
  now?: number;
}): Promise<NodeDataHandshake> {
  assertDataInit(input.init);
  if (input.init.node_id !== input.nodeId) {
    throw new Error("data-handshake: init targets a different node");
  }

  const keyPair = await generateHandshakeKeyPair();
  const nodeNonce = randomHandshakeNonce();
  const nodePublicKey = keyPair.publicKeyRaw.toString("base64");
  const transcript = channelBinding({
    nodeId: input.nodeId,
    clientPublicKey: input.init.client_public_key,
    clientNonce: input.init.client_nonce,
    nodePublicKey,
    nodeNonce: nodeNonce.toString("base64"),
  });

  const session = await deriveSecureSession({
    role: "server",
    privateKey: keyPair.privateKey,
    peerPublicKeyRaw: decodeBase64(input.init.client_public_key, "client_public_key"),
    clientNonce: decodeBase64(input.init.client_nonce, "client_nonce"),
    serverNonce: nodeNonce,
    transcriptHash: transcript,
  });

  const now = input.now ?? nowSeconds();
  const proof = signChallenge({
    challenge: createChallenge({
      nodeId: input.nodeId,
      now,
      clientNonce: decodeBase64(input.init.client_nonce, "client_nonce"),
      channelBinding: transcript,
    }),
    identity: input.identity,
    nodeId: input.nodeId,
    now,
    nodeNonce,
  });

  const message: DataAcceptMessage = {
    type: DATA_HANDSHAKE_TYPE.ACCEPT,
    protocol: DATA_HANDSHAKE_PROTOCOL,
    version: DATA_HANDSHAKE_VERSION,
    node_public_key: nodePublicKey,
    session_id: session.sessionId,
    proof,
  };
  return { message, session };
}

/** Client: verify the node's proof against the pinned key, confirm the channel
 *  binding, and derive the matching session. Throws on any mismatch. */
export async function deriveClientDataSession(input: {
  client: ClientDataHandshake;
  accept: DataAcceptMessage;
  expectedNodeId: string;
  expectedNodePublicKeyPem: string;
  now?: number;
}): Promise<SecureSession> {
  assertDataAccept(input.accept);

  const nodeNonce = input.accept.proof.node_nonce;
  const transcript = channelBinding({
    nodeId: input.expectedNodeId,
    clientPublicKey: input.client.message.client_public_key,
    clientNonce: input.client.message.client_nonce,
    nodePublicKey: input.accept.node_public_key,
    nodeNonce,
  });

  // Identity proof must verify against the pinned key and bind THIS channel
  // (transcript = channel_binding). A swapped node key changes the transcript.
  verifyProof({
    proof: input.accept.proof,
    challenge: createChallenge({
      nodeId: input.expectedNodeId,
      now: input.accept.proof.timestamp,
      clientNonce: input.client.clientNonce,
      channelBinding: transcript,
    }),
    expectedNodeId: input.expectedNodeId,
    expectedNodePublicKeyPem: input.expectedNodePublicKeyPem,
    now: input.now,
  });

  const session = await deriveSecureSession({
    role: "client",
    privateKey: input.client.keyPair.privateKey,
    peerPublicKeyRaw: decodeBase64(input.accept.node_public_key, "node_public_key"),
    clientNonce: input.client.clientNonce,
    serverNonce: decodeBase64(nodeNonce, "node_nonce"),
    transcriptHash: transcript,
  });

  if (session.sessionId !== input.accept.session_id) {
    throw new Error("data-handshake: session id mismatch");
  }
  return session;
}

function channelBinding(input: {
  nodeId: string;
  clientPublicKey: string;
  clientNonce: string;
  nodePublicKey: string;
  nodeNonce: string;
}): Buffer {
  return crypto
    .createHash("sha256")
    .update(
      canonicalJson({
        protocol: DATA_HANDSHAKE_PROTOCOL,
        version: DATA_HANDSHAKE_VERSION,
        node_id: input.nodeId,
        client_public_key: input.clientPublicKey,
        client_nonce: input.clientNonce,
        node_public_key: input.nodePublicKey,
        node_nonce: input.nodeNonce,
      }),
    )
    .digest();
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function assertDataInit(value: unknown): asserts value is DataInitMessage {
  const message = assertBase(value, DATA_HANDSHAKE_TYPE.INIT);
  if (typeof message.node_id !== "string" || message.node_id.length === 0) {
    throw new TypeError("data-handshake: node_id must be a non-empty string");
  }
  decodeBase64(message.client_public_key, "client_public_key");
  decodeBase64(message.client_nonce, "client_nonce");
  if (typeof message.timestamp !== "number" || !Number.isFinite(message.timestamp)) {
    throw new TypeError("data-handshake: timestamp must be a finite number");
  }
}

function assertDataAccept(value: unknown): asserts value is DataAcceptMessage {
  const message = assertBase(value, DATA_HANDSHAKE_TYPE.ACCEPT);
  decodeBase64(message.node_public_key, "node_public_key");
  if (typeof message.session_id !== "string" || message.session_id.length === 0) {
    throw new TypeError("data-handshake: session_id must be a non-empty string");
  }
  if (!message.proof || typeof message.proof !== "object") {
    throw new TypeError("data-handshake: proof must be an object");
  }
}

function assertBase(value: unknown, type: string): Record<string, unknown> {
  if (!value || typeof value !== "object") throw new TypeError("data-handshake: message must be an object");
  const message = value as Record<string, unknown>;
  if (message.type !== type) throw new TypeError(`data-handshake: expected type ${type}`);
  if (message.protocol !== DATA_HANDSHAKE_PROTOCOL) {
    throw new TypeError(`data-handshake: unsupported protocol ${String(message.protocol)}`);
  }
  if (message.version !== DATA_HANDSHAKE_VERSION) {
    throw new TypeError(`data-handshake: unsupported version ${String(message.version)}`);
  }
  return message;
}

function decodeBase64(value: unknown, field: string): Buffer {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`data-handshake: ${field} must be a non-empty string`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0) throw new TypeError(`data-handshake: ${field} is empty`);
  return decoded;
}
