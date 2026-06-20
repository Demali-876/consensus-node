// Responder-auth: a node proves its identity to a client that connects to it
// directly on the data plane. The client learned the node's expected Ed25519
// identity key from the orchestrator (bound to node_id at registration); it
// sends a fresh challenge, the node signs it with its identity key, and the
// client verifies the signature against the *pinned* key before trusting the
// node with a routing ticket.
//
// This is the inverse of tunnel/handshake.ts (node -> server): here the node is
// the responder and the connecting client is the initiator. createChallenge()
// and verifyProof() are the cross-repo contract consensus-client mirrors
// (locked by test-vectors/responder-auth.vectors.json); signChallenge() is the
// node-only side. Kept dependency-light (node:crypto + canonical-json) so the
// client can copy the shared functions verbatim.
//
// Security: client_nonce makes a captured proof unusable against a *different*
// client (its fresh challenge won't match the echoed nonce). It does NOT by
// itself stop a man-in-the-middle that relays both messages on its own
// transport — for that, pass channel_binding bound to the encrypted channel
// (e.g. the ECDH transcript hash). The Step 10 endpoint sets it; TLS already
// authenticates the node domain, and this layer pins the node's protocol
// identity independent of CA trust.

import crypto from "node:crypto";
import { canonicalJson } from "../crypto/canonical-json";
import type { NodeIdentity } from "../crypto/identity";

export const RESPONDER_AUTH_PROTOCOL = "consensus-node-responder-auth";
export const RESPONDER_AUTH_VERSION = 1;

const NONCE_BYTES = 32;
const DEFAULT_CLOCK_TOLERANCE_SEC = 5;
const DEFAULT_MAX_AGE_SEC = 30;

export interface ResponderChallenge {
  protocol: typeof RESPONDER_AUTH_PROTOCOL;
  version: typeof RESPONDER_AUTH_VERSION;
  node_id: string;
  client_nonce: string; // base64, client-generated freshness
  timestamp: number; // client unix seconds
  channel_binding?: string; // base64, optional (e.g. an ECDH transcript hash)
}

export interface ResponderProof {
  protocol: typeof RESPONDER_AUTH_PROTOCOL;
  version: typeof RESPONDER_AUTH_VERSION;
  node_id: string;
  client_nonce: string; // echoed from the challenge
  node_nonce: string; // base64, node-generated
  timestamp: number; // node unix seconds
  channel_binding?: string; // echoed from the challenge when present
  signature: string; // Ed25519 over canonicalJson(proof without signature)
}

/** Client side: build a fresh challenge for the node it expects to reach. */
export function createChallenge(input: {
  nodeId: string;
  now?: number;
  clientNonce?: Buffer; // injectable for tests/vectors; random otherwise
  channelBinding?: Buffer;
}): ResponderChallenge {
  const nonce = input.clientNonce ?? crypto.randomBytes(NONCE_BYTES);
  return omitUndefined({
    protocol: RESPONDER_AUTH_PROTOCOL,
    version: RESPONDER_AUTH_VERSION,
    node_id: input.nodeId,
    client_nonce: nonce.toString("base64"),
    timestamp: input.now ?? nowSeconds(),
    channel_binding: input.channelBinding?.toString("base64"),
  }) as ResponderChallenge;
}

/** Node side: prove identity by signing the client's challenge. Rejects a
 *  challenge that targets a different node_id (routing error). */
export function signChallenge(input: {
  challenge: ResponderChallenge;
  identity: NodeIdentity;
  nodeId: string;
  now?: number;
  nodeNonce?: Buffer; // injectable for tests/vectors; random otherwise
}): ResponderProof {
  assertChallenge(input.challenge);
  if (input.challenge.node_id !== input.nodeId) {
    throw new Error("responder-auth: challenge targets a different node");
  }
  const nodeNonce = input.nodeNonce ?? crypto.randomBytes(NONCE_BYTES);
  const unsigned = omitUndefined({
    protocol: RESPONDER_AUTH_PROTOCOL,
    version: RESPONDER_AUTH_VERSION,
    node_id: input.nodeId,
    client_nonce: input.challenge.client_nonce,
    node_nonce: nodeNonce.toString("base64"),
    timestamp: input.now ?? nowSeconds(),
    channel_binding: input.challenge.channel_binding,
  }) as Omit<ResponderProof, "signature">;
  const signature = crypto
    .sign(null, Buffer.from(signingPayload(unsigned), "utf8"), input.identity.privateKeyPem)
    .toString("base64");
  return { ...unsigned, signature };
}

export interface VerifyProofOptions {
  proof: ResponderProof;
  challenge: ResponderChallenge;
  expectedNodeId: string;
  /** The node's identity key as vouched for by the orchestrator — the trust
   *  anchor. The proof's signature is checked against THIS, never a self-report. */
  expectedNodePublicKeyPem: string;
  now?: number;
  clockToleranceSec?: number;
  maxAgeSec?: number;
}

/** Client side: verify the node's proof. Throws on any mismatch; returns the
 *  proof on success so the caller can use node_nonce (e.g. session binding). */
export function verifyProof(opts: VerifyProofOptions): ResponderProof {
  assertChallenge(opts.challenge);
  assertProof(opts.proof);
  const p = opts.proof;

  if (p.node_id !== opts.expectedNodeId) throw new Error("responder-auth: node_id mismatch");
  if (opts.challenge.node_id !== opts.expectedNodeId) {
    throw new Error("responder-auth: challenge node_id mismatch");
  }
  if (p.client_nonce !== opts.challenge.client_nonce) {
    throw new Error("responder-auth: client_nonce mismatch");
  }
  if ((p.channel_binding ?? null) !== (opts.challenge.channel_binding ?? null)) {
    throw new Error("responder-auth: channel_binding mismatch");
  }

  const now = opts.now ?? nowSeconds();
  const skew = opts.clockToleranceSec ?? DEFAULT_CLOCK_TOLERANCE_SEC;
  const maxAge = opts.maxAgeSec ?? DEFAULT_MAX_AGE_SEC;
  if (p.timestamp > now + skew) throw new Error("responder-auth: proof issued in the future");
  if (p.timestamp < now - maxAge - skew) throw new Error("responder-auth: proof expired");

  const ok = crypto.verify(
    null,
    Buffer.from(signingPayload(withoutSignature(p)), "utf8"),
    opts.expectedNodePublicKeyPem,
    Buffer.from(p.signature, "base64"),
  );
  if (!ok) throw new Error("responder-auth: signature verification failed");
  return p;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function signingPayload(value: object): string {
  return canonicalJson(withoutSignature(value));
}

function withoutSignature<T extends object>(value: T): Omit<T, "signature"> {
  const { signature: _signature, ...rest } = value as T & { signature?: string };
  return rest;
}

function omitUndefined<T extends Record<string, unknown>>(value: T): T {
  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (item !== undefined) output[key] = item;
  }
  return output as T;
}

function assertBase(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object") throw new TypeError("responder-auth: message must be an object");
  const message = value as Record<string, unknown>;
  if (message.protocol !== RESPONDER_AUTH_PROTOCOL) {
    throw new TypeError(`responder-auth: unsupported protocol ${String(message.protocol)}`);
  }
  if (message.version !== RESPONDER_AUTH_VERSION) {
    throw new TypeError(`responder-auth: unsupported version ${String(message.version)}`);
  }
  if (typeof message.node_id !== "string" || message.node_id.length === 0) {
    throw new TypeError("responder-auth: node_id must be a non-empty string");
  }
  if (typeof message.timestamp !== "number" || !Number.isFinite(message.timestamp)) {
    throw new TypeError("responder-auth: timestamp must be a finite number");
  }
  if (message.channel_binding !== undefined) decodeBase64(message.channel_binding, "channel_binding");
  return message;
}

function assertChallenge(value: unknown): asserts value is ResponderChallenge {
  const message = assertBase(value);
  decodeBase64(message.client_nonce, "client_nonce");
}

function assertProof(value: unknown): asserts value is ResponderProof {
  const message = assertBase(value);
  decodeBase64(message.client_nonce, "client_nonce");
  decodeBase64(message.node_nonce, "node_nonce");
  if (typeof message.signature !== "string" || message.signature.length === 0) {
    throw new TypeError("responder-auth: signature must be a non-empty string");
  }
}

function decodeBase64(value: unknown, field: string): Buffer {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`responder-auth: ${field} must be a non-empty string`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0) throw new TypeError(`responder-auth: ${field} is empty`);
  return decoded;
}
