import assert from "node:assert/strict";
import crypto from "node:crypto";
import { loadOrCreateIdentity } from "../crypto/identity";
import {
  acceptClientHandshake,
  createClientHandshake,
  decodeHandshakeMessage,
  deriveClientSessionFromAccept,
  encodeHandshakeMessage,
  verifyClientHandshake,
} from "../tunnel/handshake";
import { TUNNEL_MODE } from "../tunnel/messages";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// Redirect state BEFORE creating an identity. Without this the test writes to the
// operator's real ~/.consensus/node and rewrites live node key material.
const stateRoot = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-handshake-"));
process.env.CONSENSUS_STATE_DIR = stateRoot;
process.env.CONSENSUS_NODE_SECRET_KEY = crypto.randomBytes(32).toString("base64");

const identity = await loadOrCreateIdentity();

const client = await createClientHandshake({
  mode: TUNNEL_MODE.EVAL,
  identity,
  candidateId: "candidate-test",
  releaseVersion: "0.1.0-test",
});

assert.equal(verifyClientHandshake(client.message), true);

const decoded = decodeHandshakeMessage(encodeHandshakeMessage(client.message));
assert.deepEqual(decoded, client.message);

const server = await acceptClientHandshake({ init: client.message });
const clientSession = await deriveClientSessionFromAccept({
  client,
  accept: server.message,
});

assert.equal(clientSession.sessionId, server.session.sessionId);
assert.deepEqual(clientSession.sendKey, server.session.receiveKey);
assert.deepEqual(clientSession.receiveKey, server.session.sendKey);

const serverIdentity = crypto.generateKeyPairSync("ed25519", {
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const signedServer = await acceptClientHandshake({
  init: client.message,
  serverSigningKeyPem: serverIdentity.privateKey,
});

const signedClientSession = await deriveClientSessionFromAccept({
  client,
  accept: signedServer.message,
  serverPublicKeyPem: serverIdentity.publicKey,
});
assert.equal(signedClientSession.sessionId, signedServer.session.sessionId);

const unsignedError = await deriveClientSessionFromAccept({
  client,
  accept: server.message,
  serverPublicKeyPem: serverIdentity.publicKey,
}).then(
  () => null,
  (error: unknown) => error,
);
assert.ok(unsignedError instanceof Error);
assert.match(unsignedError.message, /signature is required/);

console.log("handshake ok");

await fs.rm(stateRoot, { recursive: true, force: true });
