import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  acceptDataInit,
  channelBinding,
  createDataInit,
  deriveClientDataSession,
  type DataAcceptMessage,
} from "../tunnel/data-handshake";
import { encryptFrame, decryptFrame } from "../crypto/secure-channel";
import type { NodeIdentity } from "../crypto/identity";

function newIdentity(): NodeIdentity {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

const NODE_ID = "node-x";
const identity = newIdentity();
let checks = 0;

// 0) Shared channel-binding vectors: consensus-client must compute the exact
// bytes the node binds the session to and signs in its proof — byte-for-byte.
// Pairs with responder-auth.vectors.json (which pins a proof over such a binding).
{
  const here = path.dirname(fileURLToPath(import.meta.url));
  const fixture = JSON.parse(
    fs.readFileSync(path.join(here, "../tunnel/test-vectors/data-handshake.vectors.json"), "utf8"),
  ) as { vectors: Array<{ name: string; input: Record<string, string>; channel_binding: string }> };

  const seen = new Set<string>();
  for (const v of fixture.vectors) {
    const binding = channelBinding({
      nodeId: v.input.node_id,
      clientPublicKey: v.input.client_public_key,
      clientNonce: v.input.client_nonce,
      nodePublicKey: v.input.node_public_key,
      nodeNonce: v.input.node_nonce,
    }).toString("base64");
    assert.equal(binding, v.channel_binding, `vector ${v.name} channel binding must match`);
    seen.add(binding);
    checks++;
  }
  // Distinct inputs must yield distinct bindings — proves every field feeds the
  // hash (a constant return would pass the equality check above but fail here).
  assert.equal(seen.size, fixture.vectors.length, "each vector's inputs produce a distinct binding");
  checks++;
}

// 1) Happy path: both sides derive the same session and the proof verifies
// against the pinned key.
{
  const client = await createDataInit({ nodeId: NODE_ID });
  const node = await acceptDataInit({ init: client.message, identity, nodeId: NODE_ID });
  const clientSession = await deriveClientDataSession({
    client,
    accept: node.message,
    expectedNodeId: NODE_ID,
    expectedNodePublicKeyPem: identity.publicKeyPem,
  });

  assert.equal(clientSession.sessionId, node.session.sessionId, "both sides agree on the session id");

  // The derived keys actually work, both directions.
  const aad = Buffer.alloc(0);
  const c2s = encryptFrame(clientSession.sendKey, 1, 0, Buffer.from("ping"), aad);
  assert.equal(decryptFrame(node.session.receiveKey, c2s, aad).toString(), "ping", "client -> node frame");
  const s2c = encryptFrame(node.session.sendKey, 1, 0, Buffer.from("pong"), aad);
  assert.equal(decryptFrame(clientSession.receiveKey, s2c, aad).toString(), "pong", "node -> client frame");
  checks += 3;
}

// 2) Wrong pinned key: a valid handshake fails if the client expects another key.
{
  const client = await createDataInit({ nodeId: NODE_ID });
  const node = await acceptDataInit({ init: client.message, identity, nodeId: NODE_ID });
  const other = newIdentity();
  await assert.rejects(
    () =>
      deriveClientDataSession({
        client,
        accept: node.message,
        expectedNodeId: NODE_ID,
        expectedNodePublicKeyPem: other.publicKeyPem,
      }),
    /signature/,
    "proof must not verify against a different identity key",
  );
  checks++;
}

// 3) A node refuses to accept an init aimed at a different node_id.
{
  const client = await createDataInit({ nodeId: NODE_ID });
  await assert.rejects(
    () => acceptDataInit({ init: client.message, identity, nodeId: "someone-else" }),
    /different node/,
  );
  checks++;
}

// 4) Relay/MITM swaps the node's ephemeral key: the transcript no longer matches
// the signed channel_binding, so the client rejects it.
{
  const client = await createDataInit({ nodeId: NODE_ID });
  const node = await acceptDataInit({ init: client.message, identity, nodeId: NODE_ID });
  const node2 = await acceptDataInit({ init: client.message, identity, nodeId: NODE_ID });
  const spliced: DataAcceptMessage = { ...node.message, node_public_key: node2.message.node_public_key };
  await assert.rejects(
    () =>
      deriveClientDataSession({
        client,
        accept: spliced,
        expectedNodeId: NODE_ID,
        expectedNodePublicKeyPem: identity.publicKeyPem,
      }),
    /channel_binding/,
    "swapping the node ephemeral key breaks the channel binding",
  );
  checks++;
}

// 5) Wrong expected node_id: the proof's node_id no longer matches.
{
  const client = await createDataInit({ nodeId: NODE_ID });
  const node = await acceptDataInit({ init: client.message, identity, nodeId: NODE_ID });
  await assert.rejects(
    () =>
      deriveClientDataSession({
        client,
        accept: node.message,
        expectedNodeId: "ghost",
        expectedNodePublicKeyPem: identity.publicKeyPem,
      }),
    /node_id/,
  );
  checks++;
}

// 6) Tampered session_id: proof still verifies, but the derived session disagrees.
{
  const client = await createDataInit({ nodeId: NODE_ID });
  const node = await acceptDataInit({ init: client.message, identity, nodeId: NODE_ID });
  const tampered: DataAcceptMessage = { ...node.message, session_id: "0".repeat(32) };
  await assert.rejects(
    () =>
      deriveClientDataSession({
        client,
        accept: tampered,
        expectedNodeId: NODE_ID,
        expectedNodePublicKeyPem: identity.publicKeyPem,
      }),
    /session id/,
  );
  checks++;
}

console.log(
  `data-handshake.test.ts: ${checks} checks passed — encrypted client<->node session with node-authenticated, channel-bound identity`,
);
