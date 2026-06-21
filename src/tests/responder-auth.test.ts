import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  createChallenge,
  signChallenge,
  verifyProof,
  type ResponderChallenge,
  type ResponderProof,
} from "../tunnel/responder-auth";
import type { NodeIdentity } from "../crypto/identity";

interface Vector {
  name: string;
  challenge: ResponderChallenge;
  proof: ResponderProof;
  verify: { expectedNodeId?: string; now: number };
  expect: { ok: boolean; error?: string };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  fs.readFileSync(path.join(here, "../tunnel/test-vectors/responder-auth.vectors.json"), "utf8"),
) as { node_id: string; node_public_key_pem: string; vectors: Vector[] };

function newIdentity(): NodeIdentity {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

let checks = 0;

// 1) Shared vectors: a client (and the consensus-client mirror) must accept or
// reject exactly what the node signs — byte-for-byte.
for (const v of fixture.vectors) {
  const opts = {
    proof: v.proof,
    challenge: v.challenge,
    expectedNodeId: v.verify.expectedNodeId ?? fixture.node_id,
    expectedNodePublicKeyPem: fixture.node_public_key_pem,
    now: v.verify.now,
  };
  if (v.expect.ok) {
    assert.doesNotThrow(() => verifyProof(opts), `vector ${v.name} should verify`);
  } else {
    assert.throws(() => verifyProof(opts), new RegExp(v.expect.error ?? "."), `vector ${v.name} should fail`);
  }
  checks++;
}

// 2) Live round-trip with random nonces + real clock (the production path).
const id = newIdentity();
const challenge = createChallenge({ nodeId: "node-live" });
const proof = signChallenge({ challenge, identity: id, nodeId: "node-live" });
const verified = verifyProof({
  proof,
  challenge,
  expectedNodeId: "node-live",
  expectedNodePublicKeyPem: id.publicKeyPem,
});
assert.equal(verified.node_id, "node-live");
assert.equal(verified.client_nonce, challenge.client_nonce, "proof echoes the challenge nonce");
assert.notEqual(proof.node_nonce, proof.client_nonce, "node contributes its own nonce");
checks += 3;

// 3) Channel binding round-trips and is enforced.
const cb = crypto.randomBytes(32);
const boundNonce = crypto.randomBytes(32);
const boundChallenge = createChallenge({ nodeId: "node-live", clientNonce: boundNonce, channelBinding: cb });
const boundProof = signChallenge({ challenge: boundChallenge, identity: id, nodeId: "node-live" });
assert.doesNotThrow(() =>
  verifyProof({
    proof: boundProof,
    challenge: boundChallenge,
    expectedNodeId: "node-live",
    expectedNodePublicKeyPem: id.publicKeyPem,
  }),
);
// Same challenge nonce but no binding: a client that never asked for a binding
// must reject a proof that carries one (isolates the channel_binding check).
const unboundSameNonce = createChallenge({ nodeId: "node-live", clientNonce: boundNonce });
assert.throws(
  () =>
    verifyProof({
      proof: boundProof,
      challenge: unboundSameNonce,
      expectedNodeId: "node-live",
      expectedNodePublicKeyPem: id.publicKeyPem,
    }),
  /channel_binding/,
);
checks += 2;

// 4) A node refuses to sign a challenge aimed at a different node.
assert.throws(() => signChallenge({ challenge, identity: id, nodeId: "someone-else" }), /different node/);
checks++;

// 5) The identity key is the trust anchor: a valid proof fails against another key.
const other = newIdentity();
assert.throws(
  () =>
    verifyProof({
      proof,
      challenge,
      expectedNodeId: "node-live",
      expectedNodePublicKeyPem: other.publicKeyPem,
    }),
  /signature/,
);
checks++;

console.log(
  `responder-auth.test.ts: ${checks} checks passed — node proves identity, client verifies against the pinned key`,
);
