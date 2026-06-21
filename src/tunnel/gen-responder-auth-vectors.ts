// Generates deterministic responder-auth vectors so consensus-client can verify
// it accepts/rejects exactly what the node produces (byte-for-byte). Fixed
// identity keys, nonces, and clock — no randomness — so the output is stable.
//
//   bun run gen:responder-auth-vectors
//
// Re-run and commit the JSON whenever the responder-auth wire format changes.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createChallenge, signChallenge, type ResponderProof } from "./responder-auth";
import type { NodeIdentity } from "../crypto/identity";

const ED25519_PKCS8_PREFIX = "302e020100300506032b657004220420";

function fixedIdentity(seedByte: number): NodeIdentity {
  const seed = Buffer.alloc(32, seedByte);
  const pkcs8 = Buffer.concat([Buffer.from(ED25519_PKCS8_PREFIX, "hex"), seed]);
  const privateKey = crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString(),
  };
}

const NODE_ID = "node-resp";
const ISSUE_AT = 1_700_000_000;
const legit = fixedIdentity(7);
const impostor = fixedIdentity(9);
const clientNonce = Buffer.alloc(32, 1);
const nodeNonce = Buffer.alloc(32, 2);
const binding = Buffer.alloc(32, 3);
const otherNonce = Buffer.alloc(32, 5);

// Base case: a challenge with no channel binding and its valid proof.
const challenge = createChallenge({ nodeId: NODE_ID, now: ISSUE_AT, clientNonce });
const proof = signChallenge({ challenge, identity: legit, nodeId: NODE_ID, now: ISSUE_AT, nodeNonce });

// Channel-bound variant (forward-compat with the Step 10 encrypted channel).
const challengeBound = createChallenge({ nodeId: NODE_ID, now: ISSUE_AT, clientNonce, channelBinding: binding });
const proofBound = signChallenge({ challenge: challengeBound, identity: legit, nodeId: NODE_ID, now: ISSUE_AT, nodeNonce });

// Proof signed by the wrong identity key.
const proofWrongKey = signChallenge({ challenge, identity: impostor, nodeId: NODE_ID, now: ISSUE_AT, nodeNonce });

// Tamper one base64 char of a valid signature.
const tampered: ResponderProof = {
  ...proof,
  signature: (proof.signature[0] === "A" ? "B" : "A") + proof.signature.slice(1),
};

// A challenge that does not match the proof's echoed client_nonce.
const challengeOtherNonce = createChallenge({ nodeId: NODE_ID, now: ISSUE_AT, clientNonce: otherNonce });

// A future-dated and an old proof for the time-window checks.
const proofFuture = signChallenge({ challenge, identity: legit, nodeId: NODE_ID, now: ISSUE_AT + 100, nodeNonce });

interface Vector {
  name: string;
  challenge: unknown;
  proof: unknown;
  verify: { expectedNodeId?: string; now: number };
  expect: { ok: boolean; error?: string };
}

const vectors: Vector[] = [
  { name: "valid", challenge, proof, verify: { now: ISSUE_AT + 1 }, expect: { ok: true } },
  { name: "valid-channel-bound", challenge: challengeBound, proof: proofBound, verify: { now: ISSUE_AT + 1 }, expect: { ok: true } },
  { name: "wrong-key", challenge, proof: proofWrongKey, verify: { now: ISSUE_AT + 1 }, expect: { ok: false, error: "signature" } },
  { name: "tampered", challenge, proof: tampered, verify: { now: ISSUE_AT + 1 }, expect: { ok: false, error: "signature" } },
  { name: "client-nonce-mismatch", challenge: challengeOtherNonce, proof, verify: { now: ISSUE_AT + 1 }, expect: { ok: false, error: "client_nonce" } },
  { name: "channel-binding-mismatch", challenge, proof: proofBound, verify: { now: ISSUE_AT + 1 }, expect: { ok: false, error: "channel_binding" } },
  { name: "expired", challenge, proof, verify: { now: ISSUE_AT + 100 }, expect: { ok: false, error: "expired" } },
  { name: "future", challenge, proof: proofFuture, verify: { now: ISSUE_AT + 1 }, expect: { ok: false, error: "future" } },
  { name: "node-id-mismatch", challenge, proof, verify: { expectedNodeId: "ghost", now: ISSUE_AT + 1 }, expect: { ok: false, error: "node_id" } },
];

const out = {
  node_id: NODE_ID,
  node_public_key_pem: legit.publicKeyPem,
  vectors,
};

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(here, "test-vectors");
fs.mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, "responder-auth.vectors.json");
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n", "utf8");
console.log(`wrote ${vectors.length} responder-auth vectors -> ${path.relative(process.cwd(), outPath)}`);
