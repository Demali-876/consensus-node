import assert from "node:assert/strict";
import crypto, { type KeyObject } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { loadConfig, saveConfig } from "../node/state";
import { issueTicket } from "../tickets/ticket";
import { verifyRoutingTicket } from "../tickets/verifier";
import { JtiReplayCache } from "../tickets/replay";
import { loadPinnedOrchestratorKey, resolvePinnedPubkey } from "../tickets/orchestrator-key";
import type { OrchestratorPublicJwk } from "../types";

// Isolate on-disk state so this test never touches a real ~/.consensus/node.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "consensus-pin-"));
process.env.CONSENSUS_STATE_DIR = tmp;

// Mirror consensus/server/features/tickets/keys.ts so the JWK we persist is
// byte-for-byte what the orchestrator embeds in the join response.
function jwkThumbprint(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return crypto.createHash("sha256").update(canonical).digest("base64url");
}
function publicJwk(publicKey: KeyObject, kid: string): OrchestratorPublicJwk {
  const jwk = publicKey.export({ format: "jwk" }) as unknown as OrchestratorPublicJwk;
  return { ...jwk, use: "sig", alg: "EdDSA", kid };
}

let checks = 0;

// 1) No pin stored yet → loader returns null (older server / FREE_MODE / pre-join).
assert.equal(await loadPinnedOrchestratorKey(), null, "absent pin loads as null");
checks++;

// Stand up an orchestrator identity and the join-response pin block.
const orchestrator = crypto.generateKeyPairSync("ed25519");
const kid = jwkThumbprint(orchestrator.publicKey);
const pinJwk = publicJwk(orchestrator.publicKey, kid);

// 2) Simulate what registerNode() persists from a join response.
await saveConfig({
  port: 9090,
  node_id: "node-pin",
  domain: "node-pin.consensus.canister.software",
  region: "us-east",
  registered_at: new Date().toISOString(),
  benchmark_score: 88,
  orchestrator_pubkey: pinJwk,
});

// 3) Reload the pinned key and verify a real ticket against it.
const pinned = await loadPinnedOrchestratorKey();
assert.ok(pinned, "pin reloads after registration");
assert.equal(pinned.kid, kid, "pinned kid survives the round-trip");
assert.equal(pinned.key.asymmetricKeyType, "ed25519", "pinned key imports as Ed25519");
checks += 3;

const token = issueTicket(
  { nodeId: "node-pin", dedupeKey: "ddk-1", jti: "jti-pin", now: 1000 },
  orchestrator.privateKey,
  kid,
);
const { claims, kid: ticketKid } = verifyRoutingTicket(token, pinned.key, {
  expectedNodeId: "node-pin",
  now: 1010,
  replay: new JtiReplayCache(),
});
assert.equal(claims.sub, "ddk-1", "ticket subject matches the request binding");
assert.equal(ticketKid, kid, "ticket footer kid matches the pinned key");
checks += 2;

// 4) A ticket signed by a different key must NOT verify against the pinned key.
const impostor = crypto.generateKeyPairSync("ed25519");
const forged = issueTicket(
  { nodeId: "node-pin", dedupeKey: "ddk-1", jti: "jti-forged", now: 1000 },
  impostor.privateKey,
  kid,
);
assert.throws(
  () => verifyRoutingTicket(forged, pinned.key, { expectedNodeId: "node-pin", now: 1010 }),
  "ticket from a non-pinned key is rejected",
);
checks++;

// 5) Re-registration against a key-less response (older server / FREE_MODE) must
// NOT wipe the pinned trust anchor — the regression this guards against.
const before = await loadConfig();
await saveConfig({
  ...before,
  orchestrator_pubkey: resolvePinnedPubkey(before.orchestrator_pubkey, undefined),
});
const stillPinned = await loadPinnedOrchestratorKey();
assert.ok(stillPinned, "key-less re-registration preserves the pinned key");
assert.equal(stillPinned.kid, kid, "preserved pin keeps its kid");
checks += 2;

// 6) resolvePinnedPubkey decision table: only an explicit key rotates the pin.
const rotated = publicJwk(impostor.publicKey, "kid-2");
assert.equal(resolvePinnedPubkey(pinJwk, rotated), rotated, "explicit key rotates the pin");
assert.equal(resolvePinnedPubkey(pinJwk, null), pinJwk, "null response preserves existing");
assert.equal(resolvePinnedPubkey(pinJwk, undefined), pinJwk, "missing response preserves existing");
assert.equal(resolvePinnedPubkey(undefined, rotated), rotated, "first pin with no prior anchor");
assert.equal(resolvePinnedPubkey(null, null), null, "no key anywhere stays null");
checks += 5;

fs.rmSync(tmp, { recursive: true, force: true });

console.log(`pin.test.ts: ${checks} checks passed — pinned orchestrator key persists, reloads, and gates ticket verification`);
