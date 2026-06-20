// Loads the orchestrator's ticket-verification key that was pinned into node
// state at registration (registration/join.ts persists it into config). The
// verifier (./verifier.ts) takes a KeyObject; in production this is where that
// key comes from — the pinned JWK, never a key fetched at request time.

import crypto, { type KeyObject } from "node:crypto";
import { loadConfig } from "../node/state";
import type { OrchestratorPublicJwk } from "../types";

export interface PinnedOrchestratorKey {
  key: KeyObject;
  kid: string | null;
}

/** Import an OKP/Ed25519 public JWK into a KeyObject for ticket verification. */
export function importOrchestratorJwk(jwk: OrchestratorPublicJwk): KeyObject {
  // node:crypto's JWK input type isn't exported in this runtime's types.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const key = crypto.createPublicKey({ key: jwk as any, format: "jwk" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("orchestrator pubkey: expected an Ed25519 (OKP) key");
  }
  return key;
}

/** The pinned orchestrator key from node config, or null if none was stored
 *  (older server, FREE_MODE dev, or not yet registered). */
export async function loadPinnedOrchestratorKey(): Promise<PinnedOrchestratorKey | null> {
  const config = await loadConfig();
  const jwk = config.orchestrator_pubkey;
  if (!jwk) return null;
  return { key: importOrchestratorJwk(jwk), kid: jwk.kid ?? null };
}
