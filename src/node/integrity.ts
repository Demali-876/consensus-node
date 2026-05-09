import crypto from "node:crypto";
import { canonicalJson } from "../crypto/canonical-json";
import { loadOrCreateIdentity, signUtf8 } from "../crypto/identity";
import { releaseManifest } from "./manifest";
import type { IntegrityPayload } from "../types";

export async function integrityPayload(): Promise<IntegrityPayload> {
  const identity = await loadOrCreateIdentity();
  const manifest = releaseManifest();
  const unsigned = {
    product: "consensus-node" as const,
    version: manifest.version,
    runtime: "bun" as const,
    platform: manifest.platform,
    node_public_key_pem: identity.publicKeyPem,
    manifest,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: crypto.randomBytes(16).toString("hex")
  };

  return {
    ...unsigned,
    signature: signUtf8(identity.privateKeyPem, canonicalJson(unsigned))
  };
}
