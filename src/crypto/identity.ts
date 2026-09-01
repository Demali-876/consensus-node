import crypto from "node:crypto";
import fs from "node:fs/promises";
import { ensureState, exists } from "../node/state";
import { readSecretFile, writeSecretFile, SLOT_NODE_KEY } from "../node/secret-store";

export interface NodeIdentity {
  privateKeyPem: string;
  publicKeyPem: string;
}

export async function loadOrCreateIdentity(): Promise<NodeIdentity> {
  const p = await ensureState();
  if ((await exists(p.privateKeyPem)) && (await exists(p.publicKeyPem))) {
    // readSecretFile returns null ONLY when the file is genuinely absent. A
    // decryption failure, an unreadable file, or a damaged data key all throw
    // rather than falling through to key generation. That is deliberate: minting a
    // fresh identity here would overwrite the registered private key and silently
    // orphan the node on the orchestrator, which is far worse than refusing to
    // start.
    const privateKeyPem = await readSecretFile(SLOT_NODE_KEY, p.privateKeyPem);
    if (privateKeyPem) {
      return {
        privateKeyPem,
        publicKeyPem: await fs.readFile(p.publicKeyPem, "utf8")
      };
    }
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  await writeSecretFile(SLOT_NODE_KEY, p.privateKeyPem, privateKey);
  await fs.writeFile(p.publicKeyPem, publicKey);

  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

export function signUtf8(privateKeyPem: string, payload: string): string {
  return signBytes(privateKeyPem, Buffer.from(payload, "utf8"));
}

export function signBytes(privateKeyPem: string, payload: Buffer): string {
  return crypto.sign(null, payload, privateKeyPem).toString("base64");
}

export function verifyUtf8(publicKeyPem: string, payload: string, signatureBase64: string): boolean {
  return crypto.verify(
    null,
    Buffer.from(payload, "utf8"),
    publicKeyPem,
    Buffer.from(signatureBase64, "base64")
  );
}
