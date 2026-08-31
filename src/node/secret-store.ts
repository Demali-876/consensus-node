// Encryption at rest for the node's secrets — the Ed25519 identity key and the
// join authorization.
//
// Envelope scheme: a single 32-byte data key (DEK) lives in the platform keystore,
// never in the state directory. Secret files hold chacha20-poly1305 ciphertext keyed
// by that DEK, with the file's logical slot name as AAD so ciphertext cannot be moved
// between slots (a join-auth blob dropped into node.key fails to open).
//
// WHAT THIS PROTECTS AGAINST — do not over-claim it:
//
//   * Covered: a copied state directory, and a backup scoped to it. That is the
//     realistic leak for this data, since ~/.consensus is what gets rsync'd,
//     archived, or handed to support.
//   * NOT covered: theft of the whole disk, or an attacker who already has the
//     node's uid on a running host.
//
// That ceiling is forced by the requirement to boot with no human present. If the
// node can decrypt unattended then the unlock secret is reachable on the same
// machine, so a full-disk attacker gets it too. This is NOT a shortcut we took:
// macOS's System keychain has the same property (it unlocks at boot from
// /var/db/SystemKey, on the same disk), so it would buy nothing here. Real
// at-rest protection means FileVault — which stops at a pre-boot unlock prompt and
// therefore cannot coexist with unattended boot.
//
// The one place that ceiling can be raised is Linux with a TPM, where the chip
// releases the key only on that hardware. The KeystoreAdapter interface below is
// where such an adapter drops in without touching any caller.
//
// WHY NOT THE macOS KEYCHAIN: the daemon runs as the operator with no login session
// (see launchd/com.consensus.node.plist.template), and the login keychain is only
// unlocked by a GUI login. The System keychain is readable pre-login but only by
// root. Using a keychain interactively and a file under the daemon would split the
// DEK across two stores and strand the node at boot, so there is exactly one store
// per platform.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { log } from "../log";

const DEK_BYTES = 32;
const NONCE_BYTES = 12;
const ENVELOPE_VERSION = 1;
const ALGORITHM = "chacha20-poly1305";

/** Slot names double as AAD, so they are part of the on-disk format: changing one
 *  makes existing ciphertext for that slot unopenable. */
export const SLOT_NODE_KEY = "node.key";
export const SLOT_JOIN_AUTH = "join-auth.json";

export interface SecretEnvelope {
  v: number;
  alg: string;
  nonce: string;
  ct: string;
}

/** A place the data key can live. Add a TPM-backed adapter here to close the
 *  Linux full-disk gap documented above. */
export interface KeystoreAdapter {
  readonly name: string;
  available(): Promise<boolean>;
  get(): Promise<Buffer | null>;
  set(key: Buffer): Promise<void>;
}

function isRoot(): boolean {
  return typeof process.getuid === "function" && process.getuid() === 0;
}

// --- Adapter: explicit key from the environment -----------------------------
// For tests, and for operators who inject the DEK from their own KMS/secret manager.
// Takes precedence over every other adapter when set.

const envAdapter: KeystoreAdapter = {
  name: "env",
  async available() {
    return Boolean(process.env.CONSENSUS_NODE_SECRET_KEY);
  },
  async get() {
    const raw = process.env.CONSENSUS_NODE_SECRET_KEY;
    if (!raw) return null;
    const key = Buffer.from(raw, "base64");
    if (key.length !== DEK_BYTES) {
      throw new Error(
        `CONSENSUS_NODE_SECRET_KEY must be ${DEK_BYTES} base64-encoded bytes, got ${key.length}`,
      );
    }
    return key;
  },
  async set() {
    // The operator owns this key; we never overwrite what they injected.
  },
};

// --- Adapter: 0600 key file outside the state directory ----------------------
// Deliberately NOT under CONSENSUS_STATE_DIR: keeping the DEK out of the directory
// it protects is the whole reason copying that directory yields nothing usable.
//
// Readable with no login session and no root, which is what makes pre-login boot
// work. CONSENSUS_NODE_SECRET_KEY_PATH overrides it for operators who want the key
// on removable media or a mounted secret.

export function keyFilePath(): string {
  const override = process.env.CONSENSUS_NODE_SECRET_KEY_PATH;
  if (override) return override;

  if (process.platform === "darwin") {
    return isRoot()
      ? "/Library/Application Support/consensus-node/secret.key"
      : path.join(os.homedir(), "Library", "Application Support", "consensus-node", "secret.key");
  }
  if (isRoot()) return "/etc/consensus-node/secret.key";
  return path.join(
    process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"),
    "consensus-node",
    "secret.key",
  );
}

const keyfileAdapter: KeystoreAdapter = {
  name: "keyfile",
  async available() {
    return process.platform === "darwin" || process.platform === "linux";
  },
  async get() {
    try {
      const raw = await fs.readFile(keyFilePath(), "utf8");
      const key = Buffer.from(raw.trim(), "base64");
      return key.length === DEK_BYTES ? key : null;
    } catch {
      return null;
    }
  },
  async set(key) {
    const file = keyFilePath();
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    await fs.writeFile(file, key.toString("base64"), { mode: 0o600 });
    // mkdir's mode is masked by umask, so set it explicitly rather than trusting it.
    await fs.chmod(path.dirname(file), 0o700);
    await fs.chmod(file, 0o600);
  },
};

const ADAPTERS: KeystoreAdapter[] = [envAdapter, keyfileAdapter];

async function selectAdapter(): Promise<KeystoreAdapter> {
  for (const adapter of ADAPTERS) {
    if (await adapter.available()) return adapter;
  }
  throw new Error(
    `No keystore adapter available for platform ${process.platform}. ` +
      "Set CONSENSUS_NODE_SECRET_KEY to a base64 32-byte key to supply one yourself.",
  );
}

let cachedKey: Buffer | null = null;

/** The data key, minted into the platform keystore on first use. Cached per process
 *  so a node reading several secrets hits the keystore once. */
export async function getOrCreateDataKey(): Promise<Buffer> {
  if (cachedKey) return cachedKey;

  const adapter = await selectAdapter();
  const existing = await adapter.get();
  if (existing) {
    cachedKey = existing;
    return existing;
  }

  const key = crypto.randomBytes(DEK_BYTES);
  await adapter.set(key);

  // Read back rather than trusting the write: a keystore that silently refused
  // would otherwise leave us encrypting against a key nothing can recover.
  const stored = await adapter.get();
  if (!stored || !stored.equals(key)) {
    throw new Error(`Keystore ${adapter.name} did not retain the node data key`);
  }

  log.info("secret-store", "data-key-created", { adapter: adapter.name });
  cachedKey = key;
  return key;
}

/** Reset the cached key. Tests only. */
export function resetDataKeyCache(): void {
  cachedKey = null;
}

export interface KeystoreStatus {
  adapter: string;
  location: string;
  present: boolean;
}

/** Where the data key lives and whether it is already there. Used by the boot-unit
 *  installers to prove, as the account the daemon will run as, that the key is
 *  reachable — so a misconfiguration surfaces at install time and not at 3am. */
export async function describeKeystore(): Promise<KeystoreStatus> {
  const adapter = await selectAdapter();
  return {
    adapter: adapter.name,
    location: adapter.name === "env" ? "CONSENSUS_NODE_SECRET_KEY" : keyFilePath(),
    present: (await adapter.get()) !== null,
  };
}

export function isSecretEnvelope(value: unknown): value is SecretEnvelope {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<SecretEnvelope>;
  return (
    candidate.v === ENVELOPE_VERSION &&
    candidate.alg === ALGORITHM &&
    typeof candidate.nonce === "string" &&
    typeof candidate.ct === "string"
  );
}

export async function sealSecret(slot: string, plaintext: string): Promise<SecretEnvelope> {
  const key = await getOrCreateDataKey();
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const aad = Buffer.from(slot, "utf8");
  const ct = chacha20poly1305(key, nonce, aad).encrypt(Buffer.from(plaintext, "utf8"));
  return {
    v: ENVELOPE_VERSION,
    alg: ALGORITHM,
    nonce: nonce.toString("base64"),
    ct: Buffer.from(ct).toString("base64"),
  };
}

export async function openSecret(slot: string, envelope: SecretEnvelope): Promise<string> {
  const key = await getOrCreateDataKey();
  const nonce = Buffer.from(envelope.nonce, "base64");
  const aad = Buffer.from(slot, "utf8");
  const pt = chacha20poly1305(key, nonce, aad).decrypt(Buffer.from(envelope.ct, "base64"));
  return Buffer.from(pt).toString("utf8");
}

/** Write plaintext to disk encrypted, replacing any existing file atomically so a
 *  crash mid-write cannot leave a truncated secret behind. */
export async function writeSecretFile(slot: string, file: string, plaintext: string): Promise<void> {
  const envelope = await sealSecret(slot, plaintext);
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${crypto.randomBytes(6).toString("hex")}`;
  await fs.writeFile(tmp, JSON.stringify(envelope), { mode: 0o600 });
  await fs.rename(tmp, file);
}

/**
 * Read a secret file, transparently upgrading a legacy plaintext one.
 *
 * Nodes provisioned before encryption landed hold a bare PEM (or bare JSON) here.
 * Those are re-written sealed on first read, so an existing node encrypts itself on
 * next start with no operator action and no re-registration.
 */
export async function readSecretFile(slot: string, file: string): Promise<string | null> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = null;
  }

  if (isSecretEnvelope(parsed)) return openSecret(slot, parsed);

  // Legacy plaintext. Seal it in place, then hand back what the caller expected.
  await writeSecretFile(slot, file, raw);
  log.info("secret-store", "plaintext-migrated", { slot });
  return raw;
}
