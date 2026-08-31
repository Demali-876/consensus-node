// Tests for encryption at rest of the node's secrets.
//
// The envelope and migration cases run against the `env` adapter
// (CONSENSUS_NODE_SECRET_KEY); the final section exercises the real `keyfile` adapter
// via CONSENSUS_NODE_SECRET_KEY_PATH. Nothing is written outside the temp dir.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-secret-store-"));

process.env.CONSENSUS_NODE_SECRET_KEY = crypto.randomBytes(32).toString("base64");
process.env.CONSENSUS_STATE_DIR = path.join(root, "state");

const {
  sealSecret,
  openSecret,
  readSecretFile,
  writeSecretFile,
  isSecretEnvelope,
  getOrCreateDataKey,
  resetDataKeyCache,
  describeKeystore,
  SLOT_NODE_KEY,
  SLOT_JOIN_AUTH,
} = await import("../node/secret-store");
const { loadOrCreateIdentity } = await import("../crypto/identity");
const { saveJoinAuthorization, loadJoinAuthorization, paths } = await import("../node/state");

const PEM_SAMPLE = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";

try {
  // --- envelope primitives -------------------------------------------------

  const sealed = await sealSecret(SLOT_NODE_KEY, PEM_SAMPLE);
  assert.equal(isSecretEnvelope(sealed), true, "seal produces a recognised envelope");
  assert.equal(await openSecret(SLOT_NODE_KEY, sealed), PEM_SAMPLE, "roundtrips");
  assert.equal(sealed.ct.includes("BEGIN PRIVATE KEY"), false, "ciphertext is not the plaintext");

  // The slot name is AAD, so a blob cannot be moved between slots.
  await assert.rejects(
    () => openSecret(SLOT_JOIN_AUTH, sealed),
    "an envelope sealed for one slot must not open under another",
  );

  // Tampering must be detected rather than silently returning garbage.
  const tampered = { ...sealed };
  const bytes = Buffer.from(tampered.ct, "base64");
  bytes[0] = bytes[0]! ^ 0xff;
  tampered.ct = bytes.toString("base64");
  await assert.rejects(() => openSecret(SLOT_NODE_KEY, tampered), "modified ciphertext is rejected");

  // A different data key must not open the envelope.
  resetDataKeyCache();
  const originalKey = process.env.CONSENSUS_NODE_SECRET_KEY;
  process.env.CONSENSUS_NODE_SECRET_KEY = crypto.randomBytes(32).toString("base64");
  await assert.rejects(() => openSecret(SLOT_NODE_KEY, sealed), "a foreign data key is rejected");
  process.env.CONSENSUS_NODE_SECRET_KEY = originalKey;
  resetDataKeyCache();

  const key = await getOrCreateDataKey();
  assert.equal(key.length, 32, "data key is 32 bytes");

  // --- file layer ----------------------------------------------------------

  const secretFile = path.join(root, "files", "secret.json");
  await writeSecretFile(SLOT_NODE_KEY, secretFile, PEM_SAMPLE);

  const onDisk = await fs.readFile(secretFile, "utf8");
  assert.equal(onDisk.includes("BEGIN PRIVATE KEY"), false, "file on disk holds no plaintext");
  assert.equal((await fs.stat(secretFile)).mode & 0o777, 0o600, "file is 0600");
  assert.equal(await readSecretFile(SLOT_NODE_KEY, secretFile), PEM_SAMPLE, "reads back");
  assert.equal(await readSecretFile(SLOT_NODE_KEY, path.join(root, "absent")), null, "missing file is null");

  // Legacy plaintext must be upgraded in place and still return its original value.
  const legacyFile = path.join(root, "files", "legacy.pem");
  await fs.writeFile(legacyFile, PEM_SAMPLE, { mode: 0o600 });
  assert.equal(await readSecretFile(SLOT_NODE_KEY, legacyFile), PEM_SAMPLE, "legacy read returns plaintext");
  const migrated = await fs.readFile(legacyFile, "utf8");
  assert.equal(migrated.includes("BEGIN PRIVATE KEY"), false, "legacy file was sealed in place");
  assert.equal(isSecretEnvelope(JSON.parse(migrated)), true, "legacy file is now an envelope");
  assert.equal(await readSecretFile(SLOT_NODE_KEY, legacyFile), PEM_SAMPLE, "still readable after migration");

  // --- identity ------------------------------------------------------------

  const p = paths();
  const first = await loadOrCreateIdentity();
  assert.equal(first.privateKeyPem.includes("BEGIN PRIVATE KEY"), true, "returns a usable PEM");

  const keyOnDisk = await fs.readFile(p.privateKeyPem, "utf8");
  assert.equal(keyOnDisk.includes("BEGIN PRIVATE KEY"), false, "node.key is encrypted at rest");
  assert.equal(
    (await fs.readFile(p.publicKeyPem, "utf8")).includes("BEGIN PUBLIC KEY"),
    true,
    "node.pub stays plaintext — it is public",
  );

  const second = await loadOrCreateIdentity();
  assert.equal(second.privateKeyPem, first.privateKeyPem, "identity is stable across loads");

  // The migration path matters most here: an existing node must keep its identity,
  // because a new key would orphan its registration on the orchestrator.
  await fs.writeFile(p.privateKeyPem, first.privateKeyPem, { mode: 0o600 });
  const afterMigration = await loadOrCreateIdentity();
  assert.equal(afterMigration.privateKeyPem, first.privateKeyPem, "plaintext key survives migration");
  assert.equal(
    (await fs.readFile(p.privateKeyPem, "utf8")).includes("BEGIN PRIVATE KEY"),
    false,
    "and is encrypted afterwards",
  );

  // --- join authorization --------------------------------------------------

  const auth = {
    join_id: "join-123",
    alg: "ed25519" as const,
    nonce: "nonce-abc",
    signature: "sig-xyz",
    expires_at: Math.floor(Date.now() / 1000) + 600,
    saved_at: new Date().toISOString(),
  };
  await saveJoinAuthorization(auth);
  assert.equal(
    (await fs.readFile(p.joinAuth, "utf8")).includes("join-123"),
    false,
    "join-auth.json is encrypted at rest",
  );
  assert.deepEqual(await loadJoinAuthorization(), auth, "join authorization roundtrips");

  await fs.writeFile(p.joinAuth, JSON.stringify(auth), { mode: 0o600 });
  assert.deepEqual(await loadJoinAuthorization(), auth, "legacy plaintext join-auth still loads");
  assert.equal(
    (await fs.readFile(p.joinAuth, "utf8")).includes("join-123"),
    false,
    "and was sealed in place",
  );

  await fs.writeFile(p.joinAuth, "{ not json", { mode: 0o600 });
  assert.equal(await loadJoinAuthorization(), null, "corrupt authorization reads as absent");

  // --- keyfile adapter -----------------------------------------------------
  // The production path. It has to work with no login session and no root, which is
  // what makes pre-login boot possible, so exercise it directly rather than only
  // through the env override the tests above use.

  const injected = process.env.CONSENSUS_NODE_SECRET_KEY;
  delete process.env.CONSENSUS_NODE_SECRET_KEY;
  const keyFile = path.join(root, "outside", "secret.key");
  process.env.CONSENSUS_NODE_SECRET_KEY_PATH = keyFile;
  resetDataKeyCache();

  const status = await describeKeystore();
  assert.equal(status.adapter, "keyfile", "falls through to the keyfile adapter");
  assert.equal(status.present, false, "no key before first use");

  const minted = await getOrCreateDataKey();
  assert.equal(minted.length, 32, "keyfile adapter mints a 32-byte key");
  assert.equal((await fs.stat(keyFile)).mode & 0o777, 0o600, "key file is 0600");
  assert.equal((await fs.stat(path.dirname(keyFile))).mode & 0o777, 0o700, "key dir is 0700");

  // The whole point of the scheme: the key must not live in the directory it protects.
  assert.equal(
    keyFile.startsWith(p.base),
    false,
    "data key lives OUTSIDE the state directory it protects",
  );

  resetDataKeyCache();
  assert.equal(
    (await getOrCreateDataKey()).toString("base64"),
    minted.toString("base64"),
    "key persists across processes",
  );
  assert.equal((await describeKeystore()).present, true, "keystore reports the key present");

  // A secret sealed under the keyfile key must survive a cache reset, which is what
  // a reboot looks like to this code.
  const bootFile = path.join(root, "outside-sealed.json");
  await writeSecretFile(SLOT_NODE_KEY, bootFile, PEM_SAMPLE);
  resetDataKeyCache();
  assert.equal(await readSecretFile(SLOT_NODE_KEY, bootFile), PEM_SAMPLE, "survives a restart");

  delete process.env.CONSENSUS_NODE_SECRET_KEY_PATH;
  if (injected) process.env.CONSENSUS_NODE_SECRET_KEY = injected;
  resetDataKeyCache();
} finally {
  await fs.rm(root, { recursive: true, force: true });
}

console.log("secret store ok");
