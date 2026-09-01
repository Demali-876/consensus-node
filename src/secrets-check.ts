#!/usr/bin/env bun
//
// Preflight for encryption at rest. Provisions the data key if it does not exist
// yet, then proves it can be read back and that the node's existing secrets open
// with it.
//
// The boot-unit installers run this AS THE ACCOUNT THE DAEMON WILL RUN AS, before
// enabling the unit. That is the point: the daemon starts with no login session, so
// "can this account reach the data key unattended?" has to be answered while an
// operator is still at the keyboard, not on the next reboot.
//
// Exit codes: 0 healthy, 1 unusable.

import fs from "node:fs/promises";
import { describeKeystore, getOrCreateDataKey, readSecretFile, SLOT_NODE_KEY, SLOT_JOIN_AUTH } from "./node/secret-store";
import { paths } from "./node/state";

async function main(): Promise<void> {
  const before = await describeKeystore();
  console.log(`keystore:   ${before.adapter}`);
  console.log(`location:   ${before.location}`);
  console.log(`existing:   ${before.present ? "yes" : "no (will be created)"}`);

  await getOrCreateDataKey();

  const after = await describeKeystore();
  if (!after.present && after.adapter !== "env") {
    throw new Error(`data key was not persisted to ${after.location}`);
  }

  // Opening the real secrets is the only proof that matters: a key that exists but
  // does not match what is already on disk would strand the node at boot.
  const p = paths();
  for (const [slot, file] of [
    [SLOT_NODE_KEY, p.privateKeyPem],
    [SLOT_JOIN_AUTH, p.joinAuth],
  ] as const) {
    try {
      await fs.access(file);
    } catch {
      console.log(`${slot}: absent (nothing to verify yet)`);
      continue;
    }
    try {
      await readSecretFile(slot, file);
    } catch (error) {
      // An AEAD tag failure means the data key does not match this ciphertext —
      // the key was rotated, lost, or minted under a different account. Say that,
      // rather than surfacing "invalid tag" and leaving the operator to guess.
      throw new Error(
        `${slot} at ${file} could not be decrypted with the data key at ${after.location}. ` +
          "The key does not match this node's secrets — it was most likely lost, rotated, or " +
          "created under a different user account. Restore the original key file; a node " +
          `cannot recover ${SLOT_NODE_KEY} without it and would have to re-register. ` +
          `(underlying: ${error instanceof Error ? error.message : String(error)})`,
      );
    }
    console.log(`${slot}: opens correctly`);
  }

  console.log("secrets ok — this account can decrypt unattended");
}

main().catch((error) => {
  console.error(`secrets check FAILED: ${error instanceof Error ? error.message : String(error)}`);
  console.error("The node would not be able to start without a login. Resolve this before enabling the boot unit.");
  process.exit(1);
});
