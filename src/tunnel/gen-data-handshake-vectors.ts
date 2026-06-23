// Generates deterministic data-handshake channel-binding vectors so
// consensus-client computes the exact bytes the node binds the session to and
// signs in its identity proof — byte-for-byte across runtimes. The binding is a
// pure function of the handshake transcript (protocol/version/node_id + both
// ephemeral public keys + both nonces), so fixed string inputs fully pin it; no
// real ECDH points are needed here. Pairs with responder-auth.vectors.json,
// which pins that a proof carrying such a binding verifies.
//
//   bun run gen:data-handshake-vectors
//
// Re-run and commit the JSON whenever the channel-binding format changes.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { channelBinding, DATA_HANDSHAKE_PROTOCOL, DATA_HANDSHAKE_VERSION } from "./data-handshake";

const NODE_ID = "node-data";

// Fixed, structurally-realistic inputs (P-256 raw public keys are 65 bytes,
// nonces 32). channelBinding treats them as opaque base64, so the values only
// need to be deterministic and distinct.
const b64 = (byte: number, len: number) => Buffer.alloc(len, byte).toString("base64");

interface VectorInput {
  node_id: string;
  client_public_key: string;
  client_nonce: string;
  node_public_key: string;
  node_nonce: string;
}

interface Vector {
  name: string;
  input: VectorInput;
  channel_binding: string; // base64 SHA-256 of the transcript
}

function vector(name: string, input: VectorInput): Vector {
  const binding = channelBinding({
    nodeId: input.node_id,
    clientPublicKey: input.client_public_key,
    clientNonce: input.client_nonce,
    nodePublicKey: input.node_public_key,
    nodeNonce: input.node_nonce,
  });
  return { name, input, channel_binding: binding.toString("base64") };
}

const baseline: VectorInput = {
  node_id: NODE_ID,
  client_public_key: b64(0x11, 65),
  client_nonce: b64(0x01, 32),
  node_public_key: b64(0x22, 65),
  node_nonce: b64(0x02, 32),
};

const vectors: Vector[] = [
  vector("baseline", baseline),
  // Swapping the node ephemeral key (the relay/MITM move) changes the binding —
  // the exact byte-level reason a spliced-key handshake is rejected.
  vector("node-key-swapped", { ...baseline, node_public_key: b64(0x33, 65) }),
  // A different client nonce changes the binding too (both sides feed the hash).
  vector("client-nonce-changed", { ...baseline, client_nonce: b64(0x05, 32) }),
];

const out = {
  protocol: DATA_HANDSHAKE_PROTOCOL,
  version: DATA_HANDSHAKE_VERSION,
  vectors,
};

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(here, "test-vectors");
fs.mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, "data-handshake.vectors.json");
fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n", "utf8");
console.log(`wrote ${vectors.length} data-handshake vectors -> ${path.relative(process.cwd(), outPath)}`);
