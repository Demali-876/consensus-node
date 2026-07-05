// Ed25519 sign + verify throughput. Diagnostic: the data-plane handshake signs
// a node-identity proof per request (crypto.sign in crypto/identity.ts, via
// responder-auth), and ticket verification does an Ed25519 verify per request
// (PASETO v4.public). These two numbers explain the composite's `handshake` and
// `ticket_verify` stages. Uses crypto.sign/verify directly — the same
// primitive calls the production path makes.

import crypto from "node:crypto";
import { bench, type BenchResult } from "../runner";

export interface Ed25519Options {
  warmupMs?: number;
  measureMs?: number;
}

export interface Ed25519Result {
  sign: BenchResult;
  verify: BenchResult;
  sign_per_second: number;
  verify_per_second: number;
  reliable: boolean;
}

// Inner loop amortizes closure overhead; ~128 keeps a sample near 5-10ms on
// fast hardware and stays reasonable on an SBC.
const INNER = 128;

export async function runEd25519(opts: Ed25519Options = {}): Promise<Ed25519Result> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  // ~96 bytes ≈ a PASETO signing input (claims + implicit assertion).
  const message = crypto.randomBytes(96);
  const signature = crypto.sign(null, message, privateKey);

  const sign = await bench(
    () => {
      for (let i = 0; i < INNER; i++) crypto.sign(null, message, privateKey);
      return INNER;
    },
    { name: "ed25519-sign", ...opts },
  );

  const verify = await bench(
    () => {
      for (let i = 0; i < INNER; i++) {
        if (!crypto.verify(null, message, publicKey, signature)) {
          throw new Error("ed25519 verify failed");
        }
      }
      return INNER;
    },
    { name: "ed25519-verify", ...opts },
  );

  return {
    sign,
    verify,
    sign_per_second: Math.round(sign.ops_per_second),
    verify_per_second: Math.round(verify.ops_per_second),
    reliable: sign.reliable && verify.reliable,
  };
}
