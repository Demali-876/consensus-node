// Session-derivation throughput: one P-256 ephemeral keygen + ECDH + HKDF per
// op — exactly what acceptDataInit pays per request to stand up the encrypted
// session (minus the Ed25519 identity sign, measured separately in ed25519.ts).
// Together they are the bulk of the composite's `handshake` stage.
//
// Note the curve is P-256, not X25519 — the data-plane secure channel
// (crypto/secure-channel.ts) uses ECDH P-256 via WebCrypto. This suite calls
// those exact production functions so the number tracks the real cost.

import {
  deriveSecureSession,
  generateHandshakeKeyPair,
  randomHandshakeNonce,
  type HandshakeKeyPair,
} from "../../../crypto/secure-channel";
import { bench, type BenchResult } from "../runner";

export interface SessionDeriveOptions {
  warmupMs?: number;
  measureMs?: number;
}

export interface SessionDeriveResult extends BenchResult {
  curve: "P-256";
  derivations_per_second: number;
}

export async function runSessionDerive(opts: SessionDeriveOptions = {}): Promise<SessionDeriveResult> {
  // The peer (client) ephemeral is supplied per request in production — generate
  // it once here so each timed op measures only the node's share: its own fresh
  // ephemeral keygen, then importing the peer key + ECDH + HKDF.
  const peer: HandshakeKeyPair = await generateHandshakeKeyPair();
  const clientNonce = randomHandshakeNonce();
  const serverNonce = randomHandshakeNonce();

  const result = await bench(
    async () => {
      const local = await generateHandshakeKeyPair();
      await deriveSecureSession({
        role: "server",
        privateKey: local.privateKey,
        peerPublicKeyRaw: peer.publicKeyRaw,
        clientNonce,
        serverNonce,
      });
      return 1;
    },
    { name: "session-derive", measureMs: opts.measureMs ?? 800, warmupMs: opts.warmupMs },
  );

  return { ...result, curve: "P-256", derivations_per_second: Math.round(result.ops_per_second) };
}
