import crypto from "node:crypto";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bench, type BenchResult } from "../runner";

const PAYLOAD_SIZES_BYTES = [64, 1024, 16384];

// Inner-loop tuned so each sample is ~5–10ms regardless of payload size.
// AEAD throughput is roughly inverse to payload size at low sizes (header overhead),
// then bandwidth-bound at large sizes.
const INNER_OPS_BY_SIZE: Record<number, number> = {
  64: 2000,
  1024: 500,
  16384: 50,
};

export interface CryptoAeadSubResult extends BenchResult {
  payload_size_bytes: number;
  encrypt_bytes_per_second: number;
  decrypt_bytes_per_second: number;
  total_bytes_per_second: number;
}

export interface CryptoAeadResult {
  algorithm: "chacha20-poly1305";
  results: CryptoAeadSubResult[];
  // Headline at 1KB. `bytes_per_second` is one-way (encrypt OR decrypt);
  // `total_bytes_per_second` is round-trip (encrypt + decrypt).
  bytes_per_second: number;
  total_bytes_per_second: number;
  reliable: boolean;
}

export async function runCryptoAead(): Promise<CryptoAeadResult> {
  const aad = Buffer.from("consensus-node-bench-v2");
  const key = crypto.randomBytes(32);
  const nonce = Buffer.alloc(12);
  const sub: CryptoAeadSubResult[] = [];

  for (const sz of PAYLOAD_SIZES_BYTES) {
    const payload = crypto.randomBytes(sz);
    const inner = INNER_OPS_BY_SIZE[sz] ?? 100;
    const result = await bench(
      () => {
        for (let i = 0; i < inner; i++) {
          const sealed = chacha20poly1305(key, nonce, aad).encrypt(payload);
          const opened = chacha20poly1305(key, nonce, aad).decrypt(sealed);
          if (opened.length !== payload.length) {
            throw new Error("AEAD round-trip verification failed");
          }
        }
        return inner;
      },
      { name: `chacha20poly1305-${sz}B` },
    );
    sub.push({
      ...result,
      payload_size_bytes: sz,
      encrypt_bytes_per_second: sz * result.ops_per_second,
      decrypt_bytes_per_second: sz * result.ops_per_second,
      total_bytes_per_second: 2 * sz * result.ops_per_second,
    });
  }

  const headline = sub.find((r) => r.payload_size_bytes === 1024) ?? sub[0];
  return {
    algorithm: "chacha20-poly1305",
    results: sub,
    bytes_per_second: headline.encrypt_bytes_per_second,
    total_bytes_per_second: headline.total_bytes_per_second,
    reliable: sub.every((r) => r.reliable),
  };
}
