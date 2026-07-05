// Response-encode throughput: base64-encode the upstream body + JSON.stringify
// the proxy_response envelope, at the same response sizes as the composite. This
// is the composite's `response_encode` stage in isolation — small at typical
// sizes but a real, often-overlooked cost that grows with the body (base64 is a
// ×1.33 expansion plus a full string copy). Mirrors the encode in
// tunnel/data-plane.ts resolveProxyResponse.

import crypto from "node:crypto";
import { bench, type BenchResult } from "../runner";

export interface EncodeOptions {
  warmupMs?: number;
  measureMs?: number;
}

export interface EncodeSubResult extends BenchResult {
  payload_size_bytes: number;
  bytes_per_second: number;
}

export interface EncodeResult {
  results: EncodeSubResult[];
  // Headline at 16KB, matching the composite headline size.
  bytes_per_second: number;
  reliable: boolean;
}

const SIZES = [1024, 16384, 262144];
const INNER_BY_SIZE: Record<number, number> = { 1024: 400, 16384: 60, 262144: 6 };

export async function runEncode(opts: EncodeOptions = {}): Promise<EncodeResult> {
  const sub: EncodeSubResult[] = [];

  for (const sz of SIZES) {
    const body = crypto.randomBytes(sz);
    const headers = {
      "content-type": "application/json",
      "content-length": String(sz),
      server: "upstream/1.0",
    };
    const inner = INNER_BY_SIZE[sz] ?? 50;

    const result = await bench(
      () => {
        for (let i = 0; i < inner; i++) {
          const json = JSON.stringify({
            type: "proxy_response",
            status: 200,
            status_text: "OK",
            headers,
            body: body.toString("base64"),
            body_encoding: "base64",
          });
          if (json.length === 0) throw new Error("encode produced empty output");
        }
        return inner;
      },
      { name: `encode-${sz}`, ...opts },
    );

    sub.push({ ...result, payload_size_bytes: sz, bytes_per_second: sz * result.ops_per_second });
  }

  const headline = sub.find((s) => s.payload_size_bytes === 16384) ?? sub[0];
  return {
    results: sub,
    bytes_per_second: headline.bytes_per_second,
    reliable: sub.every((s) => s.reliable),
  };
}
