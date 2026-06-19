import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyTicket, type TicketClaims } from '../tickets/ticket';
import { verifyRoutingTicket } from '../tickets/verifier';
import { JtiReplayCache } from '../tickets/replay';

interface Vector {
  name: string;
  token: string;
  verify: { expectedNodeId: string; expectedScope?: string; now: number };
  expect: { ok: boolean; error?: string; kid?: string; claims?: Partial<TicketClaims> };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturePath = path.join(here, '../tickets/test-vectors/tickets.vectors.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8')) as {
  kid: string;
  publicJwk: Record<string, string>;
  vectors: Vector[];
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- JWK input type isn't exported in this runtime's node:crypto types
const publicKey = crypto.createPublicKey({ key: fixture.publicJwk as any, format: 'jwk' });
assert.equal(publicKey.asymmetricKeyType, 'ed25519', 'fixture public key is Ed25519');

let checks = 0;

// 1) Shared vectors must verify identically under Bun (byte-compat with the orchestrator).
for (const v of fixture.vectors) {
  if (v.expect.ok) {
    const { claims, kid } = verifyTicket(v.token, publicKey, v.verify);
    for (const [key, value] of Object.entries(v.expect.claims ?? {})) {
      assert.equal((claims as unknown as Record<string, unknown>)[key], value, `vector ${v.name}: claim ${key}`);
    }
    if (v.expect.kid) assert.equal(kid, v.expect.kid, `vector ${v.name}: kid`);
  } else {
    assert.throws(
      () => verifyTicket(v.token, publicKey, v.verify),
      new RegExp(v.expect.error ?? '.'),
      `vector ${v.name}: expected failure`,
    );
  }
  checks++;
}

// 2) Replay protection: a valid ticket cannot be consumed twice with one cache.
const valid = fixture.vectors.find((v) => v.name === 'valid');
assert.ok(valid, 'fixture has a valid vector');
const replay = new JtiReplayCache();
const first = verifyRoutingTicket(valid.token, publicKey, { ...valid.verify, replay });
assert.equal(first.claims.jti, 'jti-valid', 'valid ticket consumed once');
assert.throws(
  () => verifyRoutingTicket(valid.token, publicKey, { ...valid.verify, replay }),
  /replayed/,
  'second use of the same jti must be rejected',
);
checks += 2;

console.log(`tickets.test.ts: ${checks} checks passed — shared vectors verify under Bun + replay enforced`);
