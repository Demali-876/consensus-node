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

// 3) Replay cache enforces maxEntries by evicting the oldest entry (even when
// nothing has expired), so the map can't grow without bound under valid load.
const bounded = new JtiReplayCache(2);
const farFuture = 9_999_999_999;
assert.ok(bounded.consume('a', farFuture, 1000), 'a is fresh');
assert.ok(bounded.consume('b', farFuture, 1000), 'b is fresh');
assert.ok(bounded.consume('c', farFuture, 1000), 'c is fresh (evicts oldest)');
assert.equal(bounded.size, 2, 'cache stays bounded at maxEntries with all entries unexpired');
assert.equal(bounded.consume('b', farFuture, 1000), false, 'still-cached jti rejected as replay');
checks += 5;

// 4) Performance at capacity: once the cache is full of still-UNEXPIRED entries,
// each insert must stay O(1) amortized. The earlier implementation force-swept
// the entire map on every insert at capacity (O(maxEntries) per insert, removing
// nothing when nothing had expired), so a busy node — ~4k req/s fills the 100k
// cache in ~25s — then paid a full 100k-entry scan per request and collapsed.
// This guards that regression with a time bound while re-checking that the
// eviction semantics (duplicates rejected, oldest evicted first) still hold.
{
  const CAP = 100_000;
  const INSERTS_AT_CAP = 10_000;
  // O(1)-amortized inserts finish in well under 100ms; the O(maxEntries) cliff
  // needs ~1e9 map iterations (many seconds). 1s cleanly separates them while
  // tolerating a slow/loaded CI runner.
  const PERF_BUDGET_MS = 1_000;
  const now = 1000;
  const perf = new JtiReplayCache(CAP);

  // Fill exactly to capacity with unexpired entries (constant `now`, so the 30s
  // janitor sweep runs once over an empty map and then stays gated out).
  let allFresh = true;
  for (let i = 0; i < CAP; i++) {
    if (!perf.consume(`fill-${i}`, farFuture, now)) allFresh = false;
  }
  assert.ok(allFresh, 'every unique fill entry is accepted as fresh');
  assert.equal(perf.size, CAP, 'cache filled exactly to capacity');

  // Time INSERTS_AT_CAP more unexpired inserts — the path that used to degrade to
  // a full scan per insert. GC first so a collection pause can't land in-window.
  Bun.gc(true);
  let allFreshAtCap = true;
  const start = performance.now();
  for (let i = 0; i < INSERTS_AT_CAP; i++) {
    if (!perf.consume(`atcap-${i}`, farFuture, now)) allFreshAtCap = false;
  }
  const elapsedMs = performance.now() - start;
  assert.ok(allFreshAtCap, 'every unique at-capacity insert is accepted as fresh');
  assert.equal(perf.size, CAP, 'cache stays bounded at capacity after inserts at capacity');
  assert.ok(
    elapsedMs < PERF_BUDGET_MS,
    `${INSERTS_AT_CAP} inserts at capacity stay O(1) amortized (took ${elapsedMs.toFixed(1)}ms, budget ${PERF_BUDGET_MS}ms)`,
  );

  // Eviction correctness at capacity, oldest-first: the most recent insert and a
  // still-resident older fill are rejected as replays, while the very oldest fill
  // (evicted on the first at-capacity insert) reads as fresh again.
  assert.equal(perf.consume('atcap-9999', farFuture, now), false, 'most-recent insert still cached → replay rejected');
  assert.equal(perf.consume('fill-99999', farFuture, now), false, 'a not-yet-evicted fill entry still cached');
  assert.equal(perf.consume('fill-0', farFuture, now), true, 'oldest entry was evicted first');
  checks += 8;
}

console.log(`tickets.test.ts: ${checks} checks passed — shared vectors verify under Bun + replay enforced + bounded + O(1) at capacity`);
