import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertProxyProfileRequestV1,
  hashProxyProfileV1,
  normalizeProxyProfileV1,
} from '../runtime/profile-v1';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(fs.readFileSync(path.join(here, '../runtime/profile-v1.vectors.json'), 'utf8')) as {
  vectors: Array<{ input: unknown; normalized: unknown; hash: string }>;
};

let checks = 0;
for (const vector of fixture.vectors) {
  assert.deepEqual(normalizeProxyProfileV1(vector.input), vector.normalized);
  assert.equal(hashProxyProfileV1(vector.input), vector.hash);
  checks += 2;
}
const profile = fixture.vectors[0].normalized;
assert.doesNotThrow(() => assertProxyProfileRequestV1(profile, 'https://api.example.com/v1/products/1', 'GET'));
assert.throws(() => assertProxyProfileRequestV1(profile, 'https://api.example.com/v1/private', 'GET'), /not allowed/);
checks += 2;

console.log(`profile-v1.test.ts: ${checks} shared contract checks passed`);
