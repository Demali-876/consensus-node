import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateDedupeKey, type DedupeParams } from '../runtime/dedupe';

interface Vector {
  name: string;
  input: DedupeParams;
  key: string;
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(fs.readFileSync(path.join(here, '../runtime/dedupe.vectors.json'), 'utf8')) as {
  vectors: Vector[];
};

let checks = 0;

// Shared vectors must reproduce identically under Bun (byte-compat with the orchestrator).
for (const v of fixture.vectors) {
  assert.equal(generateDedupeKey(v.input), v.key, `vector ${v.name}`);
  checks++;
}

// Canonicalization equivalences hold (the node will rely on these to match a ticket's sub).
const base: DedupeParams = { target_url: 'https://api.example.com/p?a=1&b=2', method: 'GET' };
assert.equal(generateDedupeKey(base), generateDedupeKey({ ...base, target_url: 'https://api.example.com/p?b=2&a=1' }));
assert.equal(generateDedupeKey(base), generateDedupeKey({ ...base, target_url: 'https://API.example.com:443/p?a=1&b=2' }));
assert.equal(generateDedupeKey(base), generateDedupeKey({ ...base, method: 'get' }));
checks += 3;

console.log(`dedupe.test.ts: ${checks} dedupe vectors verified under Bun — node matches the orchestrator`);
