import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveAndCheckTarget } from '../runtime/ssrf';

interface Case {
  url: string;
  expect: 'allow' | 'block';
}

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(fs.readFileSync(path.join(here, '../runtime/ssrf.vectors.json'), 'utf8')) as {
  cases: Case[];
};

let checks = 0;
for (const c of fixture.cases) {
  if (c.expect === 'allow') {
    const resolved = await resolveAndCheckTarget(c.url);
    assert.ok(resolved.ip, `expected ${c.url} to be allowed`);
  } else {
    await assert.rejects(() => resolveAndCheckTarget(c.url), /Forbidden/, `expected ${c.url} to be blocked`);
  }
  checks++;
}

console.log(`ssrf.test.ts: ${checks} SSRF vectors verified under Bun — node guard matches the orchestrator`);
