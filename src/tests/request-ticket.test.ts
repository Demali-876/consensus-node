import assert from "node:assert/strict";
import crypto from "node:crypto";

import { issueTicket } from "../tickets/ticket";
import { verifyRequestTicket } from "../tickets/request-ticket";
import { JtiReplayCache } from "../tickets/replay";
import { generateDedupeKey, type DedupeParams } from "../runtime/dedupe";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const KID = "kid-test";
const NODE = "node-1";

const request: DedupeParams = {
  target_url: "https://api.example.com/v1/data?b=2&a=1",
  method: "GET",
  headers: { "content-type": "application/json", "x-api-key": "secret" },
};
const dedupeKey = generateDedupeKey(request);
const otherRequest: DedupeParams = { ...request, target_url: "https://api.example.com/v1/OTHER" };

function mint(
  overrides: Partial<{ nodeId: string; dedupeKey: string; jti: string; now: number; ttlSec: number }> = {},
): string {
  return issueTicket(
    {
      nodeId: overrides.nodeId ?? NODE,
      dedupeKey: overrides.dedupeKey ?? dedupeKey,
      jti: overrides.jti ?? "j1",
      now: overrides.now ?? 1000,
      ttlSec: overrides.ttlSec,
    },
    privateKey,
    KID,
  );
}

let checks = 0;

// 1) Happy path: a matching request verifies and returns the bound dedupe key.
{
  const v = verifyRequestTicket({
    token: mint(),
    nodeId: NODE,
    publicKey,
    request,
    now: 1010,
    replay: new JtiReplayCache(),
  });
  assert.equal(v.claims.sub, dedupeKey);
  assert.equal(v.dedupeKey, dedupeKey);
  assert.equal(v.kid, KID);
  checks += 3;
}

// 2) A different request than the ticket was issued for is rejected.
assert.throws(
  () => verifyRequestTicket({ token: mint(), nodeId: NODE, publicKey, request: otherRequest, now: 1010 }),
  /does not match/,
);
checks++;

// 3) A ticket minted for another node is rejected (aud + implicit assertion).
assert.throws(() =>
  verifyRequestTicket({ token: mint({ nodeId: "node-A" }), nodeId: "node-B", publicKey, request, now: 1010 }),
);
checks++;

// 4) Expired ticket is rejected.
assert.throws(
  () => verifyRequestTicket({ token: mint({ now: 1000, ttlSec: 60 }), nodeId: NODE, publicKey, request, now: 5000 }),
  /expired/,
);
checks++;

// 5) Signed by a key other than the pinned one — rejected.
assert.throws(() =>
  verifyRequestTicket({
    token: mint(),
    nodeId: NODE,
    publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    request,
    now: 1010,
  }),
);
checks++;

// 6) Single-use: the same jti cannot be spent twice with one cache.
{
  const cache = new JtiReplayCache();
  const token = mint({ jti: "once" });
  verifyRequestTicket({ token, nodeId: NODE, publicKey, request, now: 1010, replay: cache });
  assert.throws(
    () => verifyRequestTicket({ token, nodeId: NODE, publicKey, request, now: 1010, replay: cache }),
    /replay/,
  );
  checks++;
}

// 7) Ordering: a rejected request must NOT burn the jti. After a mismatch, the
// correct request still spends the ticket, and only then is a replay rejected.
{
  const cache = new JtiReplayCache();
  const token = mint({ jti: "guarded" });
  assert.throws(
    () => verifyRequestTicket({ token, nodeId: NODE, publicKey, request: otherRequest, now: 1010, replay: cache }),
    /does not match/,
  );
  const ok = verifyRequestTicket({ token, nodeId: NODE, publicKey, request, now: 1010, replay: cache });
  assert.equal(ok.claims.jti, "guarded", "a valid request still spends the ticket after a failed mismatch");
  assert.throws(
    () => verifyRequestTicket({ token, nodeId: NODE, publicKey, request, now: 1010, replay: cache }),
    /replay/,
  );
  checks += 2;
}

console.log(
  `request-ticket.test.ts: ${checks} checks passed — ticket bound to node + request; jti consumed last`,
);
