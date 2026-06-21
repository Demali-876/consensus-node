// Request-bound ticket verification for the node data plane. Combines the signed
// routing ticket (verified against the orchestrator key pinned at registration)
// with the request itself: the node recomputes the dedupe key from the incoming
// request and checks it equals the ticket's `sub`, so a ticket can only be spent
// on the exact request it was issued for.
//
// The single-use jti is consumed LAST — only after signature, claims, and the
// request binding all pass — so a mismatched (or otherwise rejected) request can
// never burn a still-valid ticket.

import type { KeyObject } from "node:crypto";
import { verifyTicket, type TicketClaims } from "./ticket";
import type { JtiReplayCache } from "./replay";
import { generateDedupeKey, type DedupeParams } from "../runtime/dedupe";

export interface VerifyRequestTicketOptions {
  token: string;
  nodeId: string;
  publicKey: KeyObject; // orchestrator key pinned at registration (Step 8)
  request: DedupeParams; // the incoming proxy request to bind against
  replay?: JtiReplayCache;
  expectedScope?: string;
  now?: number;
  clockToleranceSec?: number;
}

export interface VerifiedRequestTicket {
  claims: TicketClaims;
  kid: string | null;
  dedupeKey: string;
}

export function verifyRequestTicket(opts: VerifyRequestTicketOptions): VerifiedRequestTicket {
  // Signature + claims (issuer, aud == node_id, scope, exp/iat, jti, sub present).
  const { claims, kid } = verifyTicket(opts.token, opts.publicKey, {
    expectedNodeId: opts.nodeId,
    expectedScope: opts.expectedScope,
    now: opts.now,
    clockToleranceSec: opts.clockToleranceSec,
  });

  // Request binding: the node recomputes the dedupe key and matches it to `sub`.
  const dedupeKey = generateDedupeKey(opts.request);
  if (dedupeKey !== claims.sub) {
    throw new Error("ticket: request does not match ticket binding (dedupe_key)");
  }

  // Commit the single-use jti only after everything else has passed.
  if (opts.replay) {
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (!opts.replay.consume(claims.jti, claims.exp, now)) {
      throw new Error("ticket: replayed jti");
    }
  }

  return { claims, kid, dedupeKey };
}
