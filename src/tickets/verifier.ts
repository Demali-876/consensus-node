// Node-side routing-ticket verification: the orchestrator's signed-ticket
// contract (mirrored ./ticket, locked by ./test-vectors/tickets.vectors.json)
// plus jti replay protection. The orchestrator's public key is pinned at
// registration (./orchestrator-key.ts → loadPinnedOrchestratorKey); pass it in here.

import type { KeyObject } from 'node:crypto';
import { verifyTicket, type VerifiedTicket, type VerifyTicketOptions } from './ticket';
import type { JtiReplayCache } from './replay';

export interface VerifyRoutingTicketOptions extends VerifyTicketOptions {
  replay?: JtiReplayCache;
}

export function verifyRoutingTicket(
  token: string,
  publicKey: KeyObject,
  opts: VerifyRoutingTicketOptions,
): VerifiedTicket {
  const verified = verifyTicket(token, publicKey, opts);
  if (opts.replay) {
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (!opts.replay.consume(verified.claims.jti, verified.claims.exp, now)) {
      throw new Error('ticket: replayed jti');
    }
  }
  return verified;
}
