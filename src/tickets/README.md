# Routing tickets (node side)

`paseto.ts`, `ticket.ts`, and `test-vectors/tickets.vectors.json` are **mirrors**
of the orchestrator's `consensus/server/features/tickets/`. The PASETO v4.public
wire format is locked by the shared vectors; `src/tests/tickets.test.ts` verifies
them under Bun to prove this runtime is byte-compatible with the orchestrator.

Do **not** edit `paseto.ts` / `ticket.ts` here independently. If the orchestrator
implementation changes, re-copy these files plus the regenerated vectors, then
run `bun run test:tickets`. (`paseto.ts` is byte-identical to the server;
`ticket.ts` differs only in using an extensionless relative import.)

`replay.ts` and `verifier.ts` are node-only — the `jti` single-use cache and the
verify wrapper that combines the mirrored verifier with replay protection.

Canonical reference: https://docs.consensus.canister.software/protocol/architecture/
