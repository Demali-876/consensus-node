// Single-use cache for routing-ticket `jti`s. In-memory with TTL = ticket exp.
// A node restart loses it, but tickets are short-lived so the replay window is
// bounded by their expiry. Node-only (not part of the mirrored ticket core).

export class JtiReplayCache {
  private readonly seen = new Map<string, number>(); // jti -> exp (unix seconds)
  private lastSweep = 0;

  constructor(private readonly maxEntries = 100_000) {}

  /** Record `jti` as used. Returns true if fresh, false if already seen. */
  consume(jti: string, expSec: number, nowSec: number): boolean {
    this.sweep(nowSec);
    if (this.seen.has(jti)) return false;
    if (this.seen.size >= this.maxEntries) this.sweep(nowSec, true);
    this.seen.set(jti, expSec);
    return true;
  }

  get size(): number {
    return this.seen.size;
  }

  private sweep(nowSec: number, force = false): void {
    if (!force && nowSec - this.lastSweep < 30) return;
    this.lastSweep = nowSec;
    for (const [jti, exp] of this.seen) {
      if (exp <= nowSec) this.seen.delete(jti);
    }
  }
}
