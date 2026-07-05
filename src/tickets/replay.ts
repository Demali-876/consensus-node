// Single-use cache for routing-ticket `jti`s. In-memory with TTL = ticket exp.
// A node restart loses it, but tickets are short-lived so the replay window is
// bounded by their expiry. Node-only (not part of the mirrored ticket core).

// How often the janitor sweep is allowed to walk the whole map dropping expired
// entries. It is a memory-reclaim nicety, NOT a correctness mechanism: the
// eviction loop in consume() is what enforces the bound, so a skipped sweep can
// never let the map grow past maxEntries. Kept off the per-insert hot path.
const SWEEP_INTERVAL_SEC = 30;

export class JtiReplayCache {
  private readonly seen = new Map<string, number>(); // jti -> exp (unix seconds)
  private lastSweep = 0;

  constructor(private readonly maxEntries = 100_000) {}

  /** Record `jti` as used. Returns true if fresh, false if already seen. */
  consume(jti: string, expSec: number, nowSec: number): boolean {
    this.sweep(nowSec);
    if (this.seen.has(jti)) return false;
    // At capacity, evict oldest-first until back under the bound. A Map iterates
    // in insertion order, so keys().next() is the oldest jti — and because every
    // ticket carries the same TTL, oldest-by-insertion is also soonest-to-expire
    // (smallest residual replay window), which is exactly the entry we want to
    // shed. Eviction is O(1) per dropped entry and needs no scan, so inserts stay
    // O(1) amortized even when the cache is full of still-unexpired entries and
    // the periodic sweep would free nothing. (Filling the cache requires that
    // many valid signed tickets, which the orchestrator only issues against
    // payment, so this path is bounded.)
    while (this.seen.size >= this.maxEntries) {
      const oldest = this.seen.keys().next().value;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
    this.seen.set(jti, expSec);
    return true;
  }

  get size(): number {
    return this.seen.size;
  }

  // Periodic janitor: drop expired entries so memory is reclaimed at below-
  // capacity load. Gated to once per SWEEP_INTERVAL_SEC — the O(n) walk is
  // amortized to near-zero per insert, and eviction (not this sweep) enforces
  // maxEntries, so a skipped sweep never breaks the bound.
  private sweep(nowSec: number): void {
    if (nowSec - this.lastSweep < SWEEP_INTERVAL_SEC) return;
    this.lastSweep = nowSec;
    for (const [jti, exp] of this.seen) {
      if (exp <= nowSec) this.seen.delete(jti);
    }
  }
}
