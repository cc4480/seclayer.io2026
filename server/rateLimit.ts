import type { Request, Response, NextFunction } from 'express';

// Rate limiting with a PLUGGABLE store so the same middleware works both on a
// single node (default: in-memory) and across a horizontally-scaled fleet
// (wire a shared Redis store at boot via setRateLimitStore). The middleware API
// is unchanged — every call site still does `rateLimit({ windowMs, max,
// keyPrefix })` and gets an Express middleware.

// A rate-limit backend. `hit` records one request against `key` within a
// `windowMs` sliding window capped at `max`, and reports whether THIS request
// is over the limit (and, if so, how many seconds until it would be allowed).
// Async so a networked store (Redis) can back it; the in-memory store resolves
// synchronously.
export interface RateLimitStore {
  hit(key: string, windowMs: number, max: number): Promise<{ limited: boolean; retryAfterSec: number }>;
}

interface Bucket {
  hits: number[];
}

// Default single-node store: a minimal in-memory sliding window. State lives in
// this process only — correct for one instance, but N instances each keep their
// own buckets, so the effective limit becomes N×max. Swap for a shared store
// (Redis) via setRateLimitStore when running more than one instance.
export class MemoryRateLimitStore implements RateLimitStore {
  private buckets = new Map<string, Bucket>();

  constructor() {
    // Periodically evict buckets with no recent hits so the map can't grow
    // unbounded. unref so it never keeps the process (or a test) alive.
    setInterval(() => {
      const now = Date.now();
      for (const [key, bucket] of this.buckets) {
        if (bucket.hits.every((t) => now - t > 60 * 60 * 1000)) this.buckets.delete(key);
      }
    }, 10 * 60 * 1000).unref();
  }

  async hit(key: string, windowMs: number, max: number): Promise<{ limited: boolean; retryAfterSec: number }> {
    const now = Date.now();
    const bucket = this.buckets.get(key) || { hits: [] };
    bucket.hits = bucket.hits.filter((t) => now - t < windowMs);

    if (bucket.hits.length >= max) {
      const retryAfterSec = Math.ceil((windowMs - (now - bucket.hits[0])) / 1000);
      return { limited: true, retryAfterSec };
    }
    bucket.hits.push(now);
    this.buckets.set(key, bucket);
    return { limited: false, retryAfterSec: 0 };
  }
}

// A shared/networked store (Redis) implements the same interface — drop-in via
// setRateLimitStore at boot. Sketch of a Redis-backed sliding window using a
// sorted set per key (needs a redis client; test against a real Redis before
// relying on it):
//
//   class RedisRateLimitStore implements RateLimitStore {
//     constructor(private redis: RedisClient) {}
//     async hit(key, windowMs, max) {
//       const now = Date.now(), zkey = `rl:${key}`;
//       const m = this.redis.multi();
//       m.zremrangebyscore(zkey, 0, now - windowMs);   // drop hits outside the window
//       m.zcard(zkey);                                 // count in-window BEFORE adding
//       m.zadd(zkey, now, `${now}-${Math.random()}`);  // record this hit
//       m.pexpire(zkey, windowMs);                     // let the key self-expire
//       const res = await m.exec();
//       const count = Number(res[1]);
//       if (count >= max) { await this.redis.zrem(zkey, /* the member just added */); return { limited: true, retryAfterSec: ... }; }
//       return { limited: false, retryAfterSec: 0 };
//     }
//   }

let activeStore: RateLimitStore = new MemoryRateLimitStore();

// Swap the rate-limit backend (e.g. to a Redis store) at boot, BEFORE any route
// middleware is created. Returns the previous store (handy for tests).
export function setRateLimitStore(store: RateLimitStore): RateLimitStore {
  const prev = activeStore;
  activeStore = store;
  return prev;
}

// req.ip already resolves X-Forwarded-For correctly per Express's `trust proxy`
// setting (server.ts only trusts it in production, behind our own proxy/LB) —
// reading the header directly here would let any caller spoof a fresh IP on
// every request (a different X-Forwarded-For value each time) and reset their
// own rate-limit bucket at will, in both dev and prod.
function clientIp(req: Request): string {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

export function rateLimit(opts: { windowMs: number; max: number; keyPrefix: string; message?: string }) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const key = `${opts.keyPrefix}:${clientIp(req)}`;
    let result: { limited: boolean; retryAfterSec: number };
    try {
      result = await activeStore.hit(key, opts.windowMs, opts.max);
    } catch (err) {
      // Fail OPEN on a store error (e.g. a Redis blip): availability of the API
      // matters more than strict limiting, and a shared-store outage must not
      // 500 every request. Logged so the outage is visible.
      console.warn('[rateLimit] store error — allowing request:', (err as any)?.message || err);
      return next();
    }

    if (result.limited) {
      res.setHeader('Retry-After', String(result.retryAfterSec));
      return res.status(429).json({
        status: 'error',
        message: opts.message || 'Too many requests. Please slow down and try again shortly.',
      });
    }
    next();
  };
}
