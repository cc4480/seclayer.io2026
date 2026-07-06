import type { Request, Response, NextFunction } from 'express';

// Minimal in-memory sliding-window rate limiter. Sufficient for a single-node
// deployment; swap for a shared store (Redis) if scaling horizontally.
interface Bucket {
  hits: number[];
}

const buckets = new Map<string, Bucket>();

function clientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) return fwd.split(',')[0].trim();
  return req.ip || req.socket.remoteAddress || 'unknown';
}

export function rateLimit(opts: { windowMs: number; max: number; keyPrefix: string; message?: string }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${opts.keyPrefix}:${clientIp(req)}`;
    const now = Date.now();
    const bucket = buckets.get(key) || { hits: [] };
    bucket.hits = bucket.hits.filter((t) => now - t < opts.windowMs);

    if (bucket.hits.length >= opts.max) {
      const retryAfter = Math.ceil((opts.windowMs - (now - bucket.hits[0])) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return res.status(429).json({
        status: 'error',
        message: opts.message || 'Too many requests. Please slow down and try again shortly.',
      });
    }

    bucket.hits.push(now);
    buckets.set(key, bucket);
    next();
  };
}

// Periodically evict empty buckets so the map cannot grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (bucket.hits.every((t) => now - t > 60 * 60 * 1000)) buckets.delete(key);
  }
}, 10 * 60 * 1000).unref();
