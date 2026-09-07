import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { rateLimit, setRateLimitStore, MemoryRateLimitStore, type RateLimitStore } from './rateLimit.js';

async function withApp(app: express.Express, fn: (base: string) => Promise<void>) {
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('rate limiter blocks after the configured max from a single real client', async () => {
  const app = express();
  app.use(rateLimit({ windowMs: 60_000, max: 3, keyPrefix: 'test-basic' }));
  app.get('/ping', (_req, res) => res.json({ ok: true }));

  await withApp(app, async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${base}/ping`);
      statuses.push(res.status);
    }
    assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
  });
});

test('a spoofed X-Forwarded-For must not let a client reset its own bucket', async () => {
  // Regression test: rateLimit used to key its bucket on the client-supplied
  // X-Forwarded-For header unconditionally, regardless of whether the app
  // actually sits behind a trusted proxy (Express's `trust proxy` is off by
  // default, matching this app's non-prod configuration). A caller could send
  // a different fake IP on every request and get a fresh bucket every time,
  // defeating the limiter entirely — e.g. unlimited magic-link email sends or
  // unlimited scan launches. It must now key on req.ip, which without `trust
  // proxy` configured ignores the header and reflects the real socket.
  const app = express();
  app.use(rateLimit({ windowMs: 60_000, max: 3, keyPrefix: 'test-spoof' }));
  app.get('/ping', (_req, res) => res.json({ ok: true }));

  await withApp(app, async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      const res = await fetch(`${base}/ping`, {
        // A different spoofed source IP on every single request.
        headers: { 'X-Forwarded-For': `10.0.0.${i}` },
      });
      statuses.push(res.status);
    }
    assert.deepEqual(
      statuses,
      [200, 200, 200, 429, 429, 429],
      'a spoofed X-Forwarded-For must not reset the limiter — every request came from the same real client'
    );
  });
});

test('two distinct real clients (different keyPrefix scopes) get independent buckets', async () => {
  const app = express();
  app.use('/a', rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'test-scope-a' }));
  app.use('/b', rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'test-scope-b' }));
  app.get('/a', (_req, res) => res.json({ ok: true }));
  app.get('/b', (_req, res) => res.json({ ok: true }));

  await withApp(app, async (base) => {
    const a1 = await fetch(`${base}/a`);
    const b1 = await fetch(`${base}/b`);
    const a2 = await fetch(`${base}/a`);
    assert.equal(a1.status, 200);
    assert.equal(b1.status, 200, 'a different route/limiter scope must not be affected by /a\'s bucket');
    assert.equal(a2.status, 429);
  });
});

// Direct middleware invocation with mock req/res/next — verifies the middleware
// WIRING (store dispatch, 429 response, Retry-After, store-swap, fail-open)
// without a network listener, so it runs independently of the HTTP tests above.
function invoke(mw: ReturnType<typeof rateLimit>, ip = '9.9.9.9') {
  const req: any = { ip, socket: {}, headers: {} };
  let statusCode = 200; let jsonBody: any; const headers: Record<string, string> = {};
  const res: any = {
    setHeader: (k: string, v: string) => { headers[k.toLowerCase()] = v; },
    status: (c: number) => { statusCode = c; return res; },
    json: (b: any) => { jsonBody = b; return res; },
  };
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  return Promise.resolve(mw(req, res, next)).then(() => ({ statusCode, jsonBody, headers, nextCalled }));
}

test('setRateLimitStore swaps the backend — a shared store (e.g. Redis) drives the limit', async () => {
  // A stand-in "shared store": counts hits per key in one place, exactly as a
  // Redis store would across a fleet. Proves the middleware defers to whatever
  // store is installed rather than its own in-process Map.
  const counts = new Map<string, number>();
  const sharedStore: RateLimitStore = {
    async hit(key, _windowMs, max) {
      const n = (counts.get(key) || 0) + 1;
      counts.set(key, n);
      return n > max ? { limited: true, retryAfterSec: 42 } : { limited: false, retryAfterSec: 0 };
    },
  };
  const prev = setRateLimitStore(sharedStore);
  try {
    const mw = rateLimit({ windowMs: 60_000, max: 2, keyPrefix: 'test-shared' });
    const r1 = await invoke(mw); assert.equal(r1.nextCalled, true);
    const r2 = await invoke(mw); assert.equal(r2.nextCalled, true);
    const r3 = await invoke(mw);
    assert.equal(r3.nextCalled, false, 'the 3rd request is over the shared-store limit');
    assert.equal(r3.statusCode, 429);
    assert.equal(r3.headers['retry-after'], '42', 'Retry-After comes from the store result');
  } finally {
    setRateLimitStore(prev); // restore global state for other tests
  }
});

test('a store error fails OPEN (a Redis blip must not 500 every request)', async () => {
  const brokenStore: RateLimitStore = { async hit() { throw new Error('redis down'); } };
  const prev = setRateLimitStore(brokenStore);
  try {
    const mw = rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'test-broken' });
    for (let i = 0; i < 3; i++) {
      const r = await invoke(mw);
      assert.equal(r.nextCalled, true, 'requests pass through when the store errors');
      assert.equal(r.statusCode, 200);
    }
  } finally {
    setRateLimitStore(prev);
  }
});

test('MemoryRateLimitStore is the default and enforces the window directly', async () => {
  const store = new MemoryRateLimitStore();
  assert.deepEqual(await store.hit('k', 60_000, 2), { limited: false, retryAfterSec: 0 });
  assert.deepEqual(await store.hit('k', 60_000, 2), { limited: false, retryAfterSec: 0 });
  const third = await store.hit('k', 60_000, 2);
  assert.equal(third.limited, true);
  assert.ok(third.retryAfterSec > 0);
});

// The attack an IP-keyed limiter cannot see: one mailbox, many source IPs.
// A caller on CGNAT or mobile egresses from several addresses, so each gets its
// own IP bucket and the target inbox absorbs the sum of all of them.
test('keyFrom buckets on the mailbox, so rotating source IPs do not multiply the allowance', async () => {
  const prev = setRateLimitStore(new MemoryRateLimitStore());
  try {
    const mw = rateLimit({ windowMs: 60_000, max: 2, keyPrefix: 'auth-email',
      keyFrom: (req: any) => String(req.body.email).toLowerCase().trim() });
    const run = async (ip: string, email: string) => {
      let status = 200;
      const res: any = { setHeader() {}, status(c: number) { status = c; return res; }, json() { return res; } };
      await mw({ ip, body: { email }, socket: {} } as any, res, () => {});
      return status;
    };
    // Same mailbox, a different source IP every time.
    assert.equal(await run('1.1.1.1', 'victim@example.com'), 200);
    assert.equal(await run('2.2.2.2', 'victim@example.com'), 200);
    assert.equal(await run('3.3.3.3', 'victim@example.com'), 429, 'a new IP must not buy a fresh allowance for the same mailbox');
    // Casing and whitespace must not open a second bucket for one address.
    assert.equal(await run('4.4.4.4', '  VICTIM@Example.com  '), 429);
    // A different mailbox is genuinely a different bucket.
    assert.equal(await run('1.1.1.1', 'someone-else@example.com'), 200);
  } finally { setRateLimitStore(prev); }
});

test('keyFrom returning undefined skips limiting rather than bucketing everyone together', async () => {
  const prev = setRateLimitStore(new MemoryRateLimitStore());
  try {
    // A request with no email has no identity to bucket on. Falling back to a
    // shared constant key would let one malformed request exhaust the limit for
    // everybody; the handler's own validation rejects these anyway.
    const mw = rateLimit({ windowMs: 60_000, max: 1, keyPrefix: 'auth-email',
      keyFrom: (req: any) => (req.body.email ? String(req.body.email) : undefined) });
    let nexted = 0;
    const res: any = { setHeader() {}, status() { return res; }, json() { return res; } };
    for (let i = 0; i < 5; i++) await mw({ ip: '1.1.1.1', body: {}, socket: {} } as any, res, () => { nexted++; });
    assert.equal(nexted, 5, 'identity-less requests must pass through, not consume a shared bucket');
  } finally { setRateLimitStore(prev); }
});
