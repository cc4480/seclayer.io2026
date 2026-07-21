import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { rateLimit } from './rateLimit.js';

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
