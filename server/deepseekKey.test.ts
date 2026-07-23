import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');
const { resolveApiKey } = await import('./deepseekClient.js');
const { registerAccountRoutes } = await import('./routes/account.js');

test('resolveApiKey: a per-user override wins over the env key; falls back to env, then null', () => {
  const prev = process.env.DEEPSEEK_API_KEY;
  try {
    process.env.DEEPSEEK_API_KEY = 'sk-env-key-000000000000';
    assert.equal(resolveApiKey('sk-user-key-1111111111'), 'sk-user-key-1111111111', 'override wins');
    assert.equal(resolveApiKey(), 'sk-env-key-000000000000', 'falls back to env');
    assert.equal(resolveApiKey('   '), 'sk-env-key-000000000000', 'blank override is ignored');

    delete process.env.DEEPSEEK_API_KEY;
    assert.equal(resolveApiKey(), null, 'null when neither is set');
    assert.equal(resolveApiKey('sk-user-key-2222222222'), 'sk-user-key-2222222222', 'override works with no env key');
  } finally {
    if (prev === undefined) delete process.env.DEEPSEEK_API_KEY; else process.env.DEEPSEEK_API_KEY = prev;
  }
});

test('db: set / get / clear a user DeepSeek key (trimmed, never surfaced on the User)', () => {
  const u = db.getOrCreateUser(`ds-${Date.now()}@test.io`);
  assert.equal(db.getUserDeepseekKey(u.id), null, 'none by default');

  db.setUserDeepseekKey(u.id, '  sk-abcdefghijklmnopqrst  ');
  assert.equal(db.getUserDeepseekKey(u.id), 'sk-abcdefghijklmnopqrst', 'stored trimmed');
  // The raw key must never appear on the client-facing User object.
  assert.equal((db.getUser(u.id) as any).deepseekApiKey, undefined, 'never leaked via getUser');

  db.setUserDeepseekKey(u.id, '');
  assert.equal(db.getUserDeepseekKey(u.id), null, 'empty string clears it');
});

async function withAccountApp(userId: string, fn: (base: string) => Promise<void>) {
  const app = express();
  app.use(express.json());
  registerAccountRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = userId; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: () => {},
    cookieOptions: { httpOnly: true },
    sessionCookie: 'sl_session',
  });
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('PUT /api/user/deepseek-key sets a key (masked preview, raw never returned), rejects junk, and clears', async () => {
  const u = db.getOrCreateUser(`ds-route-${Date.now()}@test.io`);
  await withAccountApp(u.id, async (base) => {
    const rawKey = 'sk-1234567890abcdefghijklmnop';

    const set = await fetch(`${base}/api/user/deepseek-key`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: rawKey }),
    });
    assert.equal(set.status, 200);
    const body = await set.json();
    assert.equal(body.deepseekKeySet, true);
    assert.ok(body.deepseekKeyPreview && body.deepseekKeyPreview !== rawKey, 'a masked preview, not the raw key');
    assert.ok(!JSON.stringify(body).includes(rawKey), 'the raw key is never in the response');
    assert.equal(db.getUserDeepseekKey(u.id), rawKey, 'the raw key is stored server-side');

    // Junk key rejected, existing key untouched.
    const bad = await fetch(`${base}/api/user/deepseek-key`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: 'nope has spaces' }),
    });
    assert.equal(bad.status, 400);
    assert.equal(db.getUserDeepseekKey(u.id), rawKey, 'a rejected update does not change the stored key');

    // Clear it.
    const clear = await fetch(`${base}/api/user/deepseek-key`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: '' }),
    });
    assert.equal(clear.status, 200);
    assert.equal((await clear.json()).deepseekKeySet, false);
    assert.equal(db.getUserDeepseekKey(u.id), null);
  });
});
