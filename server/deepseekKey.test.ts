import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
// The per-user key is sealed at rest (dbCrypto.sealSecret), so storing one now
// requires a configured key. Set before the db module is imported.
process.env.ENCRYPTION_KEY = (await import('node:crypto')).randomBytes(32).toString('base64');
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

test('db: set / get / clear a user DeepSeek key (trimmed, never surfaced on the User)', async () => {
  const u = (await db.getOrCreateUser(`ds-${Date.now()}@test.io`));
  assert.equal((await db.getUserDeepseekKey(u.id)), null, 'none by default');

  (await db.setUserDeepseekKey(u.id, '  sk-abcdefghijklmnopqrst  '));
  assert.equal((await db.getUserDeepseekKey(u.id)), 'sk-abcdefghijklmnopqrst', 'stored trimmed');
  // The raw key must never appear on the client-facing User object.
  assert.equal(((await db.getUser(u.id)) as any).deepseekApiKey, undefined, 'never leaked via getUser');

  (await db.setUserDeepseekKey(u.id, ''));
  assert.equal((await db.getUserDeepseekKey(u.id)), null, 'empty string clears it');
});

async function withAccountApp(userId: string, fn: (base: string) => Promise<void>) {
  const app = express();
  app.use(express.json());
  registerAccountRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = userId; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: () => {},
    processNmapScanJob: () => {},
    nmapAvailable: false,
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
  const u = (await db.getOrCreateUser(`ds-route-${Date.now()}@test.io`));
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
    assert.equal((await db.getUserDeepseekKey(u.id)), rawKey, 'the raw key round-trips server-side');
    // ...but the column itself must hold ciphertext, not the key. This is the
    // whole point: a database dump must not yield a billable DeepSeek key.
    const atRest = (db as any).db?.prepare?.('SELECT deepseekApiKey FROM users WHERE id = ?').get(u.id)?.deepseekApiKey;
    if (atRest) {
      assert.ok(!String(atRest).includes(rawKey), 'the column holds ciphertext, not the raw key');
      assert.ok(String(atRest).startsWith('enc.v1.'), 'sealed with the versioned format');
    }

    // Junk key rejected, existing key untouched.
    const bad = await fetch(`${base}/api/user/deepseek-key`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: 'nope has spaces' }),
    });
    assert.equal(bad.status, 400);
    assert.equal((await db.getUserDeepseekKey(u.id)), rawKey, 'a rejected update does not change the stored key');

    // Clear it.
    const clear = await fetch(`${base}/api/user/deepseek-key`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: '' }),
    });
    assert.equal(clear.status, 200);
    assert.equal((await clear.json()).deepseekKeySet, false);
    assert.equal((await db.getUserDeepseekKey(u.id)), null);
  });
});

test('PUT /api/user/deepseek-key refuses to store a key when the server has no ENCRYPTION_KEY', async () => {
  const u = (await db.getOrCreateUser(`ds-noenc-${Date.now()}@test.io`));
  const prev = process.env.ENCRYPTION_KEY;
  delete process.env.ENCRYPTION_KEY;
  try {
    await withAccountApp(u.id, async (base) => {
      const res = await fetch(`${base}/api/user/deepseek-key`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: 'sk-1234567890abcdefghijklmnop' }),
      });
      // 503, not a 500 from the crypto layer and not a silent plaintext write.
      assert.equal(res.status, 503);
      assert.equal((await db.getUserDeepseekKey(u.id)), null, 'nothing was stored');

      // Clearing must still work, so a user is never stuck with a key they
      // cannot remove after the server loses its encryption key.
      const clear = await fetch(`${base}/api/user/deepseek-key`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: '' }),
      });
      assert.equal(clear.status, 200);
    });
  } finally {
    if (prev === undefined) delete process.env.ENCRYPTION_KEY;
    else process.env.ENCRYPTION_KEY = prev;
  }
});
