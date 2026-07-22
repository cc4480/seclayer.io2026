import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
const { db } = await import('../db.js');
const { registerAccountRoutes } = await import('./account.js');

// A literal public IP passes the SSRF guard with no DNS lookup, so these
// tests don't depend on real network access.
const SAFE_TARGET = 'https://93.184.216.34';
const UNSAFE_TARGET = 'http://169.254.169.254/latest/meta-data/';

async function withAccountApp(fn: (base: string, userId: string) => Promise<void>) {
  const user = db.getOrCreateUser(`account-${Date.now()}-${Math.random()}@test.io`);

  const app = express();
  app.use(express.json());
  registerAccountRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = user.id; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: () => {},
    cookieOptions: { httpOnly: true },
    sessionCookie: 'sl_session',
  });

  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`, user.id);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('POST /api/monitoring rejects an unsafe/internal target', async () => {
  await withAccountApp(async (base, userId) => {
    const res = await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: UNSAFE_TARGET }),
    });
    assert.equal(res.status, 400);
    assert.equal(db.listMonitoredTargets(userId).length, 0, 'no monitor row should be created for a rejected target');
  });
});

test('POST /api/monitoring accepts a valid, safe target', async () => {
  await withAccountApp(async (base, userId) => {
    const res = await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET, frequencyDays: 1 }),
    });
    assert.equal(res.status, 200);
    const targets = db.listMonitoredTargets(userId);
    assert.equal(targets.length, 1);
    assert.equal(targets[0].url, SAFE_TARGET);
  });
});

test('POST /api/monitoring rejects a duplicate target for the same user (409), regardless of scheme/trailing slash', async () => {
  await withAccountApp(async (base, userId) => {
    const first = await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(first.status, 200);

    const second = await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: `${SAFE_TARGET}/` }), // same host, trailing slash
    });
    assert.equal(second.status, 409);
    assert.equal(db.listMonitoredTargets(userId).length, 1, 'still exactly one monitor for this URL');
  });
});

test('POST /api/monitoring does not dedupe across different users', async () => {
  await withAccountApp(async (base) => {
    const res = await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 200);
  });
  // A second, independent user adding the exact same URL must succeed.
  await withAccountApp(async (base, userId) => {
    const res = await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 200);
    assert.equal(db.listMonitoredTargets(userId).length, 1);
  });
});

test('GET /api/monitoring only returns the caller\'s own targets', async () => {
  const otherUser = db.getOrCreateUser(`account-other-${Date.now()}@test.io`);
  db.addMonitoredTarget(otherUser.id, SAFE_TARGET, 7);

  await withAccountApp(async (base, userId) => {
    await fetch(`${base}/api/monitoring`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://1.1.1.1' }),
    });
    const res = await fetch(`${base}/api/monitoring`);
    const data = await res.json();
    assert.equal(data.monitoredTargets.length, 1);
    assert.notEqual(data.monitoredTargets[0].userId, otherUser.id);
    assert.equal(data.monitoredTargets[0].userId, userId);
  });
});

test('DELETE /api/monitoring/:id 404s for a target owned by someone else', async () => {
  const otherUser = db.getOrCreateUser(`account-del-other-${Date.now()}@test.io`);
  const otherTarget = db.addMonitoredTarget(otherUser.id, SAFE_TARGET, 7);

  await withAccountApp(async (base) => {
    const res = await fetch(`${base}/api/monitoring/${otherTarget.id}`, { method: 'DELETE' });
    assert.equal(res.status, 404);
  });
  assert.equal(db.listMonitoredTargets(otherUser.id).length, 1, 'the other user\'s target must be untouched');
});
