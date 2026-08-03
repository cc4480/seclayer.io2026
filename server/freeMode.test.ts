import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

// This whole file exercises FREE_MODE — scans require no credits. config.freeMode
// is read once at import time, so it must be set before importing anything that
// pulls in config. (The paid-flow suites pin FREE_MODE=false the same way.)
process.env.DB_PATH = ':memory:';
process.env.FREE_MODE = 'true';
const { db } = await import('./db.js');
const { registerScanRoutes } = await import('./routes/scans.js');
const { runDueMonitoredScans } = await import('./monitorWorker.js');

// Literal public IP: passes the SSRF guard with no DNS lookup.
const SAFE_TARGET = 'https://93.184.216.34';

async function withScanApp(userId: string, fn: (base: string) => Promise<void>) {
  const app = express();
  app.use(express.json());
  let launched = 0;
  registerScanRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = userId; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: () => { launched++; },
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
  return () => launched;
}

test('free mode: a scan launches with zero credits and deducts nothing', async () => {
  const u = db.getOrCreateUser(`free-scan-${Date.now()}@test.io`);
  db.deductCredits(u.id, db.getUser(u.id)!.credits); // spend down to 0
  assert.equal(db.getUser(u.id)!.credits, 0);

  await withScanApp(u.id, async (base) => {
    const res = await fetch(`${base}/api/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 200, 'a 0-credit user can scan for free');
    const data = await res.json();
    assert.ok(data.scan?.id, 'a scan was created');
  });

  assert.equal(db.getUser(u.id)!.credits, 0, 'no credit was deducted in free mode');
  assert.equal(db.listScans(u.id).length, 1);
});

test('free mode: the monitoring worker scans a due target with zero credits, no error recorded', async () => {
  const u = db.getOrCreateUser(`free-monitor-${Date.now()}@test.io`);
  db.deductCredits(u.id, db.getUser(u.id)!.credits); // 0 credits
  const target = db.addMonitoredTarget(u.id, SAFE_TARGET, 7);
  db.markMonitoredScanned(target.id, new Date(Date.now() - 1000).toISOString(), new Date(Date.now() - 1000).toISOString());

  let launched = false;
  await runDueMonitoredScans(() => { launched = true; });

  assert.equal(launched, true, 'a due target scans even at 0 credits in free mode');
  assert.equal(db.getUser(u.id)!.credits, 0, 'no credit spent');
  assert.equal(db.listScans(u.id).length, 1);
  const updated = db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!;
  assert.ok(!updated.lastError, 'no insufficient-credits error in free mode');
});

test('validateApiKey resolves an active key without touching credits, and rejects an inactive one', async () => {
  const u = db.getOrCreateUser(`free-key-${Date.now()}@test.io`);
  const { rawKey, apiKey } = db.generateApiKey(u.id);
  const before = db.getUser(u.id)!.credits;

  const resolved = db.validateApiKey(rawKey);
  assert.ok(resolved, 'active key resolves to its owner');
  assert.equal(resolved!.id, u.id);
  assert.equal(db.getUser(u.id)!.credits, before, 'validateApiKey never deducts');

  assert.equal(db.validateApiKey('sl_live_not_a_real_key'), null, 'unknown key rejected');
  db.revokeApiKey(u.id, apiKey.id);
  assert.equal(db.validateApiKey(rawKey), null, 'revoked key rejected');
});
