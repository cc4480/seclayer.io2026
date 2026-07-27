import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
process.env.FREE_MODE = 'false'; // these suites exercise the paid credit flow
const { db } = await import('../db.js');
const { registerAccountRoutes } = await import('./account.js');

// A literal public IP passes the SSRF guard with no DNS lookup, so these
// tests don't depend on real network access.
const SAFE_TARGET = 'https://93.184.216.34';
const UNSAFE_TARGET = 'http://169.254.169.254/latest/meta-data/';

async function withAccountApp(
  fn: (base: string, userId: string) => Promise<void>,
  opts: { processScanJob?: (scanId: string, allowActiveProbes: boolean) => void } = {},
) {
  const user = db.getOrCreateUser(`account-${Date.now()}-${Math.random()}@test.io`);

  const app = express();
  app.use(express.json());
  registerAccountRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = user.id; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: opts.processScanJob || (() => {}),
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

async function addTarget(base: string, url = SAFE_TARGET): Promise<string> {
  const res = await fetch(`${base}/api/monitoring`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
  });
  assert.equal(res.status, 200);
  return (await res.json()).target.id;
}

test('PATCH /api/monitoring/:id pauses and resumes a target (and pausing removes it from the due set)', async () => {
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    // Backdate so it would be due if not paused.
    const past = new Date(Date.now() - 1000).toISOString();
    db.markMonitoredScanned(id, past, past);
    assert.ok(db.listDueMonitoredTargets(new Date().toISOString()).some((t) => t.id === id), 'due before pausing');

    const pause = await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paused: true }),
    });
    assert.equal(pause.status, 200);
    assert.equal(db.getMonitoredTarget(userId, id)!.paused, true);
    assert.equal(db.listDueMonitoredTargets(new Date().toISOString()).some((t) => t.id === id), false, 'paused target is not due');

    const resume = await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paused: false }),
    });
    assert.equal(resume.status, 200);
    assert.equal(db.getMonitoredTarget(userId, id)!.paused, false);
    assert.ok(db.listDueMonitoredTargets(new Date().toISOString()).some((t) => t.id === id), 'due again after resume');
  });
});

test('PATCH /api/monitoring/:id rejects a non-boolean and 404s for another user\'s target', async () => {
  const otherUser = db.getOrCreateUser(`account-patch-other-${Date.now()}@test.io`);
  const otherTarget = db.addMonitoredTarget(otherUser.id, SAFE_TARGET, 7);
  await withAccountApp(async (base) => {
    const id = await addTarget(base);
    const bad = await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paused: 'yes' }),
    });
    assert.equal(bad.status, 400);

    const cross = await fetch(`${base}/api/monitoring/${otherTarget.id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ paused: true }),
    });
    assert.equal(cross.status, 404);
  });
  assert.equal(db.getMonitoredTarget(otherUser.id, otherTarget.id)!.paused, false, 'other user\'s target untouched');
});

test('PATCH /api/monitoring/:id edits the cadence and recomputes the next run', async () => {
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    const before = db.getMonitoredTarget(userId, id)!;

    // Change to a weekly Wednesday 06:30 UTC schedule.
    const res = await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ frequencyDays: 7, weekday: 3, hour: 6, minute: 30 }),
    });
    assert.equal(res.status, 200);
    const t = db.getMonitoredTarget(userId, id)!;
    assert.equal(t.frequencyDays, 7);
    assert.equal(t.scanWeekday, 3);
    assert.equal(t.scanHour, 6);
    assert.equal(t.scanMinute, 30);
    // The next automated run must be recomputed (it should differ from the
    // original daily-default schedule) and land in the future.
    assert.notEqual(t.nextScanAt, before.nextScanAt);
    assert.ok(new Date(t.nextScanAt!).getTime() > Date.now());
    // It must fire on the chosen weekday at the chosen UTC time.
    const next = new Date(t.nextScanAt!);
    assert.equal(next.getUTCDay(), 3);
    assert.equal(next.getUTCHours(), 6);
    assert.equal(next.getUTCMinutes(), 30);
  });
});

test('PATCH /api/monitoring/:id merges a partial schedule edit over existing values', async () => {
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    // Set a full schedule first.
    await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ frequencyDays: 7, weekday: 1, hour: 9, minute: 0 }),
    });
    // Now change only the hour; weekday/minute/frequency must be preserved.
    const res = await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hour: 14 }),
    });
    assert.equal(res.status, 200);
    const t = db.getMonitoredTarget(userId, id)!;
    assert.equal(t.scanHour, 14, 'hour changed');
    assert.equal(t.scanWeekday, 1, 'weekday preserved');
    assert.equal(t.scanMinute, 0, 'minute preserved');
    assert.equal(t.frequencyDays, 7, 'frequency preserved');
  });
});

test('PATCH /api/monitoring/:id rejects an out-of-range schedule (400) and 404s across users', async () => {
  const otherUser = db.getOrCreateUser(`account-edit-other-${Date.now()}@test.io`);
  const otherTarget = db.addMonitoredTarget(otherUser.id, SAFE_TARGET, 7);
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    const bad = await fetch(`${base}/api/monitoring/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hour: 25 }),
    });
    assert.equal(bad.status, 400, 'hour 25 is invalid');

    const cross = await fetch(`${base}/api/monitoring/${otherTarget.id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ frequencyDays: 3 }),
    });
    assert.equal(cross.status, 404, "can't edit another user's monitor");
  });
  assert.equal(db.getMonitoredTarget(otherUser.id, otherTarget.id)!.frequencyDays, 7, 'other user\'s schedule untouched');
});

test('POST /api/monitoring/:id/scan-now launches a scan, deducts a credit, and reschedules', async () => {
  const launched: Array<{ scanId: string; allowActiveProbes: boolean }> = [];
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    const creditsBefore = db.getUser(userId)!.credits;

    const res = await fetch(`${base}/api/monitoring/${id}/scan-now`, { method: 'POST' });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.scan?.id, 'returns the created scan');

    assert.equal(db.getUser(userId)!.credits, creditsBefore - 1, 'one credit spent');
    assert.equal(db.listScans(userId).length, 1, 'a scan row was created');
    assert.equal(launched.length, 1, 'the scan job was dispatched');
    assert.equal(launched[0].scanId, data.scan.id);
    // lastScannedAt set; nextScanAt rescheduled into the future.
    const t = db.getMonitoredTarget(userId, id)!;
    assert.ok(t.lastScannedAt, 'lastScannedAt set after scan-now');
    assert.ok(new Date(t.nextScanAt!).getTime() > Date.now(), 'next automated run rescheduled forward');
  }, { processScanJob: (scanId, allowActiveProbes) => { launched.push({ scanId, allowActiveProbes }); } });
});

test('POST /api/monitoring/:id/scan-now returns 402 with no credits and never dispatches a job', async () => {
  let dispatched = 0;
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    db.deductCredits(userId, db.getUser(userId)!.credits); // spend to zero

    const res = await fetch(`${base}/api/monitoring/${id}/scan-now`, { method: 'POST' });
    assert.equal(res.status, 402);
    assert.equal(db.listScans(userId).length, 0, 'no scan created when out of credits');
    assert.equal(dispatched, 0);
  }, { processScanJob: () => { dispatched++; } });
});

test('POST /api/monitoring/:id/scan-now 404s for another user\'s target without spending its owner\'s credit', async () => {
  const otherUser = db.getOrCreateUser(`account-sn-other-${Date.now()}@test.io`);
  const otherTarget = db.addMonitoredTarget(otherUser.id, SAFE_TARGET, 7);
  const otherCreditsBefore = db.getUser(otherUser.id)!.credits;
  await withAccountApp(async (base) => {
    const res = await fetch(`${base}/api/monitoring/${otherTarget.id}/scan-now`, { method: 'POST' });
    assert.equal(res.status, 404);
  });
  assert.equal(db.getUser(otherUser.id)!.credits, otherCreditsBefore, 'other user\'s credits untouched');
});

test('GET /api/monitoring enriches each target with its latest scan', async () => {
  await withAccountApp(async (base, userId) => {
    const id = await addTarget(base);
    // Before any scan: lastScan is null.
    let res = await fetch(`${base}/api/monitoring`);
    let target = (await res.json()).monitoredTargets.find((t: any) => t.id === id);
    assert.equal(target.lastScan, null, 'no lastScan before any scan runs');

    // Create + complete a scan for this target's URL.
    const scan = db.createScan(userId, SAFE_TARGET);
    db.updateScan(scan.id, { status: 'complete', score: 72, severity: 'medium', completedAt: new Date().toISOString() });

    res = await fetch(`${base}/api/monitoring`);
    target = (await res.json()).monitoredTargets.find((t: any) => t.id === id);
    assert.equal(target.lastScan.id, scan.id);
    assert.equal(target.lastScan.status, 'complete');
    assert.equal(target.lastScan.score, 72);
    assert.equal(target.lastScan.severity, 'medium');
  });
});
