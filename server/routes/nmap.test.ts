import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
process.env.FREE_MODE = 'false'; // exercise the paid credit flow
const { db } = await import('../db.js');
const { registerNmapRoutes } = await import('./nmap.js');

// A literal public IP passes the SSRF guard with no DNS lookup.
const SAFE_TARGET = 'https://93.184.216.34';

async function withNmapApp(
  fn: (base: string, userId: string) => Promise<void>,
  opts: { nmapAvailable?: boolean; verifyDomain?: boolean; processNmapScanJob?: (scanId: string) => void } = {},
) {
  const user = db.getOrCreateUser(`nmap-route-${Date.now()}-${Math.random()}@test.io`);
  if (opts.verifyDomain !== false) {
    db.startDomainVerification(user.id, '93.184.216.34', 'sl-verify-test');
    db.markDomainVerified(user.id, '93.184.216.34');
  }

  const app = express();
  app.use(express.json());
  registerNmapRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = user.id; next(); },
    getUserId: (req) => (req as any).userId,
    processScanJob: () => {},
    processNmapScanJob: opts.processNmapScanJob || (() => {}),
    nmapAvailable: opts.nmapAvailable !== false,
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

test('POST /api/nmap/scans returns 503 when nmap is not available on this deployment', async () => {
  await withNmapApp(async (base) => {
    const res = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 503);
  }, { nmapAvailable: false });
});

test('POST /api/nmap/scans returns 400 for a missing url', async () => {
  await withNmapApp(async (base) => {
    const res = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    });
    assert.equal(res.status, 400);
  });
});

test('POST /api/nmap/scans returns 400 and never creates a scan for an SSRF-unsafe target', async () => {
  await withNmapApp(async (base, userId) => {
    const res = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: 'http://127.0.0.1' }),
    });
    assert.equal(res.status, 400);
    assert.equal(db.listNmapScans(userId).length, 0);
  });
});

test('POST /api/nmap/scans returns 403 and spends no credit when the domain is not verified', async () => {
  await withNmapApp(async (base, userId) => {
    const before = db.getUser(userId)!.credits;
    const res = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 403);
    assert.equal(db.getUser(userId)!.credits, before);
    assert.equal(db.listNmapScans(userId).length, 0);
  }, { verifyDomain: false });
});

test('POST /api/nmap/scans returns 402 and creates no scan when the user has no credits', async () => {
  await withNmapApp(async (base, userId) => {
    db.deductCredits(userId, db.getUser(userId)!.credits);
    const res = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 402);
    assert.equal(db.listNmapScans(userId).length, 0);
  });
});

test('POST /api/nmap/scans launches on the happy path: deducts one credit, creates one queued scan, dispatches the worker', async () => {
  let dispatchedId: string | null = null;
  await withNmapApp(async (base, userId) => {
    const before = db.getUser(userId)!.credits;
    const res = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.scan.status, 'queued');
    assert.equal(db.getUser(userId)!.credits, before - 1);
    assert.equal(db.listNmapScans(userId).length, 1);
    assert.equal(dispatchedId, body.scan.id);
  }, { processNmapScanJob: (scanId) => { dispatchedId = scanId; } });
});

test('POST /api/nmap/scans returns 409 and spends no extra credit when a scan is already in flight', async () => {
  await withNmapApp(async (base, userId) => {
    const first = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(first.status, 200);
    const afterFirst = db.getUser(userId)!.credits;

    const second = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(second.status, 409);
    assert.equal(db.getUser(userId)!.credits, afterFirst, 'the second (rejected) attempt must not spend a credit');
    assert.equal(db.listNmapScans(userId).length, 1);
  });
});

test('GET /api/nmap/scans lists only the caller\'s own scans', async () => {
  await withNmapApp(async (base, userId) => {
    await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    const other = db.getOrCreateUser(`nmap-other-${Date.now()}@test.io`);
    db.createNmapScan(other.id, 'https://not-mine.test');

    const res = await fetch(`${base}/api/nmap/scans`);
    const body = await res.json();
    assert.equal(body.scans.length, 1);
    assert.equal(body.scans[0].userId, userId);
  });
});

test('GET /api/nmap/scans/:id 404s for a scan owned by someone else', async () => {
  await withNmapApp(async (base) => {
    const other = db.getOrCreateUser(`nmap-other-owner-${Date.now()}@test.io`);
    const theirScan = db.createNmapScan(other.id, 'https://not-mine.test');

    const res = await fetch(`${base}/api/nmap/scans/${theirScan.id}`);
    assert.equal(res.status, 404);
  });
});

test('POST /api/nmap/scans/:id/cancel refunds the credit and 409s a second attempt', async () => {
  await withNmapApp(async (base, userId) => {
    const launch = await fetch(`${base}/api/nmap/scans`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: SAFE_TARGET }),
    });
    const { scan } = await launch.json();
    const afterLaunch = db.getUser(userId)!.credits;

    const cancel = await fetch(`${base}/api/nmap/scans/${scan.id}/cancel`, { method: 'POST' });
    assert.equal(cancel.status, 200);
    assert.equal(db.getUser(userId)!.credits, afterLaunch + 1);

    const again = await fetch(`${base}/api/nmap/scans/${scan.id}/cancel`, { method: 'POST' });
    assert.equal(again.status, 409);
    assert.equal(db.getUser(userId)!.credits, afterLaunch + 1, 'no double-refund');
  });
});

test('GET /api/nmap/scans/:id/events 404s for a scan owned by someone else', async () => {
  await withNmapApp(async (base) => {
    const other = db.getOrCreateUser(`nmap-events-owner-${Date.now()}@test.io`);
    const theirScan = db.createNmapScan(other.id, 'https://not-mine.test');

    const res = await fetch(`${base}/api/nmap/scans/${theirScan.id}/events`);
    assert.equal(res.status, 404);
  });
});

test('POST /api/nmap/scans is rate-limited per caller', async () => {
  // Declared LAST: the launch route's rate limiter buckets by IP (all local
  // test requests share 127.0.0.1), so this deliberately exhausts whatever
  // budget the tests above it left in the shared bucket, then keeps sending
  // well past the limit — same pattern as mcp.test.ts's identical rate-limit
  // test. It doesn't assume a fresh bucket; it only checks the shape of a
  // burst: some requests still reach the handler, then it locks into 429.
  await withNmapApp(async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) {
      const res = await fetch(`${base}/api/nmap/scans`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
      });
      statuses.push(res.status);
    }
    assert.ok(statuses.every((s) => s === 400 || s === 429), `only 400/429 expected; got ${statuses}`);
    const firstLimitedIndex = statuses.indexOf(429);
    assert.ok(firstLimitedIndex !== -1, `the limiter never kicked in across 25 requests; got ${statuses}`);
    assert.ok(statuses.slice(firstLimitedIndex).every((s) => s === 429), `once limited, every subsequent request must stay 429; got ${statuses}`);
  });
});
