import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

// Isolated in-memory database, set before importing the db singleton (same
// pattern as db.test.ts) so this file's writes never touch a real data file
// and can't race against other test files.
process.env.DB_PATH = ':memory:';
process.env.FREE_MODE = 'false'; // these suites exercise the paid credit flow
const { db } = await import('../db.js');
const { registerScanRoutes } = await import('./scans.js');

// A literal public IP passes the SSRF guard with no DNS lookup (see
// scanner.test.ts's "assertScanTargetSafe allows a public literal IP"), so
// these tests don't depend on real network access or a live target.
const SAFE_TARGET = 'https://93.184.216.34';

// The concurrency test below needs a target whose SSRF pre-check genuinely
// yields the event loop (a real async DNS lookup via libuv's threadpool, not
// just a microtask), or Node tends to run each request's handler to
// completion before starting the next and the race window never actually
// opens. A literal IP resolves synchronously and doesn't reproduce this.
const HOSTNAME_TARGET = 'https://example.com';

async function withScanApp(fn: (base: string, userId: string) => Promise<void>) {
  const user = db.getOrCreateUser(`race-${Date.now()}-${Math.random()}@test.io`);

  const app = express();
  app.use(express.json());
  registerScanRoutes(app, {
    requireAuth: (req, _res, next) => { (req as any).userId = user.id; next(); },
    getUserId: (req) => (req as any).userId,
    // No-op: these tests check the HTTP-layer credit/creation contract, not
    // the background scan pipeline.
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

test('POST /api/scans deducts exactly one credit and creates exactly one scan on a normal launch', async () => {
  await withScanApp(async (base, userId) => {
    const before = db.getUser(userId)!.credits;
    const res = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 200);
    assert.equal(db.getUser(userId)!.credits, before - 1);
    assert.equal(db.listScans(userId).length, 1);
  });
});

test('POST /api/scans rejects the launch (402) and creates no scan when the user has no credits', async () => {
  await withScanApp(async (base, userId) => {
    db.deductCredits(userId, db.getUser(userId)!.credits); // spend down to 0
    const res = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET }),
    });
    assert.equal(res.status, 402);
    assert.equal(db.listScans(userId).length, 0);
  });
});

test('concurrent launches sharing a single credit produce exactly one scan, not one per request', async () => {
  // Regression test: the route used to check `user.credits < 1` before an
  // `await assertScanTargetSafe(url)` and then call db.deductCredits without
  // checking its return value, so concurrent requests could all pass the
  // stale check and all get a free scan. deductCredits' result must now gate
  // scan creation, and the check must hold under real concurrency.
  await withScanApp(async (base, userId) => {
    db.deductCredits(userId, db.getUser(userId)!.credits - 1); // leave exactly 1 credit
    assert.equal(db.getUser(userId)!.credits, 1);

    const CONCURRENCY = 6;
    const responses = await Promise.all(
      Array.from({ length: CONCURRENCY }, () =>
        fetch(`${base}/api/scans`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: HOSTNAME_TARGET }),
        })
      )
    );
    const statuses = responses.map((r) => r.status).sort();
    const successes = statuses.filter((s) => s === 200);
    const declined = statuses.filter((s) => s === 402);

    assert.equal(successes.length, 1, `exactly one launch should succeed with 1 credit; got statuses ${statuses}`);
    assert.equal(declined.length, CONCURRENCY - 1, 'every other concurrent launch must be declined, not silently granted');
    assert.equal(db.getUser(userId)!.credits, 0, 'the balance must land at exactly 0, never negative');
    assert.equal(db.listScans(userId).length, 1, 'only one scan row may exist — a free scan must never be created');
  });
});

test('POST /api/scans/:id/cancel refunds the credit and marks the scan canceled', async () => {
  await withScanApp(async (base, userId) => {
    const launch = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: SAFE_TARGET }),
    });
    const { scan } = await launch.json();
    const creditsAfterLaunch = db.getUser(userId)!.credits;

    const cancel = await fetch(`${base}/api/scans/${scan.id}/cancel`, { method: 'POST' });
    assert.equal(cancel.status, 200);
    const { scan: canceled } = await cancel.json();
    assert.equal(canceled.status, 'canceled');
    assert.equal(db.getUser(userId)!.credits, creditsAfterLaunch + 1, 'the credit is refunded');

    // Can't cancel it again, and no double-refund.
    const secondCancel = await fetch(`${base}/api/scans/${scan.id}/cancel`, { method: 'POST' });
    assert.equal(secondCancel.status, 409);
    assert.equal(db.getUser(userId)!.credits, creditsAfterLaunch + 1);
  });
});

test('POST /api/scans/:id/cancel 409s for a scan owned by someone else, without leaking existence', async () => {
  await withScanApp(async (base) => {
    const otherUser = db.getOrCreateUser(`cancel-other-${Date.now()}@test.io`);
    const otherScan = db.createScan(otherUser.id, SAFE_TARGET);

    const res = await fetch(`${base}/api/scans/${otherScan.id}/cancel`, { method: 'POST' });
    assert.equal(res.status, 409);
    assert.equal(db.getScan(otherScan.id)!.status, 'queued', 'the other user\'s scan must be untouched');
  });
});

// --- Public shareable report links ---

// Create a completed scan for the harness user and return its id.
function completedScan(userId: string, url = SAFE_TARGET): string {
  const s = db.createScan(userId, url);
  db.updateScan(s.id, {
    status: 'complete', score: 80, severity: 'medium', aiSummary: 'summary',
    findings: [{ id: 'f1', title: 'Missing CSP', description: 'd', severity: 'medium', confidence: 'medium', fix: 'add csp', category: 'IAST' }],
    completedAt: new Date().toISOString(),
  });
  return s.id;
}

test('POST /api/scans/:id/share mints a link; the public report is viewable without auth and sanitized', async () => {
  await withScanApp(async (base, userId) => {
    const scanId = completedScan(userId);
    const shareRes = await fetch(`${base}/api/scans/${scanId}/share`, { method: 'POST' });
    assert.equal(shareRes.status, 200);
    const { shareToken, shareUrl } = await shareRes.json();
    assert.match(shareToken, /^shr_[0-9a-f]{32}$/);
    assert.match(shareUrl, /\/r\/shr_[0-9a-f]{32}$/);

    // Public fetch — no credentials at all.
    const pub = await fetch(`${base}/api/public/report/${shareToken}`);
    assert.equal(pub.status, 200);
    const { report } = await pub.json();
    assert.equal(report.url, SAFE_TARGET);
    assert.equal(report.findings.length, 1);
    // Owner-internal fields must never be exposed on the public payload.
    assert.equal(report.userId, undefined, 'userId must not leak');
    assert.equal(report.authHeader, undefined, 'authHeader must not leak');
    assert.equal(report.shareToken, undefined, 'the token must not be echoed back');
  });
});

test('POST /api/scans/:id/share is idempotent (same token on repeat calls)', async () => {
  await withScanApp(async (base, userId) => {
    const scanId = completedScan(userId);
    const a = await (await fetch(`${base}/api/scans/${scanId}/share`, { method: 'POST' })).json();
    const b = await (await fetch(`${base}/api/scans/${scanId}/share`, { method: 'POST' })).json();
    assert.equal(a.shareToken, b.shareToken, 'repeat share returns the same token, not a new one');
  });
});

test('DELETE /api/scans/:id/share revokes the link so the public URL 404s', async () => {
  await withScanApp(async (base, userId) => {
    const scanId = completedScan(userId);
    const { shareToken } = await (await fetch(`${base}/api/scans/${scanId}/share`, { method: 'POST' })).json();
    assert.equal((await fetch(`${base}/api/public/report/${shareToken}`)).status, 200);

    const del = await fetch(`${base}/api/scans/${scanId}/share`, { method: 'DELETE' });
    assert.equal(del.status, 200);
    assert.equal((await fetch(`${base}/api/public/report/${shareToken}`)).status, 404, 'revoked link no longer resolves');
  });
});

test('GET /api/public/report/:token 404s for an unknown token', async () => {
  await withScanApp(async (base) => {
    const res = await fetch(`${base}/api/public/report/shr_deadbeefdeadbeefdeadbeefdeadbeef`);
    assert.equal(res.status, 404);
  });
});

test('POST /api/scans/:id/share 404s for an incomplete scan and for another user\'s scan', async () => {
  const other = db.getOrCreateUser(`share-other-${Date.now()}@test.io`);
  const otherScanId = completedScan(other.id); // completed, but owned by someone else
  await withScanApp(async (base, userId) => {
    // Incomplete scan of our own → nothing worth sharing.
    const pending = db.createScan(userId, SAFE_TARGET); // status: queued
    const inc = await fetch(`${base}/api/scans/${pending.id}/share`, { method: 'POST' });
    assert.equal(inc.status, 404);

    // Another user's scan → 404 (never mints a token).
    const cross = await fetch(`${base}/api/scans/${otherScanId}/share`, { method: 'POST' });
    assert.equal(cross.status, 404);
    assert.equal(db.getScan(otherScanId)!.shareToken, undefined, "other user's scan stays unshared");
  });
});

// --- Fix verification (retest) ---

test('POST retest 403s when the domain is not verified, and 404s for unknown finding/scan', async () => {
  const other = db.getOrCreateUser(`retest-other-${Date.now()}@test.io`);
  const otherScanId = completedScan(other.id);
  await withScanApp(async (base, userId) => {
    const scanId = completedScan(userId); // finding id 'f1', domain NOT verified

    // Domain unverified → 403 (a retest re-issues active exploit traffic).
    const gated = await fetch(`${base}/api/scans/${scanId}/findings/f1/retest`, { method: 'POST' });
    assert.equal(gated.status, 403);

    // Unknown finding on an owned scan → 404.
    const noFinding = await fetch(`${base}/api/scans/${scanId}/findings/nope/retest`, { method: 'POST' });
    assert.equal(noFinding.status, 404);

    // Another user's scan → 404 (never reveals it exists).
    const cross = await fetch(`${base}/api/scans/${otherScanId}/findings/f1/retest`, { method: 'POST' });
    assert.equal(cross.status, 404);
  });
});
