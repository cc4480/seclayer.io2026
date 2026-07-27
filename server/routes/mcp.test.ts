import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import net from 'node:net';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
process.env.FREE_MODE = 'false'; // these suites exercise the paid credit flow
const { db } = await import('../db.js');
const { registerMcpRoutes } = await import('./mcp.js');

async function withMcpApp(fn: (base: string) => Promise<void>) {
  const app = express();
  app.use(express.json());
  registerMcpRoutes(app, {
    requireAuth: (_req, _res, next) => next(),
    getUserId: () => '',
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

// A bound-then-closed ephemeral port: nothing is listening there, so a
// connection attempt fails instantly (ECONNREFUSED) with no network-timeout
// wait — deterministic and fast for a test.
async function reserveClosedPort(): Promise<number> {
  const srv = net.createServer();
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  const port = (srv.address() as AddressInfo).port;
  await new Promise((r) => srv.close(r));
  return port;
}

// NOTE: rateLimit.ts's bucket state is a module-level singleton shared by
// every test in this file/process, keyed by client IP + the limiter's
// keyPrefix — so any test that burns through the "mcp-scan" limit must run
// LAST, or it starves every test declared after it. Node's test runner runs
// top-level test() calls in declaration order, so ordering in this file is
// significant.

test('POST /api/mcp/scan refunds the credit and records a failed scan when the pipeline throws', async () => {
  // Regression test: this route used to deduct the credit and only ever
  // create a scan record on the SUCCESS path — any exception from the
  // pipeline (runPassiveScan deliberately throws on an unreachable target,
  // per its doc comment in scanner.ts) fell into the catch block, which
  // returned a 500 with no refund and no record of what happened to the
  // spent credit. The credit must come back and the scan must be visible as
  // "failed", the same guarantee the dashboard flow already has.
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    const closedPort = await reserveClosedPort();
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${closedPort}`;

    const user = db.getOrCreateUser(`mcp-fail-${Date.now()}@test.io`);
    const { rawKey } = db.generateApiKey(user.id);
    const creditsBefore = db.getUser(user.id)!.credits;

    await withMcpApp(async (base) => {
      const res = await fetch(`${base}/api/mcp/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: `http://127.0.0.1:${closedPort}`, apiKey: rawKey }),
      });
      assert.equal(res.status, 500);
      const body = await res.json();
      assert.equal(body.creditsRemaining, creditsBefore, 'the credit spent for this attempt must be refunded');
    });

    assert.equal(db.getUser(user.id)!.credits, creditsBefore, 'balance is back to where it started');
    const scans = db.listScans(user.id);
    assert.equal(scans.length, 1, 'the failed attempt must still be visible in scan history, not silently discarded');
    assert.equal(scans[0].status, 'failed');
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
  }
});

test('POST /api/mcp/scan creates exactly one complete scan record on success, deducting exactly one credit', async () => {
  const targetServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>hello</body></html>');
  });
  await new Promise<void>((r) => targetServer.listen(0, '127.0.0.1', () => r()));
  const targetPort = (targetServer.address() as AddressInfo).port;

  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${targetPort}`;

    const user = db.getOrCreateUser(`mcp-success-${Date.now()}@test.io`);
    const { rawKey } = db.generateApiKey(user.id);
    const creditsBefore = db.getUser(user.id)!.credits;

    await withMcpApp(async (base) => {
      const res = await fetch(`${base}/api/mcp/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: `http://127.0.0.1:${targetPort}`, apiKey: rawKey }),
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.creditsRemaining, creditsBefore - 1);
    });

    assert.equal(db.getUser(user.id)!.credits, creditsBefore - 1);
    const scans = db.listScans(user.id);
    assert.equal(scans.length, 1, 'exactly one scan record — created upfront, not duplicated on success');
    assert.equal(scans[0].status, 'complete');
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise((r) => targetServer.close(r));
  }
});

test('GET /api/mcp/scans lists only the key owner\'s scans and 401s without a valid key', async () => {
  const owner = db.getOrCreateUser(`mcp-list-owner-${Date.now()}@test.io`);
  const { rawKey } = db.generateApiKey(owner.id);
  const other = db.getOrCreateUser(`mcp-list-other-${Date.now()}@test.io`);
  const ownScan = db.createScan(owner.id, 'https://93.184.216.34');
  db.updateScan(ownScan.id, { status: 'complete', score: 70, severity: 'medium', completedAt: new Date().toISOString() });
  db.createScan(other.id, 'https://1.1.1.1'); // must never appear for the owner's key

  await withMcpApp(async (base) => {
    // No key → 401.
    const noKey = await fetch(`${base}/api/mcp/scans`);
    assert.equal(noKey.status, 401);

    // Owner's key → only their scan(s), compact shape, no findings bodies.
    const res = await fetch(`${base}/api/mcp/scans`, { headers: { 'X-API-Key': rawKey } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.scans.some((s: any) => s.id === ownScan.id));
    assert.ok(body.scans.every((s: any) => s.id !== undefined && s.findings === undefined), 'list is compact (no finding bodies)');
    assert.ok(!body.scans.some((s: any) => s.url === 'https://1.1.1.1'), "another user's scan must never leak");
  });
});

test('GET /api/mcp/scans/:id returns a completed report, 404s across users, and 409s when incomplete', async () => {
  const owner = db.getOrCreateUser(`mcp-report-owner-${Date.now()}@test.io`);
  const { rawKey } = db.generateApiKey(owner.id);
  const other = db.getOrCreateUser(`mcp-report-other-${Date.now()}@test.io`);

  const done = db.createScan(owner.id, 'https://93.184.216.34');
  // One high-severity finding: the read-model recomputes the display score from
  // findings (100 − 25 = 75), so the report's postureScore is deterministic and
  // reflects the shared scoring, not whatever raw value was stored.
  db.updateScan(done.id, {
    status: 'complete', score: 61, severity: 'high', aiSummary: 'sum',
    findings: [{ id: 'f1', title: 'Test High Finding', description: 'd', severity: 'high', confidence: 'high', fix: 'f', category: 'DAST' }],
    completedAt: new Date().toISOString(),
  });
  const pending = db.createScan(owner.id, 'https://93.184.216.34'); // status: queued
  const foreign = db.createScan(other.id, 'https://1.1.1.1');
  db.updateScan(foreign.id, { status: 'complete', completedAt: new Date().toISOString() });

  await withMcpApp(async (base) => {
    // Completed → full report shape (same as POST /scan), no credit cost.
    const ok = await fetch(`${base}/api/mcp/scans/${done.id}`, { headers: { 'X-API-Key': rawKey } });
    assert.equal(ok.status, 200);
    const report = await ok.json();
    assert.equal(report.success, true);
    assert.equal(report.targetUrl, 'https://93.184.216.34');
    assert.equal(report.postureScore, 75, 'score is recomputed from findings via the shared read-model (100 − 25)');
    assert.equal(report.vulnerabilityLevel, 'high');
    assert.equal(report.securityFindings.length, 1);

    // Another user's scan → 404 (not 403), so an id can't probe existence.
    const cross = await fetch(`${base}/api/mcp/scans/${foreign.id}`, { headers: { 'X-API-Key': rawKey } });
    assert.equal(cross.status, 404);

    // Incomplete scan → 409 with the status.
    const notReady = await fetch(`${base}/api/mcp/scans/${pending.id}`, { headers: { 'X-API-Key': rawKey } });
    assert.equal(notReady.status, 409);
    assert.equal((await notReady.json()).status, 'queued');
  });
});

test('POST /api/mcp/scan is rate-limited per caller', async () => {
  // Regression test: this endpoint used to have no rateLimit() at all, unlike
  // every other scan-launching route, so a caller could burst unlimited
  // concurrent full-pipeline scans. The limiter runs ahead of the handler, so
  // sending requests missing `url`/`apiKey` (a fast 400, no real scan work)
  // is enough to prove the middleware is wired up without needing a live target.
  // Declared LAST in this file: it deliberately exhausts the shared
  // rate-limit bucket (see note above), which would starve any test after it.
  // The two earlier tests in this file already spent 2 of the bucket's 5
  // slots (one real request each), so this doesn't assume a fresh bucket —
  // it just sends well past the limit and checks the shape of the outcome:
  // some requests reach the handler (400, missing params), then it locks
  // into 429 and stays there.
  await withMcpApp(async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${base}/api/mcp/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      statuses.push(res.status);
    }
    assert.ok(statuses.every((s) => s === 400 || s === 429), `only 400/429 expected; got ${statuses}`);
    const reached = statuses.filter((s) => s === 400).length;
    assert.ok(reached >= 1 && reached <= 5, `expected between 1 and 5 requests to reach the handler before the limit; got ${statuses}`);
    // Once limited, it must stay limited for the rest of the burst.
    const firstLimitedIndex = statuses.indexOf(429);
    assert.ok(firstLimitedIndex !== -1, `the limiter never kicked in; got ${statuses}`);
    assert.ok(statuses.slice(firstLimitedIndex).every((s) => s === 429), `once limited, every subsequent request must stay 429; got ${statuses}`);
  });
});
