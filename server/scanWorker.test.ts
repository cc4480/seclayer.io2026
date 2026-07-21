import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');
const { makeProcessScanJob } = await import('./scanWorker.js');

// Every response is deliberately slow so runDiagnostics' several sequential/
// parallel probes take real wall-clock time, giving the test a reliable
// window to cancel while the worker is still mid-flight.
async function withSlowServer(fn: (port: number) => Promise<void>) {
  const handler: http.RequestListener = (_req, res) => {
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body>slow target</body></html>');
    }, 30);
  };
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    // SCAN_DEV_ALLOW_HOSTS is the dev-only escape hatch that lets the SSRF
    // guard scan this loopback test server (see ssrf.ts).
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
}

test('a scan canceled mid-flight keeps its canceled status — the worker discards its late result', async () => {
  await withSlowServer(async (port) => {
    const u = db.getOrCreateUser(`worker-cancel-${Date.now()}@test.io`);
    const scan = db.createScan(u.id, `http://127.0.0.1:${port}`);
    const processScanJob = makeProcessScanJob();

    const jobPromise = processScanJob(scan.id, false);

    // Give the worker enough time to flip status to "scanning" and start
    // probing the (deliberately slow) target, then cancel while it's still
    // mid-flight — diagnostics haven't resolved yet.
    await new Promise((r) => setTimeout(r, 15));
    assert.equal(db.getScan(scan.id)!.status, 'scanning', 'sanity check: the worker must still be running when we cancel');
    const canceled = db.cancelScan(u.id, scan.id);
    assert.ok(canceled, 'the scan must still be cancellable while the worker is in flight');
    assert.equal(canceled!.status, 'canceled');

    await jobPromise; // let the worker run to its natural completion

    const final = db.getScan(scan.id)!;
    assert.equal(final.status, 'canceled', 'the worker must not overwrite the cancellation with a late complete/failed result');
    assert.equal(final.findings, undefined, 'no findings should have been persisted for a canceled scan');
    assert.equal(final.score, undefined);
  });
});

test('a scan that completes before any cancellation request is unaffected', async () => {
  const u = db.getOrCreateUser(`worker-normal-${Date.now()}@test.io`);
  // A safe, DNS-free literal-IP target keeps this fast and network-independent.
  const scan = db.createScan(u.id, 'https://93.184.216.34');
  const processScanJob = makeProcessScanJob();

  await processScanJob(scan.id, false);

  const final = db.getScan(scan.id)!;
  assert.ok(final.status === 'complete' || final.status === 'failed', `expected a terminal status, got ${final.status}`);
});
