import { test } from 'node:test';
import assert from 'node:assert/strict';

// Use an isolated in-memory database. Set before importing the db singleton.
process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');
const { processNmapScanJob } = await import('./nmapWorker.js');
const scanEvents = await import('./scanEvents.js');

// No mocking, matching this codebase's existing test style (real probes
// against real local servers elsewhere) — the SSRF guard rejects an internal
// target synchronously, which is enough to exercise the worker's full
// scanning -> failed lifecycle and cancellation guards without needing a real
// nmap binary. The nmap-installed success path is covered separately in
// server/nmap/run.integration.test.ts.

test('processNmapScanJob no-ops immediately for an unknown scan id', async () => {
  await assert.doesNotReject(() => processNmapScanJob('nmap_does_not_exist'));
});

test('processNmapScanJob no-ops for a scan already canceled before it starts', async () => {
  const u = (await db.getOrCreateUser('nmap-worker-precanceled@test.io'));
  const scan = (await db.createNmapScan(u.id, 'http://127.0.0.1'));
  (await db.updateNmapScan(scan.id, { status: 'canceled', error: 'Canceled by user.' }));

  await processNmapScanJob(scan.id);

  const after = (await db.getNmapScan(scan.id))!;
  assert.equal(after.status, 'canceled', 'a pre-canceled scan must never be overwritten');
  assert.equal(after.error, 'Canceled by user.');
});

test('processNmapScanJob transitions scanning -> failed when target resolution is refused, and emits a live event', async () => {
  const u = (await db.getOrCreateUser('nmap-worker-blocked@test.io'));
  const scan = (await db.createNmapScan(u.id, 'http://127.0.0.1')); // blocked: loopback

  await processNmapScanJob(scan.id);

  const after = (await db.getNmapScan(scan.id))!;
  assert.equal(after.status, 'failed');
  assert.match(after.error || '', /internal or reserved/);
  assert.ok(after.startedAt, 'the scan must have entered the scanning phase before failing');
  assert.ok(after.completedAt);

  // The live stream is closed on completion but its buffered tail should
  // still be readable immediately after (EVICT_AFTER_MS hasn't elapsed).
  const { events } = scanEvents.getSince(scan.id, 0);
  assert.ok(events.some((e) => /Resolving/.test(e.text)));
  assert.ok(events.some((e) => /Scan failed/.test(e.text)));
});

test('processNmapScanJob does not overwrite a scan canceled mid-flight (after it reached scanning)', async () => {
  const u = (await db.getOrCreateUser('nmap-worker-midflight-cancel@test.io'));
  const scan = (await db.createNmapScan(u.id, 'http://this-domain-should-not-exist-seclayer-test.invalid'));

  const jobPromise = processNmapScanJob(scan.id);
  // Race the worker: flip to canceled while it's mid-resolution (DNS lookup
  // for a nonexistent domain takes a little real time, giving this a window).
  (await db.updateNmapScan(scan.id, { status: 'canceled', error: 'Canceled by user.' }));
  await jobPromise;

  const after = (await db.getNmapScan(scan.id))!;
  assert.equal(after.status, 'canceled', 'the worker must never overwrite a cancellation with a failure');
});
