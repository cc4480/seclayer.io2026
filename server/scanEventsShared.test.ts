import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

// Own database file: this exercises the SHARED path, and the default in-memory
// path is covered by scanEvents.test.ts.
process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'scanev-')), 'db.sqlite');
const { db } = await import('./db.js');
const scanEvents = await import('./scanEvents.js');

// The bug this closes: a scan runs on ONE instance and buffers its events in
// that process. With more than one replica the client's poll can land on an
// instance that never ran it, finds no local stream, and reports found:false —
// so the live ticker shows nothing for a scan that is running perfectly well.
test('a poll on an instance that never ran the scan still sees the feed', async () => {
  scanEvents.installSharedScanEvents(true);
  const scanId = 'scan_other_instance_' + Date.now();

  // Stand in for the instance that IS running the scan: rows in the shared
  // store, and deliberately NO local stream in this process.
  await db.appendScanEvents(scanId, [
    { seq: 1, ts: Date.now(), channel: 'system', text: 'Launching scan…' },
    { seq: 2, ts: Date.now(), channel: 'recon', text: 'Resolving DNS…' },
  ]);

  const first = await scanEvents.getSince(scanId, 0);
  assert.equal(first.found, true, 'a feed that exists on another instance must be found');
  assert.deepEqual(first.events.map((e) => e.text), ['Launching scan…', 'Resolving DNS…']);
  assert.equal(first.cursor, 2);

  // The cursor must advance so a poller drains rather than re-reading forever.
  const second = await scanEvents.getSince(scanId, first.cursor);
  assert.equal(second.found, true, 'nothing new is NOT the same as no feed');
  assert.deepEqual(second.events, []);
  assert.equal(second.cursor, 2);
});

test('a scan with no feed anywhere still reports found:false', async () => {
  scanEvents.installSharedScanEvents(true);
  // found:false is what makes the client fall back to the stored narration log.
  // Conflating it with "nothing new" would blank a finished scan's ticker.
  const r = await scanEvents.getSince('scan_never_existed_' + Date.now(), 0);
  assert.equal(r.found, false);
  assert.deepEqual(r.events, []);
});

test('a locally-running scan is served from memory and written through', async () => {
  scanEvents.installSharedScanEvents(true);
  const scanId = 'scan_local_' + Date.now();
  const stream = scanEvents.openStream(scanId);
  stream.emit('system', 'local event');

  // Served from the local buffer immediately — no database round-trip on the
  // instance actually running the scan.
  const local = await scanEvents.getSince(scanId, 0);
  assert.equal(local.found, true);
  assert.deepEqual(local.events.map((e) => e.text), ['local event']);

  // close() flushes the tail, so another instance can read it afterwards.
  stream.close();
  await new Promise((r) => setTimeout(r, 250));
  const shared = await db.getScanEventsSince(scanId, 0);
  assert.equal(shared.found, true, 'the tail must reach the shared store on close');
  assert.deepEqual(shared.events.map((e) => e.text), ['local event']);
});
