import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lease-')), 'db.sqlite');
const { db, STALE_LEASE_MS } = await import('./db.js');

// updateScan writes a fixed column list that does not include heartbeatAt, so
// setting a stale lease has to go through the raw handle. Done deliberately:
// this is establishing a precondition ("the owner died N minutes ago"), not
// exercising a production path, and routing it through updateScan silently did
// nothing — leaving the assertion below to pass on a NULL lease instead of the
// staleness comparison it is supposed to be testing.
function expireLease(scanId: string, msAgo = STALE_LEASE_MS + 60_000): void {
  (db as any).db.prepare('UPDATE scans SET heartbeatAt = ? WHERE id = ?')
    .run(new Date(Date.now() - msAgo).toISOString(), scanId);
}

async function queuedScan() {
  const user = await db.getOrCreateUser(`lease-${Math.random()}@test.local`);
  const scan = await db.createScan(user.id, 'https://example.com');
  return scan.id;
}

// The bug: recoverStuckScans took EVERY queued/scanning/analyzing scan on boot,
// with no notion of which process owned it. Correct on exactly one instance —
// destructive on more, where any replica restarting (a deploy, a crash, a scale
// event) would fail and refund every scan the OTHER replicas were running, and
// tell those users their scan had been interrupted.
test('a booting instance does not recover scans another live instance is running', async () => {
  const running = await queuedScan();
  // Stand in for the live owner: a lease refreshed just now.
  await db.touchScan(running);

  const recovered = await db.recoverStuckScans();
  assert.equal(recovered, 0, 'a scan with a fresh lease belongs to a live process');
  assert.equal((await db.getScan(running))!.status, 'queued', 'and must be left alone');
});

test('a scan whose owner died IS recovered once its lease goes stale', async () => {
  const abandoned = await queuedScan();
  // Lease last refreshed longer ago than the staleness window.
  expireLease(abandoned);

  const recovered = await db.recoverStuckScans();
  assert.ok(recovered >= 1, 'an abandoned scan must still be swept');
  const after = await db.getScan(abandoned);
  assert.equal(after!.status, 'failed');
  assert.match(after!.error || '', /interrupted/i);
});

test('a scan with no lease at all is still recovered', async () => {
  // Scans predating the heartbeatAt column, or left by an older build, have a
  // NULL lease. Treating NULL as "live" would strand them in flight forever.
  const legacy = await queuedScan();
  const recovered = await db.recoverStuckScans();
  assert.ok(recovered >= 1);
  assert.equal((await db.getScan(legacy))!.status, 'failed');
});
