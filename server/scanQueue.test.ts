import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'queue-')), 'db.sqlite');
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

async function queued(url = 'https://example.com') {
  const user = await db.getOrCreateUser(`q-${Math.random()}@test.local`);
  const scan = await db.createScan(user.id, url);
  await db.enqueueScanJob(scan.id, { allowActiveProbes: false });
  return scan.id;
}

// The guarantee the whole queue rests on. Without it two workers run the same
// scan: duplicated cost, duplicated probes against the target, and two writers
// racing on one scan row.
test('a queued scan is claimed exactly once', async () => {
  const id = await queued();
  const first = await db.claimNextQueuedScan();
  const second = await db.claimNextQueuedScan();

  assert.equal(first?.scanId, id);
  assert.equal(second, null, 'a claimed scan must not be handed to a second worker');
});

test('claiming is what leases the scan, so recovery cannot take it', async () => {
  await queued();
  const job = await db.claimNextQueuedScan();
  assert.ok(job);
  // Claim and lease are one act — a scan picked up a moment ago must not look
  // abandoned to an instance booting right after.
  assert.equal(await db.recoverStuckScans(), 0);
  assert.equal((await db.getScan(job!.scanId))!.status, 'queued');
});

test('a scan whose worker died is re-claimable rather than stranded', async () => {
  const id = await queued();
  await db.claimNextQueuedScan();
  // That worker vanished: nothing has refreshed the lease since.
  expireLease(id);

  const reclaimed = await db.claimNextQueuedScan();
  assert.equal(reclaimed?.scanId, id, 'another worker must be able to pick it up');
});

test('the job parameters survive the handoff to another worker', async () => {
  const user = await db.getOrCreateUser(`q-params-${Math.random()}@test.local`);
  const scan = await db.createScan(user.id, 'https://example.com');
  await db.enqueueScanJob(scan.id, { allowActiveProbes: true, allowAggressiveProbes: true });

  const job = await db.claimNextQueuedScan();
  assert.deepEqual(job?.params, { allowActiveProbes: true, allowAggressiveProbes: true });
});

test('a scan that was never enqueued is not claimable', async () => {
  // Credentialed scans run in-process and are deliberately never queued, since
  // storing bolaIdentities/loginCredentials would mean secrets at rest. A scan
  // with no jobParams must therefore be invisible to the queue.
  const user = await db.getOrCreateUser(`q-cred-${Math.random()}@test.local`);
  await db.createScan(user.id, 'https://example.com');
  assert.equal(await db.claimNextQueuedScan(), null);
});

test('scans are claimed oldest first', async () => {
  const a = await queued('https://a.example.com');
  await new Promise((r) => setTimeout(r, 10));
  const b = await queued('https://b.example.com');
  assert.equal((await db.claimNextQueuedScan())?.scanId, a, 'FIFO: the longest-waiting user goes first');
  assert.equal((await db.claimNextQueuedScan())?.scanId, b);
});
