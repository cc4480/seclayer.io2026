import { test } from 'node:test';
import assert from 'node:assert/strict';

// Use an isolated in-memory database. Set before importing the db singleton.
process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');

test('createNmapScan starts queued and is independent of the AppSec scans table', async () => {
  const u = (await db.getOrCreateUser('nmap-create@test.io'));
  const scan = (await db.createNmapScan(u.id, 'https://target.test'));
  assert.equal(scan.status, 'queued');
  assert.equal(scan.url, 'https://target.test');
  assert.equal(scan.userId, u.id);
  assert.equal((await db.listScans(u.id)).length, 0, 'creating an nmap scan must not create an AppSec scan row');
});

test('listNmapScans returns only the caller\'s own scans', async () => {
  const owner = (await db.getOrCreateUser('nmap-list-owner@test.io'));
  const other = (await db.getOrCreateUser('nmap-list-other@test.io'));
  const first = (await db.createNmapScan(owner.id, 'https://a.test'));
  const second = (await db.createNmapScan(owner.id, 'https://b.test'));
  (await db.createNmapScan(other.id, 'https://not-mine.test'));

  const rows = (await db.listNmapScans(owner.id));
  assert.equal(rows.length, 2);
  assert.deepEqual(new Set(rows.map(r => r.id)), new Set([first.id, second.id]));
});

test('updateNmapScan merges onto the existing row and round-trips the result JSON', async () => {
  const u = (await db.getOrCreateUser('nmap-update@test.io'));
  const scan = (await db.createNmapScan(u.id, 'https://scan-me.test'));

  const result = {
    scannedAt: new Date().toISOString(),
    targetHost: 'scan-me.test',
    resolvedIp: '203.0.113.10',
    state: 'up' as const,
    ports: [{ port: 22, protocol: 'tcp' as const, state: 'open', service: 'ssh', scripts: [] }],
    osMatches: [{ name: 'Linux 5.x', accuracy: 92 }],
    vulnFindings: [{ port: 22, scriptId: 'sshv1', output: 'Server supports deprecated SSHv1', outcome: 'finding' as const }],
    nmapVersion: '7.94',
    scanArgs: ['-p-', '-sV', '-O', '--script', 'vuln'],
    durationMs: 12345,
  };

  const updated = (await db.updateNmapScan(scan.id, {
    status: 'complete', resolvedIp: '203.0.113.10', nmapVersion: '7.94', result, rawXml: '<nmaprun/>',
    completedAt: new Date().toISOString(),
  }));

  assert.equal(updated.status, 'complete');
  assert.equal(updated.resolvedIp, '203.0.113.10');
  assert.deepEqual(updated.result, result);
  assert.equal(updated.rawXml, '<nmaprun/>');

  // Re-fetch from a fresh row read to confirm it was actually persisted, not
  // just returned from the in-memory merge.
  const refetched = (await db.getNmapScan(scan.id))!;
  assert.deepEqual(refetched.result, result);
});

test('recoverStuckNmapScans fails and refunds any scan left mid-flight, and leaves completed scans alone', async () => {
  const u = (await db.getOrCreateUser('nmap-stuck@test.io'));
  const creditsBefore = (await db.getUser(u.id))!.credits;

  const queued = (await db.createNmapScan(u.id, 'https://queued.test'));
  const scanning = (await db.updateNmapScan((await db.createNmapScan(u.id, 'https://scanning.test')).id, { status: 'scanning' }));
  const completed = (await db.updateNmapScan((await db.createNmapScan(u.id, 'https://done.test')).id, { status: 'complete', completedAt: new Date().toISOString() }));

  const recovered = (await db.recoverStuckNmapScans());
  assert.ok(recovered >= 2, `at least the two mid-flight scans created here must be recovered; got ${recovered}`);

  assert.equal((await db.getNmapScan(queued.id))!.status, 'failed');
  assert.equal((await db.getNmapScan(scanning.id))!.status, 'failed');
  assert.match((await db.getNmapScan(queued.id))!.error || '', /interrupted by a server restart/);
  assert.equal((await db.getNmapScan(completed.id))!.status, 'complete', 'a completed scan must be untouched');

  assert.equal((await db.getUser(u.id))!.credits, creditsBefore + 2);

  // Idempotent — nothing left to recover on a second sweep.
  (await db.recoverStuckNmapScans());
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore + 2);
});

test('cancelNmapScan refunds the credit, is scoped to the owner, and refuses a terminal scan', async () => {
  const owner = (await db.getOrCreateUser('nmap-cancel-owner@test.io'));
  const other = (await db.getOrCreateUser('nmap-cancel-other@test.io'));
  const creditsBefore = (await db.getUser(owner.id))!.credits;

  const scan = (await db.createNmapScan(owner.id, 'https://cancel-me.test'));
  (await db.updateNmapScan(scan.id, { status: 'scanning' }));

  assert.equal((await db.cancelNmapScan(other.id, scan.id)), null, 'another user cannot cancel someone else\'s scan');

  const canceled = (await db.cancelNmapScan(owner.id, scan.id));
  assert.ok(canceled);
  assert.equal(canceled!.status, 'canceled');
  assert.equal((await db.getUser(owner.id))!.credits, creditsBefore + 1);

  // Already terminal — no double-cancel, no double-refund.
  assert.equal((await db.cancelNmapScan(owner.id, scan.id)), null);
  assert.equal((await db.getUser(owner.id))!.credits, creditsBefore + 1);
});

test('hasInFlightNmapScan reflects only queued/scanning rows for that user', async () => {
  const u = (await db.getOrCreateUser('nmap-inflight@test.io'));
  assert.equal((await db.hasInFlightNmapScan(u.id)), false);

  const scan = (await db.createNmapScan(u.id, 'https://busy.test'));
  assert.equal((await db.hasInFlightNmapScan(u.id)), true);

  (await db.updateNmapScan(scan.id, { status: 'scanning' }));
  assert.equal((await db.hasInFlightNmapScan(u.id)), true);

  (await db.updateNmapScan(scan.id, { status: 'complete', completedAt: new Date().toISOString() }));
  assert.equal((await db.hasInFlightNmapScan(u.id)), false);
});
