import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');
const { runDueMonitoredScans } = await import('./monitorWorker.js');

// A literal public IP passes the SSRF guard with no DNS lookup (see
// scanner.test.ts's "assertScanTargetSafe allows a public literal IP"), so
// the "successful launch" tests don't depend on real network access.
const SAFE_TARGET = 'https://93.184.216.34';
// Cloud-metadata address — always blocked by the SSRF guard, no allowlist needed.
const UNSAFE_TARGET = 'http://169.254.169.254/latest/meta-data/';

function backdateToDue(targetId: string, iso = new Date(Date.now() - 1000).toISOString()) {
  db.markMonitoredScanned(targetId, iso, iso);
}

test('a due target with credits and a safe URL launches a scan and deducts one credit', async () => {
  const u = db.getOrCreateUser(`mw-success-${Date.now()}@test.io`);
  const target = db.addMonitoredTarget(u.id, SAFE_TARGET, 7);
  backdateToDue(target.id);
  const creditsBefore = db.getUser(u.id)!.credits;

  const launched: Array<{ scanId: string; allowActiveProbes: boolean }> = [];
  await runDueMonitoredScans((scanId, allowActiveProbes) => {
    launched.push({ scanId, allowActiveProbes });
  });

  assert.equal(launched.length, 1, 'exactly one scan should be launched for the one due target');
  assert.equal(db.getUser(u.id)!.credits, creditsBefore - 1);
  assert.equal(db.listScans(u.id).length, 1);

  const updated = db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!;
  assert.ok(updated.lastScannedAt, 'lastScannedAt must be set after a successful launch');
  assert.ok(new Date(updated.nextScanAt!).getTime() > Date.now(), 'nextScanAt must be rescheduled into the future');
  assert.ok(!updated.lastError, 'no lastError after a successful launch');
});

test('a target not yet due is left completely untouched', async () => {
  const u = db.getOrCreateUser(`mw-not-due-${Date.now()}@test.io`);
  const target = db.addMonitoredTarget(u.id, SAFE_TARGET, 7); // freshly added -> scheduled in the future
  const creditsBefore = db.getUser(u.id)!.credits;

  let launched = false;
  await runDueMonitoredScans(() => { launched = true; });

  assert.equal(launched, false);
  assert.equal(db.getUser(u.id)!.credits, creditsBefore);
  assert.equal(db.listScans(u.id).length, 0);
  const unchanged = db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!;
  assert.ok(!unchanged.lastScannedAt);
});

test('a due target with no credits is skipped, retried next tick, and records why', async () => {
  const u = db.getOrCreateUser(`mw-no-credits-${Date.now()}@test.io`);
  db.deductCredits(u.id, db.getUser(u.id)!.credits); // spend down to 0
  const target = db.addMonitoredTarget(u.id, SAFE_TARGET, 7);
  const dueAt = new Date(Date.now() - 1000).toISOString();
  backdateToDue(target.id, dueAt);

  let launched = false;
  await runDueMonitoredScans(() => { launched = true; });

  assert.equal(launched, false);
  assert.equal(db.listScans(u.id).length, 0);
  const updated = db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!;
  assert.match(updated.lastError || '', /insufficient credits/i);
  // Scheduling is untouched — it must still be due so the very next tick retries it.
  assert.equal(updated.nextScanAt, dueAt);
});

test('a due target with an unsafe URL is deferred to its next cadence and records why, without spending a credit', async () => {
  const u = db.getOrCreateUser(`mw-unsafe-${Date.now()}@test.io`);
  const target = db.addMonitoredTarget(u.id, UNSAFE_TARGET, 7);
  backdateToDue(target.id);
  const creditsBefore = db.getUser(u.id)!.credits;

  let launched = false;
  await runDueMonitoredScans(() => { launched = true; });

  assert.equal(launched, false);
  assert.equal(db.getUser(u.id)!.credits, creditsBefore, 'an unsafe target must never spend a credit');
  assert.equal(db.listScans(u.id).length, 0);
  const updated = db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!;
  assert.ok(updated.lastError, 'the unsafe-target reason must be recorded');
  assert.ok(new Date(updated.nextScanAt!).getTime() > Date.now(), 'deferred to the next real cadence, not retried every tick');
});

test('a successful launch clears a lingering lastError from a previous failed tick', async () => {
  const u = db.getOrCreateUser(`mw-recover-${Date.now()}@test.io`);
  const target = db.addMonitoredTarget(u.id, SAFE_TARGET, 7);
  backdateToDue(target.id);
  db.markMonitoredError(target.id, 'Skipped: insufficient credits.');
  assert.ok(db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!.lastError);

  await runDueMonitoredScans(() => {});

  const updated = db.listMonitoredTargets(u.id).find((t) => t.id === target.id)!;
  assert.ok(!updated.lastError, 'a subsequent successful launch must clear the old error');
});

test('a paused target is never scanned even when its next run is due', async () => {
  const u = db.getOrCreateUser(`mw-paused-${Date.now()}@test.io`);
  const target = db.addMonitoredTarget(u.id, SAFE_TARGET, 7);
  backdateToDue(target.id); // would be due
  db.setMonitoredPaused(u.id, target.id, true);
  const creditsBefore = db.getUser(u.id)!.credits;

  let launched = false;
  await runDueMonitoredScans(() => { launched = true; });

  assert.equal(launched, false, 'a paused target must not launch a scan');
  assert.equal(db.getUser(u.id)!.credits, creditsBefore, 'no credit spent on a paused target');
  assert.equal(db.listScans(u.id).length, 0);
});

test('overlapping ticks do not double-process the same due target', async () => {
  const u = db.getOrCreateUser(`mw-overlap-${Date.now()}@test.io`);
  // A real hostname forces assertScanTargetSafe through a genuine async DNS
  // lookup (a real event-loop yield), giving a concurrent second tick a
  // window to start while the first is still in flight — a literal IP
  // resolves synchronously and wouldn't reproduce the race (see the same
  // reasoning in routes/scans.test.ts's concurrency test).
  const target = db.addMonitoredTarget(u.id, 'https://example.com', 7);
  backdateToDue(target.id);

  let launchCount = 0;
  const tick1 = runDueMonitoredScans(() => { launchCount++; });
  const tick2 = runDueMonitoredScans(() => { launchCount++; }); // fired while tick1 is still running
  await Promise.all([tick1, tick2]);

  assert.equal(launchCount, 1, 'the overlap guard must prevent the same due target from being processed twice');
});
