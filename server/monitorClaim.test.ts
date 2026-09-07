import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');

async function target() {
  const user = await db.getOrCreateUser(`mon-${Math.random()}@test.local`);
  const t = await db.addMonitoredTarget(user.id, `https://x${Math.random()}.example.com`, {
    frequencyDays: 7, hour: 9, minute: 0,
  } as any);
  return t.id;
}

const STALE = new Date(Date.now() - 10 * 60 * 1000).toISOString();
const NOW = () => new Date().toISOString();

// Without this, all three replicas see the same due target on the same tick and
// each launches a scan: triple the credits spent and triple the load aimed at
// the customer's site.
test('only one instance may process a due target', async () => {
  const id = await target();
  const results = await Promise.all([
    db.claimMonitoredTick(id, STALE, NOW()),
    db.claimMonitoredTick(id, STALE, NOW()),
    db.claimMonitoredTick(id, STALE, NOW()),
  ]);
  assert.equal(results.filter(Boolean).length, 1, 'exactly one instance may take the target');
});

// The whole reason the lease is a separate column rather than nextRun: a target
// skipped for want of credits keeps its due time and must be retried on the very
// next tick. Claiming through nextRun would silently reschedule it a week out.
test('releasing lets the very next tick pick the target up again', async () => {
  const id = await target();
  assert.equal(await db.claimMonitoredTick(id, STALE, NOW()), true);
  assert.equal(await db.claimMonitoredTick(id, STALE, NOW()), false, 'held while in flight');

  await db.releaseMonitoredTick(id);
  assert.equal(await db.claimMonitoredTick(id, STALE, NOW()), true, 'retry-next-tick must still work');
});

test('a lease left behind by a dead instance expires', async () => {
  const id = await target();
  // Claimed ten minutes ago by an instance that never released it.
  await db.claimMonitoredTick(id, STALE, new Date(Date.now() - 10 * 60 * 1000).toISOString());
  const staleCutoff = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  assert.equal(await db.claimMonitoredTick(id, staleCutoff, NOW()), true,
    'a target must not be stranded because the instance holding it died');
});
