import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'digest-')), 'db.sqlite');
const { db } = await import('./db.js');

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

// The bug this closes: runDueDigests read lastDigestAt, sent, then wrote it.
// On one instance that is fine. On three, all three ticks read the same stale
// value, all decide the digest is due, and the user gets three identical emails
// — which cannot be recalled.
test('only one instance wins the right to send a given digest', async () => {
  const user = await db.getOrCreateUser(`digest-${Math.random()}@test.local`);
  const now = new Date();
  const notSince = new Date(now.getTime() - WEEK_MS).toISOString();

  // Three replicas ticking at the same moment.
  const results = await Promise.all([
    db.claimDigestSend(user.id, notSince, now.toISOString()),
    db.claimDigestSend(user.id, notSince, now.toISOString()),
    db.claimDigestSend(user.id, notSince, now.toISOString()),
  ]);

  assert.equal(results.filter(Boolean).length, 1, 'exactly one instance may send');
});

test('the claim is refused again within the same period', async () => {
  const user = await db.getOrCreateUser(`digest-again-${Math.random()}@test.local`);
  const now = new Date();
  const notSince = new Date(now.getTime() - WEEK_MS).toISOString();

  assert.equal(await db.claimDigestSend(user.id, notSince, now.toISOString()), true);
  assert.equal(await db.claimDigestSend(user.id, notSince, now.toISOString()), false,
    'a second tick in the same period must not send another copy');
});

test('the claim is granted again once the period has elapsed', async () => {
  const user = await db.getOrCreateUser(`digest-next-${Math.random()}@test.local`);
  const sentAt = new Date(Date.now() - WEEK_MS - 60_000);
  assert.equal(await db.claimDigestSend(user.id, new Date(sentAt.getTime() - 1000).toISOString(), sentAt.toISOString()), true);

  // A week later the next digest is due again — the claim must not be permanent.
  const now = new Date();
  assert.equal(await db.claimDigestSend(user.id, new Date(now.getTime() - WEEK_MS).toISOString(), now.toISOString()), true);
});

test('claiming stamps the send time, so a crash cannot resend', async () => {
  const user = await db.getOrCreateUser(`digest-stamp-${Math.random()}@test.local`);
  const now = new Date();
  await db.claimDigestSend(user.id, new Date(now.getTime() - WEEK_MS).toISOString(), now.toISOString());
  // Stamped before the email goes out: a duplicate cannot be recalled, whereas a
  // digest missed because the send failed simply arrives next period.
  const after = await db.getUser(user.id);
  assert.ok(after?.lastDigestAt, 'the send must be recorded at claim time, not after sending');
});
