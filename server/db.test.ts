import { test } from 'node:test';
import assert from 'node:assert/strict';

// Use an isolated in-memory database. Set before importing the db singleton.
process.env.DB_PATH = ':memory:';
const { db, assertNotSilentlyFallingBack } = await import('./db.js');
const { runMigrations } = await import('./dbSchema.js');

test('a new user receives signup credits; no API key is auto-provisioned', async () => {
  const u = (await db.getOrCreateUser('t1@test.io'));
  assert.equal(u.credits, 5);
  // A key's raw value is only ever shown once, at generateApiKey() time, so
  // signup does not create one out-of-band (it could never be displayed).
  assert.equal((await db.listApiKeys(u.id)).length, 0);
  // getOrCreateUser is idempotent by email
  assert.equal((await db.getOrCreateUser('T1@test.io')).id, u.id);
});

test('generateApiKey returns the raw secret once and stores only its hash', async () => {
  const u = (await db.getOrCreateUser('keytest@test.io'));
  const { apiKey, rawKey } = (await db.generateApiKey(u.id));
  assert.match(rawKey, /^sl_live_[0-9a-f]{32}$/);
  assert.equal(apiKey.keyPreview.includes(rawKey), false, 'the preview must not contain the full raw key');
  assert.equal((apiKey as any).key, undefined, 'the raw/hashed key must never be present on the returned object');

  // The key validates by its raw value (hashed internally for lookup)...
  const validated = (await db.validateApiKeyAndDeduct(rawKey, 1));
  assert.equal(validated?.id, u.id);
  // ...but the raw value itself is never stored, so listing keys never
  // reveals it — only the safe preview.
  const listed = (await db.listApiKeys(u.id));
  assert.equal(listed.some((k) => (k as any).key === rawKey), false);
});

test('deductCredits respects the balance', async () => {
  const u = (await db.getOrCreateUser('t2@test.io'));
  assert.equal((await db.deductCredits(u.id, 99)), false);
  assert.equal((await db.deductCredits(u.id, 5)), true);
  assert.equal((await db.getUser(u.id))!.credits, 0);
});

test('a sign-in code is single-use and validates ownership', async () => {
  const code = (await db.createLoginCode('t3@test.io'));
  assert.deepEqual((await db.verifyLoginCode('t3@test.io', code)), { ok: true, email: 't3@test.io' });
  assert.equal((await db.verifyLoginCode('t3@test.io', code)).ok, false, 'a code cannot be reused');
});

test('an expired sign-in code is rejected', async () => {
  const code = (await db.createLoginCode('t3b@test.io', -1)); // already expired
  const r = (await db.verifyLoginCode('t3b@test.io', code));
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason, 'expired');
});

// THE property that makes a six-digit secret safe. If a code could be matched
// without naming the address it was issued to, one guess would be tested
// against every live code in the table at once instead of against one account.
test('a code issued to one address does not work for another', async () => {
  const code = (await db.createLoginCode('victim@test.io'));
  assert.equal((await db.verifyLoginCode('attacker@test.io', code)).ok, false);
  // Still valid for its real owner — the rejection above was about scope, not
  // about the code having been spent.
  assert.equal((await db.verifyLoginCode('victim@test.io', code)).ok, true);
});

test('five wrong guesses kill the code, even if the sixth guess is correct', async () => {
  const code = (await db.createLoginCode('t3e@test.io'));
  const wrong = code === '000000' ? '111111' : '000000';
  for (let i = 0; i < 5; i++) {
    const r = (await db.verifyLoginCode('t3e@test.io', wrong));
    assert.equal(r.ok, false);
    assert.equal(r.ok === false && r.reason, 'invalid', `attempt ${i + 1} should read as invalid`);
  }
  const r = (await db.verifyLoginCode('t3e@test.io', code));
  assert.equal(r.ok, false, 'the correct code must not work once the attempts are spent');
  assert.equal(r.ok === false && r.reason, 'too_many_attempts');
});

// Property 3 in server/loginCode.ts: N live codes for one mailbox would divide
// the odds of a blind guess by N. It also means the newest email is the one
// that works, which is what someone who requested a second code expects.
test('issuing a new code retires the previous one for that address', async () => {
  const first = (await db.createLoginCode('t3f@test.io'));
  const second = (await db.createLoginCode('t3f@test.io'));
  assert.notEqual(first, second, 'a fresh code is issued, not the same one returned');
  assert.equal((await db.verifyLoginCode('t3f@test.io', first)).ok, false, 'the superseded code is dead');
  assert.equal((await db.verifyLoginCode('t3f@test.io', second)).ok, true);
});

test('a code is matched case- and whitespace-insensitively on the address', async () => {
  const code = (await db.createLoginCode('  T3G@Test.IO '));
  const r = (await db.verifyLoginCode('t3g@test.io', code));
  assert.deepEqual(r, { ok: true, email: 't3g@test.io' });
});

test('verifying an address that was never sent a code fails like any wrong guess', async () => {
  const r = (await db.verifyLoginCode('nobody@test.io', '123456'));
  assert.equal(r.ok, false);
  assert.equal(r.ok === false && r.reason, 'invalid', 'must not be distinguishable from a wrong code');
});

test('sessions resolve to a user and can be revoked', async () => {
  const u = (await db.getOrCreateUser('t4@test.io'));
  const s = (await db.createSession(u.id));
  assert.equal((await db.getSessionUserId(s)), u.id);
  (await db.deleteSession(s));
  assert.equal((await db.getSessionUserId(s)), null);
});

test('suppression is a pure read-model: it recomputes the score without writing', async () => {
  const u = (await db.getOrCreateUser('t5@test.io'));
  const scan = (await db.createScan(u.id, 'https://acme.test'));
  (await db.updateScan(scan.id, {
    status: 'complete', score: 75, severity: 'high',
    findings: [{ id: 'a', title: 'Missing CSP', description: '', severity: 'high', fix: '', category: 'IAST' }],
  }));

  (await db.addSuppression(u.id, 'https://acme.test', 'Missing CSP', 'accepted risk'));

  const view = (await db.getScanWithSuppressedFindings((await db.getScan(scan.id))!));
  assert.equal(view.findings![0].isFalsePositive, true);
  assert.equal(view.score, 100, 'suppressing the only high returns the score to 100');

  // The stored row is untouched — reads must not mutate state.
  assert.equal((await db.getScan(scan.id))!.score, 75);
  assert.equal((await db.getScan(scan.id))!.findings![0].isFalsePositive, undefined);
});

test('scan ownership is queryable for authorization checks', async () => {
  const a = (await db.getOrCreateUser('owner@test.io'));
  const b = (await db.getOrCreateUser('other@test.io'));
  const scan = (await db.createScan(a.id, 'https://owned.test'));
  assert.equal((await db.getScan(scan.id))!.userId, a.id);
  assert.notEqual((await db.getScan(scan.id))!.userId, b.id);
});

test('Stripe webhook idempotency: a session is only credited once', async () => {
  const u = (await db.getOrCreateUser('billing@test.io'));
  const sessionId = 'cs_test_idem_1';
  assert.equal((await db.hasTransactionForSession(sessionId)), false);
  (await db.addCredits(u.id, 5, 'purchase', sessionId));
  assert.equal((await db.hasTransactionForSession(sessionId)), true); // retry would be skipped
});

test('user alert webhook can be set and cleared', async () => {
  const u = (await db.getOrCreateUser('hook@test.io'));
  assert.equal(u.notifyWebhook, undefined);
  assert.equal((await db.setUserWebhook(u.id, 'https://hooks.slack.com/x'))!.notifyWebhook, 'https://hooks.slack.com/x');
  assert.equal((await db.getUser(u.id))!.notifyWebhook, 'https://hooks.slack.com/x');
  assert.equal((await db.setUserWebhook(u.id, null))!.notifyWebhook, undefined);
});

test('domain verification starts pending, is idempotent, and flips to verified', async () => {
  const u = (await db.getOrCreateUser('verify@test.io'));
  assert.equal((await db.isDomainVerified(u.id, 'owned.test')), false);

  const first = (await db.startDomainVerification(u.id, 'owned.test', 'sl-verify-abc'));
  const second = (await db.startDomainVerification(u.id, 'owned.test', 'sl-verify-DIFFERENT'));
  assert.equal(second.token, first.token, 'a second "start" call reuses the pending token');

  (await db.markDomainVerified(u.id, 'owned.test'));
  assert.equal((await db.isDomainVerified(u.id, 'owned.test')), true);
  assert.equal((await db.getDomainVerification(u.id, 'owned.test'))!.verified, true);

  // Verification is scoped per-user: another user's scan of the same domain
  // is unaffected.
  const other = (await db.getOrCreateUser('notowner@test.io'));
  assert.equal((await db.isDomainVerified(other.id, 'owned.test')), false);
});

test('self-attestation no longer unlocks active probes: legacy attested domains are revoked on migrate', async () => {
  const u = (await db.getOrCreateUser('legacy-attest@test.io'));
  (await db.startDomainVerification(u.id, 'legacy.test', 'sl-verify-legacy'));
  // Simulate a row left behind by the removed attestation endpoint.
  (db as any).db
    .prepare("UPDATE domain_verifications SET verified = 1, method = 'attestation', attestation = ? WHERE userId = ? AND domain = ?")
    .run('I attest that I own legacy.test.', u.id, 'legacy.test');
  assert.equal((await db.isDomainVerified(u.id, 'legacy.test')), true, 'row is verified before the corrective migration runs');

  // Re-running the migrations (as happens on every boot) must revoke it.
  runMigrations((db as any).db);
  assert.equal((await db.isDomainVerified(u.id, 'legacy.test')), false, 'attestation-only verification is revoked');
});

test('monitoring scheduler surfaces only due targets', async () => {
  const u = (await db.getOrCreateUser('monitor@test.io'));
  const t = (await db.addMonitoredTarget(u.id, 'https://watch.test', 7));
  // Freshly added target is scheduled in the future -> not yet due.
  assert.equal((await db.listDueMonitoredTargets(new Date().toISOString())).some((x) => x.id === t.id), false);
  // Backdate its next scan -> becomes due.
  (await db.markMonitoredScanned(t.id, new Date(Date.now() - 1000).toISOString(), new Date(Date.now() - 1000).toISOString()));
  assert.equal((await db.listDueMonitoredTargets(new Date().toISOString())).some((x) => x.id === t.id), true);
});

test('OOB collaborator records callbacks only for tokens we issued, and not stale ones', async () => {
  const tok = 'a'.repeat(48);
  // Unknown token → refused (the public endpoint can't be an open write store).
  assert.equal((await db.recordOobEvent(tok, { method: 'GET', sourceIp: '1.2.3.4', path: `/api/oob/${tok}` })), false);
  assert.equal((await db.getOobEvents(tok)).length, 0);

  // Issued token → the callback is recorded and readable.
  (await db.registerOobToken(tok, 'scan_x'));
  assert.equal((await db.recordOobEvent(tok, { method: 'GET', sourceIp: '1.2.3.4', path: `/api/oob/${tok}`, userAgent: 'curl/8' })), true);
  const events = (await db.getOobEvents(tok));
  assert.equal(events.length, 1);
  assert.equal(events[0].sourceIp, '1.2.3.4');
  assert.equal(events[0].method, 'GET');

  // A different, never-issued token is still refused after a successful record.
  assert.equal((await db.recordOobEvent('b'.repeat(48), { method: 'GET', sourceIp: '9.9.9.9', path: '/x' })), false);
});

test('OOB collaborator refuses a callback for a token issued more than 15 minutes ago', async () => {
  const tok = 'c'.repeat(48);
  (await db.registerOobToken(tok, 'scan_stale'));
  // A fresh token accepts the callback...
  assert.equal((await db.recordOobEvent(tok, { method: 'GET', sourceIp: '1.2.3.4', path: `/api/oob/${tok}` })), true);

  // ...but backdate its issue time past the 15-minute window and it must be
  // refused — an old collaborator URL can't be replayed to forge a proof.
  const sixteenMinAgo = new Date(Date.now() - 16 * 60 * 1000).toISOString();
  (db as any).db.prepare('UPDATE oob_tokens SET createdAt = ? WHERE token = ?').run(sixteenMinAgo, tok);
  assert.equal((await db.recordOobEvent(tok, { method: 'GET', sourceIp: '5.6.7.8', path: `/api/oob/${tok}` })), false);
  // The stale callback left no trace; only the original in-window hit remains.
  assert.equal((await db.getOobEvents(tok)).length, 1);
  assert.equal((await db.getOobEvents(tok))[0].sourceIp, '1.2.3.4');
});

test('recoverStuckScans fails and refunds any scan left mid-flight, and leaves completed scans alone', async () => {
  const u = (await db.getOrCreateUser('stuck@test.io'));
  const creditsBefore = (await db.getUser(u.id))!.credits;

  const queued = (await db.createScan(u.id, 'https://queued.test'));
  const scanning = (await db.updateScan((await db.createScan(u.id, 'https://scanning.test')).id, { status: 'scanning' }));
  const analyzing = (await db.updateScan((await db.createScan(u.id, 'https://analyzing.test')).id, { status: 'analyzing' }));
  const completed = (await db.updateScan((await db.createScan(u.id, 'https://done.test')).id, { status: 'complete', score: 90, severity: 'low', findings: [] }));
  // Each createScan above spent nothing (createScan doesn't touch credits —
  // the route does), so the balance is still whatever it started at.
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore);

  // Other tests in this file share the same in-memory DB and may leave their
  // own scans mid-flight, so don't assume this sweep's count is exactly 3 —
  // only assert on this test's own scans and its own user's credit delta.
  const recovered = (await db.recoverStuckScans());
  assert.ok(recovered >= 3, `at least the three mid-flight scans created here must be recovered; got ${recovered}`);

  assert.equal((await db.getScan(queued.id))!.status, 'failed');
  assert.equal((await db.getScan(scanning.id))!.status, 'failed');
  assert.equal((await db.getScan(analyzing.id))!.status, 'failed');
  assert.match((await db.getScan(queued.id))!.error || '', /interrupted by a server restart/);

  // The already-completed scan must be untouched.
  assert.equal((await db.getScan(completed.id))!.status, 'complete');

  // One refund per recovered scan — this user owns exactly 3 of them, so
  // their balance must move by exactly +3 regardless of what else was swept.
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore + 3);

  // Idempotent: nothing left to recover for this user on a second sweep, so
  // no double-refund.
  (await db.recoverStuckScans());
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore + 3);
});

test('cancelScan refunds the credit and stops the scan from ever reporting a result', async () => {
  const u = (await db.getOrCreateUser('cancel@test.io'));
  const creditsBefore = (await db.getUser(u.id))!.credits;

  const scan = (await db.createScan(u.id, 'https://cancel-me.test'));
  (await db.updateScan(scan.id, { status: 'scanning' }));

  const canceled = (await db.cancelScan(u.id, scan.id));
  assert.ok(canceled);
  assert.equal(canceled!.status, 'canceled');
  assert.match(canceled!.error || '', /Canceled by user/);
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore + 1, 'the spent credit is refunded');

  // A second cancel attempt on an already-canceled scan is rejected — it's
  // no longer "in flight", so there's nothing left to cancel or refund again.
  assert.equal((await db.cancelScan(u.id, scan.id)), null);
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore + 1, 'no double-refund');
});

test('cancelScan refuses to touch a scan that already reached a terminal state', async () => {
  const u = (await db.getOrCreateUser('cancel-terminal@test.io'));
  const completed = (await db.createScan(u.id, 'https://done.test'));
  (await db.updateScan(completed.id, { status: 'complete', score: 90, severity: 'low', findings: [] }));
  const creditsBefore = (await db.getUser(u.id))!.credits;

  assert.equal((await db.cancelScan(u.id, completed.id)), null, 'a completed scan cannot be canceled');
  assert.equal((await db.getScan(completed.id))!.status, 'complete');
  assert.equal((await db.getUser(u.id))!.credits, creditsBefore, 'no refund for a scan that was never canceled');
});

test('cancelScan is scoped to the owning user', async () => {
  const owner = (await db.getOrCreateUser('cancel-owner@test.io'));
  const other = (await db.getOrCreateUser('cancel-other@test.io'));
  const scan = (await db.updateScan((await db.createScan(owner.id, 'https://mine.test')).id, { status: 'queued' }));

  assert.equal((await db.cancelScan(other.id, scan.id)), null, 'another user cannot cancel someone else\'s scan');
  assert.equal((await db.getScan(scan.id))!.status, 'queued');
});

test('healthy() returns true against a live database handle', async () => {
  // Backs the /api/system/health readiness probe: a trivial round-trip to the
  // datastore that must succeed while the handle is open.
  assert.equal((await db.healthy()), true);
});

// A redeploy restarts every replica at once, so several can read the same
// genuinely stale scan before any of them writes. The sweep therefore has to be
// a CLAIM: only the instance whose UPDATE actually moves the row out of an
// in-flight status may refund it. Without the status guard each replica refunded
// a credit for the same scan.
test('recoverStuckScans refunds exactly once even when swept repeatedly', async () => {
  const u = (await db.getOrCreateUser('sweep-race@test.io'));
  const scan = (await db.updateScan((await db.createScan(u.id, 'https://race.test')).id, { status: 'scanning' }));
  const creditsBeforeSweep = (await db.getUser(u.id))!.credits;

  // Three replicas booting together. NOTE: single-process SQLite serialises
  // these, so this cannot reproduce the interleaved SELECT the guard actually
  // defends against on Postgres — it pins the invariant (one scan, one refund,
  // however many sweepers) rather than the race itself.
  await Promise.all([db.recoverStuckScans(), db.recoverStuckScans(), db.recoverStuckScans()]);

  assert.equal(
    (await db.getUser(u.id))!.credits,
    creditsBeforeSweep + 1,
    'one interrupted scan refunds exactly one credit, no matter how many replicas sweep',
  );
  assert.equal((await db.getScan(scan!.id))!.status, 'failed');
});

// The failure this prevents is silent and total: with DATABASE_URL missing the
// selector would open the local SQLite file, which in the container is an
// ephemeral directory, so the app boots on a brand-new EMPTY database, passes
// its health check, and serves as though every user, scan and credit had
// vanished — losing anything written on the next restart.
test('production refuses to start on the SQLite fallback', () => {
  assert.throws(
    () => assertNotSilentlyFallingBack('production'),
    /DATABASE_URL is not set/,
    'a production process with no DATABASE_URL must fail loudly, not fall back',
  );
});

test('dev, test and unset environments still use SQLite freely', () => {
  // The fallback is the correct, intended path everywhere except production —
  // this whole test suite runs on it.
  for (const env of ['development', 'test', undefined]) {
    assert.doesNotThrow(() => assertNotSilentlyFallingBack(env as string | undefined), `env=${env}`);
  }
});
