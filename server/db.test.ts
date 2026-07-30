import { test } from 'node:test';
import assert from 'node:assert/strict';

// Use an isolated in-memory database. Set before importing the db singleton.
process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');
const { runMigrations } = await import('./dbSchema.js');

test('a new user receives signup credits; no API key is auto-provisioned', () => {
  const u = db.getOrCreateUser('t1@test.io');
  assert.equal(u.credits, 5);
  // A key's raw value is only ever shown once, at generateApiKey() time, so
  // signup does not create one out-of-band (it could never be displayed).
  assert.equal(db.listApiKeys(u.id).length, 0);
  // getOrCreateUser is idempotent by email
  assert.equal(db.getOrCreateUser('T1@test.io').id, u.id);
});

test('generateApiKey returns the raw secret once and stores only its hash', () => {
  const u = db.getOrCreateUser('keytest@test.io');
  const { apiKey, rawKey } = db.generateApiKey(u.id);
  assert.match(rawKey, /^sl_live_[0-9a-f]{32}$/);
  assert.equal(apiKey.keyPreview.includes(rawKey), false, 'the preview must not contain the full raw key');
  assert.equal((apiKey as any).key, undefined, 'the raw/hashed key must never be present on the returned object');

  // The key validates by its raw value (hashed internally for lookup)...
  const validated = db.validateApiKeyAndDeduct(rawKey, 1);
  assert.equal(validated?.id, u.id);
  // ...but the raw value itself is never stored, so listing keys never
  // reveals it — only the safe preview.
  const listed = db.listApiKeys(u.id);
  assert.equal(listed.some((k) => (k as any).key === rawKey), false);
});

test('deductCredits respects the balance', () => {
  const u = db.getOrCreateUser('t2@test.io');
  assert.equal(db.deductCredits(u.id, 99), false);
  assert.equal(db.deductCredits(u.id, 5), true);
  assert.equal(db.getUser(u.id)!.credits, 0);
});

test('a magic-link token is single-use and validates ownership', () => {
  const raw = db.createLoginToken('t3@test.io');
  assert.equal(db.consumeLoginToken(raw), 't3@test.io');
  assert.equal(db.consumeLoginToken(raw), null, 'token cannot be reused');
  assert.equal(db.consumeLoginToken('not-a-real-token'), null);
});

test('an expired magic-link token is rejected', () => {
  const raw = db.createLoginToken('t3b@test.io', -1); // already expired
  assert.equal(db.consumeLoginToken(raw), null);
});

test('sessions resolve to a user and can be revoked', () => {
  const u = db.getOrCreateUser('t4@test.io');
  const s = db.createSession(u.id);
  assert.equal(db.getSessionUserId(s), u.id);
  db.deleteSession(s);
  assert.equal(db.getSessionUserId(s), null);
});

test('suppression is a pure read-model: it recomputes the score without writing', () => {
  const u = db.getOrCreateUser('t5@test.io');
  const scan = db.createScan(u.id, 'https://acme.test');
  db.updateScan(scan.id, {
    status: 'complete', score: 75, severity: 'high',
    findings: [{ id: 'a', title: 'Missing CSP', description: '', severity: 'high', fix: '', category: 'IAST' }],
  });

  db.addSuppression(u.id, 'https://acme.test', 'Missing CSP', 'accepted risk');

  const view = db.getScanWithSuppressedFindings(db.getScan(scan.id)!);
  assert.equal(view.findings![0].isFalsePositive, true);
  assert.equal(view.score, 100, 'suppressing the only high returns the score to 100');

  // The stored row is untouched — reads must not mutate state.
  assert.equal(db.getScan(scan.id)!.score, 75);
  assert.equal(db.getScan(scan.id)!.findings![0].isFalsePositive, undefined);
});

test('scan ownership is queryable for authorization checks', () => {
  const a = db.getOrCreateUser('owner@test.io');
  const b = db.getOrCreateUser('other@test.io');
  const scan = db.createScan(a.id, 'https://owned.test');
  assert.equal(db.getScan(scan.id)!.userId, a.id);
  assert.notEqual(db.getScan(scan.id)!.userId, b.id);
});

test('Stripe webhook idempotency: a session is only credited once', () => {
  const u = db.getOrCreateUser('billing@test.io');
  const sessionId = 'cs_test_idem_1';
  assert.equal(db.hasTransactionForSession(sessionId), false);
  db.addCredits(u.id, 5, 'purchase', sessionId);
  assert.equal(db.hasTransactionForSession(sessionId), true); // retry would be skipped
});

test('user alert webhook can be set and cleared', () => {
  const u = db.getOrCreateUser('hook@test.io');
  assert.equal(u.notifyWebhook, undefined);
  assert.equal(db.setUserWebhook(u.id, 'https://hooks.slack.com/x')!.notifyWebhook, 'https://hooks.slack.com/x');
  assert.equal(db.getUser(u.id)!.notifyWebhook, 'https://hooks.slack.com/x');
  assert.equal(db.setUserWebhook(u.id, null)!.notifyWebhook, undefined);
});

test('domain verification starts pending, is idempotent, and flips to verified', () => {
  const u = db.getOrCreateUser('verify@test.io');
  assert.equal(db.isDomainVerified(u.id, 'owned.test'), false);

  const first = db.startDomainVerification(u.id, 'owned.test', 'sl-verify-abc');
  const second = db.startDomainVerification(u.id, 'owned.test', 'sl-verify-DIFFERENT');
  assert.equal(second.token, first.token, 'a second "start" call reuses the pending token');

  db.markDomainVerified(u.id, 'owned.test');
  assert.equal(db.isDomainVerified(u.id, 'owned.test'), true);
  assert.equal(db.getDomainVerification(u.id, 'owned.test')!.verified, true);

  // Verification is scoped per-user: another user's scan of the same domain
  // is unaffected.
  const other = db.getOrCreateUser('notowner@test.io');
  assert.equal(db.isDomainVerified(other.id, 'owned.test'), false);
});

test('self-attestation no longer unlocks active probes: legacy attested domains are revoked on migrate', () => {
  const u = db.getOrCreateUser('legacy-attest@test.io');
  db.startDomainVerification(u.id, 'legacy.test', 'sl-verify-legacy');
  // Simulate a row left behind by the removed attestation endpoint.
  (db as any).db
    .prepare("UPDATE domain_verifications SET verified = 1, method = 'attestation', attestation = ? WHERE userId = ? AND domain = ?")
    .run('I attest that I own legacy.test.', u.id, 'legacy.test');
  assert.equal(db.isDomainVerified(u.id, 'legacy.test'), true, 'row is verified before the corrective migration runs');

  // Re-running the migrations (as happens on every boot) must revoke it.
  runMigrations((db as any).db);
  assert.equal(db.isDomainVerified(u.id, 'legacy.test'), false, 'attestation-only verification is revoked');
});

test('monitoring scheduler surfaces only due targets', () => {
  const u = db.getOrCreateUser('monitor@test.io');
  const t = db.addMonitoredTarget(u.id, 'https://watch.test', 7);
  // Freshly added target is scheduled in the future -> not yet due.
  assert.equal(db.listDueMonitoredTargets(new Date().toISOString()).some((x) => x.id === t.id), false);
  // Backdate its next scan -> becomes due.
  db.markMonitoredScanned(t.id, new Date(Date.now() - 1000).toISOString(), new Date(Date.now() - 1000).toISOString());
  assert.equal(db.listDueMonitoredTargets(new Date().toISOString()).some((x) => x.id === t.id), true);
});

test('OOB collaborator records callbacks only for tokens we issued, and not stale ones', () => {
  const tok = 'a'.repeat(48);
  // Unknown token → refused (the public endpoint can't be an open write store).
  assert.equal(db.recordOobEvent(tok, { method: 'GET', sourceIp: '1.2.3.4', path: `/api/oob/${tok}` }), false);
  assert.equal(db.getOobEvents(tok).length, 0);

  // Issued token → the callback is recorded and readable.
  db.registerOobToken(tok, 'scan_x');
  assert.equal(db.recordOobEvent(tok, { method: 'GET', sourceIp: '1.2.3.4', path: `/api/oob/${tok}`, userAgent: 'curl/8' }), true);
  const events = db.getOobEvents(tok);
  assert.equal(events.length, 1);
  assert.equal(events[0].sourceIp, '1.2.3.4');
  assert.equal(events[0].method, 'GET');

  // A different, never-issued token is still refused after a successful record.
  assert.equal(db.recordOobEvent('b'.repeat(48), { method: 'GET', sourceIp: '9.9.9.9', path: '/x' }), false);
});

test('OOB collaborator refuses a callback for a token issued more than 15 minutes ago', () => {
  const tok = 'c'.repeat(48);
  db.registerOobToken(tok, 'scan_stale');
  // A fresh token accepts the callback...
  assert.equal(db.recordOobEvent(tok, { method: 'GET', sourceIp: '1.2.3.4', path: `/api/oob/${tok}` }), true);

  // ...but backdate its issue time past the 15-minute window and it must be
  // refused — an old collaborator URL can't be replayed to forge a proof.
  const sixteenMinAgo = new Date(Date.now() - 16 * 60 * 1000).toISOString();
  (db as any).db.prepare('UPDATE oob_tokens SET createdAt = ? WHERE token = ?').run(sixteenMinAgo, tok);
  assert.equal(db.recordOobEvent(tok, { method: 'GET', sourceIp: '5.6.7.8', path: `/api/oob/${tok}` }), false);
  // The stale callback left no trace; only the original in-window hit remains.
  assert.equal(db.getOobEvents(tok).length, 1);
  assert.equal(db.getOobEvents(tok)[0].sourceIp, '1.2.3.4');
});

test('recoverStuckScans fails and refunds any scan left mid-flight, and leaves completed scans alone', () => {
  const u = db.getOrCreateUser('stuck@test.io');
  const creditsBefore = db.getUser(u.id)!.credits;

  const queued = db.createScan(u.id, 'https://queued.test');
  const scanning = db.updateScan(db.createScan(u.id, 'https://scanning.test').id, { status: 'scanning' });
  const analyzing = db.updateScan(db.createScan(u.id, 'https://analyzing.test').id, { status: 'analyzing' });
  const completed = db.updateScan(db.createScan(u.id, 'https://done.test').id, { status: 'complete', score: 90, severity: 'low', findings: [] });
  // Each createScan above spent nothing (createScan doesn't touch credits —
  // the route does), so the balance is still whatever it started at.
  assert.equal(db.getUser(u.id)!.credits, creditsBefore);

  // Other tests in this file share the same in-memory DB and may leave their
  // own scans mid-flight, so don't assume this sweep's count is exactly 3 —
  // only assert on this test's own scans and its own user's credit delta.
  const recovered = db.recoverStuckScans();
  assert.ok(recovered >= 3, `at least the three mid-flight scans created here must be recovered; got ${recovered}`);

  assert.equal(db.getScan(queued.id)!.status, 'failed');
  assert.equal(db.getScan(scanning.id)!.status, 'failed');
  assert.equal(db.getScan(analyzing.id)!.status, 'failed');
  assert.match(db.getScan(queued.id)!.error || '', /interrupted by a server restart/);

  // The already-completed scan must be untouched.
  assert.equal(db.getScan(completed.id)!.status, 'complete');

  // One refund per recovered scan — this user owns exactly 3 of them, so
  // their balance must move by exactly +3 regardless of what else was swept.
  assert.equal(db.getUser(u.id)!.credits, creditsBefore + 3);

  // Idempotent: nothing left to recover for this user on a second sweep, so
  // no double-refund.
  db.recoverStuckScans();
  assert.equal(db.getUser(u.id)!.credits, creditsBefore + 3);
});

test('cancelScan refunds the credit and stops the scan from ever reporting a result', () => {
  const u = db.getOrCreateUser('cancel@test.io');
  const creditsBefore = db.getUser(u.id)!.credits;

  const scan = db.createScan(u.id, 'https://cancel-me.test');
  db.updateScan(scan.id, { status: 'scanning' });

  const canceled = db.cancelScan(u.id, scan.id);
  assert.ok(canceled);
  assert.equal(canceled!.status, 'canceled');
  assert.match(canceled!.error || '', /Canceled by user/);
  assert.equal(db.getUser(u.id)!.credits, creditsBefore + 1, 'the spent credit is refunded');

  // A second cancel attempt on an already-canceled scan is rejected — it's
  // no longer "in flight", so there's nothing left to cancel or refund again.
  assert.equal(db.cancelScan(u.id, scan.id), null);
  assert.equal(db.getUser(u.id)!.credits, creditsBefore + 1, 'no double-refund');
});

test('cancelScan refuses to touch a scan that already reached a terminal state', () => {
  const u = db.getOrCreateUser('cancel-terminal@test.io');
  const completed = db.createScan(u.id, 'https://done.test');
  db.updateScan(completed.id, { status: 'complete', score: 90, severity: 'low', findings: [] });
  const creditsBefore = db.getUser(u.id)!.credits;

  assert.equal(db.cancelScan(u.id, completed.id), null, 'a completed scan cannot be canceled');
  assert.equal(db.getScan(completed.id)!.status, 'complete');
  assert.equal(db.getUser(u.id)!.credits, creditsBefore, 'no refund for a scan that was never canceled');
});

test('cancelScan is scoped to the owning user', () => {
  const owner = db.getOrCreateUser('cancel-owner@test.io');
  const other = db.getOrCreateUser('cancel-other@test.io');
  const scan = db.updateScan(db.createScan(owner.id, 'https://mine.test').id, { status: 'queued' });

  assert.equal(db.cancelScan(other.id, scan.id), null, 'another user cannot cancel someone else\'s scan');
  assert.equal(db.getScan(scan.id)!.status, 'queued');
});

test('healthy() returns true against a live database handle', () => {
  // Backs the /api/system/health readiness probe: a trivial round-trip to the
  // datastore that must succeed while the handle is open.
  assert.equal(db.healthy(), true);
});
