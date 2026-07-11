import { test } from 'node:test';
import assert from 'node:assert/strict';

// Use an isolated in-memory database. Set before importing the db singleton.
process.env.DB_PATH = ':memory:';
const { db } = await import('./db.js');

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

test('attestation verifies a domain in one step and records the exact statement', () => {
  const u = db.getOrCreateUser('attest@test.io');
  assert.equal(db.isDomainVerified(u.id, 'myapp.test'), false);

  const statement = 'I attest that I own myapp.test.';
  const rec = db.attestDomainOwnership(u.id, 'myapp.test', statement);

  assert.equal(rec.verified, true);
  assert.equal(rec.method, 'attestation');
  assert.equal(rec.attestation, statement, 'the affirmed statement is stored for the audit trail');
  assert.ok(rec.verifiedAt, 'verifiedAt is set');
  assert.equal(db.isDomainVerified(u.id, 'myapp.test'), true, 'active probes are now unlocked for this user');

  // Still scoped per-user — one user attesting does not authorize another.
  const other = db.getOrCreateUser('other-attest@test.io');
  assert.equal(db.isDomainVerified(other.id, 'myapp.test'), false);
});

test('attestation upgrades an existing pending verification without losing scope', () => {
  const u = db.getOrCreateUser('attest2@test.io');
  db.startDomainVerification(u.id, 'pending.test', 'sl-verify-xyz');
  assert.equal(db.isDomainVerified(u.id, 'pending.test'), false);

  const rec = db.attestDomainOwnership(u.id, 'pending.test', 'authorized by owner');
  assert.equal(rec.verified, true);
  assert.equal(rec.method, 'attestation');
  assert.equal(db.isDomainVerified(u.id, 'pending.test'), true);
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
