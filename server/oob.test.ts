import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOobCollaborator, OobStore } from './oob.js';
import { OobEvent } from '../src/types.js';

// A minimal in-memory store standing in for SqliteDb — the collaborator only
// needs registerOobToken/getOobEvents (see the OobStore surface in oob.ts).
function fakeStore() {
  const tokens = new Set<string>();
  const events = new Map<string, OobEvent[]>();
  const store: OobStore = {
    registerOobToken: (t: string) => { tokens.add(t); },
    getOobEvents: (t: string) => events.get(t) || [],
  };
  // Test helper: simulate the public endpoint recording a callback.
  const fire = (t: string, ev: Partial<OobEvent> = {}) => {
    const arr = events.get(t) || [];
    arr.push({ id: 'e' + arr.length, token: t, method: 'GET', sourceIp: '127.0.0.1', path: `/api/oob/${t}`, receivedAt: new Date().toISOString(), ...ev });
    events.set(t, arr);
  };
  return { store, tokens, fire };
}

test('issue() mints a unique, registered, unguessable token and a well-formed URL', () => {
  const { store, tokens } = fakeStore();
  const oob = createOobCollaborator(store, 'https://scan.example.com');
  const seen = new Set<string>();
  for (let i = 0; i < 100; i++) {
    const probe = oob.issue('scan_1');
    // 24 random bytes → 48 lowercase hex chars.
    assert.match(probe.token, /^[a-f0-9]{48}$/);
    assert.equal(probe.url, `https://scan.example.com/api/oob/${probe.token}`);
    assert.ok(tokens.has(probe.token), 'the token must be registered with the store');
    assert.ok(!seen.has(probe.token), 'tokens must never collide');
    seen.add(probe.token);
  }
});

test('issue() trims a trailing slash from the base URL so the callback path is clean', () => {
  const { store } = fakeStore();
  const oob = createOobCollaborator(store, 'https://scan.example.com/');
  const probe = oob.issue();
  assert.equal(probe.url, `https://scan.example.com/api/oob/${probe.token}`);
  assert.ok(!probe.url.includes('//api/'), 'no double slash before /api');
});

test('poll() fast-path returns a callback already recorded before polling starts', async () => {
  const { store, fire } = fakeStore();
  const oob = createOobCollaborator(store, 'https://scan.example.com');
  const probe = oob.issue();
  fire(probe.token, { sourceIp: '203.0.113.9' });
  const started = Date.now();
  const ev = await oob.poll(probe.token, 8000);
  assert.ok(ev, 'an already-present callback must resolve immediately');
  assert.equal(ev!.sourceIp, '203.0.113.9');
  // Fast path: it must not wait out the timeout window.
  assert.ok(Date.now() - started < 300, 'the fast path must not sleep for a poll interval');
});

test('poll() picks up a callback that arrives during the wait window', async () => {
  const { store, fire } = fakeStore();
  const oob = createOobCollaborator(store, 'https://scan.example.com');
  const probe = oob.issue();
  // Nothing recorded yet; fire the callback shortly after polling begins.
  setTimeout(() => fire(probe.token, { sourceIp: '198.51.100.7' }), 250);
  const ev = await oob.poll(probe.token, 4000);
  assert.ok(ev, 'a callback arriving mid-wait must be picked up');
  assert.equal(ev!.sourceIp, '198.51.100.7');
});

test('poll() resolves null when no callback ever arrives within the timeout', async () => {
  const { store } = fakeStore();
  const oob = createOobCollaborator(store, 'https://scan.example.com');
  const probe = oob.issue();
  const started = Date.now();
  const ev = await oob.poll(probe.token, 700); // short window: no callback
  assert.equal(ev, null, 'no callback → null, never a fabricated event');
  assert.ok(Date.now() - started >= 700, 'it must honor the full timeout before giving up');
});
