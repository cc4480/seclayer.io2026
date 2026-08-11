import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
process.env.FREE_MODE = 'false'; // exercise the paid credit flow
delete process.env.DEEPSEEK_API_KEY; // these tests never expect a real DeepSeek call to succeed
const { db } = await import('../db.js');
const { registerAutofixRoutes } = await import('./autofix.js');

async function withAutofixApp(fn: (base: string) => Promise<void>) {
  const app = express();
  app.use(express.json());
  registerAutofixRoutes(app);

  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// NOTE: rateLimit.ts's bucket state is a module-level singleton shared by every
// test in this file/process, keyed by client IP + the limiter's keyPrefix (see
// the identical note in mcp.test.ts). "mcp-autofix-start" allows 5/min — tests
// that only need a session to exist create one directly via db.createAutofixSession
// rather than going through the rate-limited route, so the budget is reserved
// for the tests that actually exercise /start. The dedicated rate-limit test is
// declared LAST so it doesn't starve anything declared after it.

test('POST /api/mcp/autofix/start creates an active session and deducts exactly one credit', async () => {
  const user = (await db.getOrCreateUser(`autofix-start-${Date.now()}@test.io`));
  const { rawKey } = (await db.generateApiKey(user.id));
  const creditsBefore = (await db.getUser(user.id))!.credits;

  await withAutofixApp(async (base) => {
    const res = await fetch(`${base}/api/mcp/autofix/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: rawKey, url: 'https://93.184.216.34', findingTitle: 'Missing CSP header', findingCategory: 'IAST' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.ok(body.sessionId);
    assert.equal(body.creditsRemaining, creditsBefore - 1);

    const session = (await db.getAutofixSession(body.sessionId));
    assert.ok(session);
    assert.equal(session!.userId, user.id);
    assert.equal(session!.status, 'active');
    assert.equal(session!.turns, 0);
  });

  assert.equal((await db.getUser(user.id))!.credits, creditsBefore - 1);
});

test('POST /api/mcp/autofix/start 401s with an invalid key and spends nothing', async () => {
  await withAutofixApp(async (base) => {
    const res = await fetch(`${base}/api/mcp/autofix/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: 'sl_live_not_a_real_key', url: 'https://93.184.216.34', findingTitle: 'x', findingCategory: 'IAST' }),
    });
    assert.equal(res.status, 401);
  });
});

test('POST /api/mcp/autofix/turn 404s a session that belongs to a different key', async () => {
  const owner = (await db.getOrCreateUser(`autofix-turn-owner-${Date.now()}@test.io`));
  const other = (await db.getOrCreateUser(`autofix-turn-other-${Date.now()}@test.io`));
  const { rawKey: otherKey } = (await db.generateApiKey(other.id));
  const session = (await db.createAutofixSession(owner.id, 'https://93.184.216.34', 'Missing CSP header', 'IAST'));

  await withAutofixApp(async (base) => {
    const res = await fetch(`${base}/api/mcp/autofix/turn`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: otherKey, sessionId: session.id, messages: [{ role: 'user', content: 'hi' }] }),
    });
    assert.equal(res.status, 404);
  });
});

test('POST /api/mcp/autofix/turn 409s once the session is no longer active', async () => {
  const user = (await db.getOrCreateUser(`autofix-turn-done-${Date.now()}@test.io`));
  const { rawKey } = (await db.generateApiKey(user.id));
  const session = (await db.createAutofixSession(user.id, 'https://93.184.216.34', 'Missing CSP header', 'IAST'));
  (await db.completeAutofixSession(session.id, 'done'));

  await withAutofixApp(async (base) => {
    const res = await fetch(`${base}/api/mcp/autofix/turn`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: rawKey, sessionId: session.id, messages: [{ role: 'user', content: 'hi' }] }),
    });
    assert.equal(res.status, 409);
    assert.equal((await res.json()).status, 'done');
  });
});

test('POST /api/mcp/autofix/turn 409s and expires the session once the turn cap is reached', async () => {
  const user = (await db.getOrCreateUser(`autofix-turn-cap-${Date.now()}@test.io`));
  const { rawKey } = (await db.generateApiKey(user.id));
  const session = (await db.createAutofixSession(user.id, 'https://93.184.216.34', 'Missing CSP header', 'IAST'));
  for (let i = 0; i < 25; i++) (await db.incrementAutofixTurn(session.id));

  await withAutofixApp(async (base) => {
    const res = await fetch(`${base}/api/mcp/autofix/turn`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: rawKey, sessionId: session.id, messages: [{ role: 'user', content: 'hi' }] }),
    });
    assert.equal(res.status, 409);
    assert.equal((await res.json()).status, 'expired');
  });

  assert.equal((await db.getAutofixSession(session.id))!.status, 'expired');
});

test('POST /api/mcp/autofix/turn fails cleanly without DEEPSEEK_API_KEY and consumes no turn', async () => {
  // Regression guard: a DeepSeek-side failure must not silently advance the
  // turn counter or flip the session's status — the caller should be able to
  // retry the exact same turn.
  const user = (await db.getOrCreateUser(`autofix-turn-nokey-${Date.now()}@test.io`));
  const { rawKey } = (await db.generateApiKey(user.id));
  const session = (await db.createAutofixSession(user.id, 'https://93.184.216.34', 'Missing CSP header', 'IAST'));

  await withAutofixApp(async (base) => {
    const res = await fetch(`${base}/api/mcp/autofix/turn`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: rawKey, sessionId: session.id, messages: [{ role: 'user', content: 'hi' }] }),
    });
    assert.equal(res.status, 500);
  });

  const after = (await db.getAutofixSession(session.id))!;
  assert.equal(after.turns, 0, 'a failed turn must not be counted');
  assert.equal(after.status, 'active', 'a failed turn must not change session status');
});

test('POST /api/mcp/autofix/start is rate-limited per caller', async () => {
  // Declared LAST: deliberately exhausts the shared "mcp-autofix-start" bucket
  // (5/min), which would starve any test declared after it. Sends requests
  // missing required params (a fast 400, no credit spent) to prove the limiter
  // sits ahead of the handler, mirroring mcp.test.ts's equivalent check.
  await withAutofixApp(async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${base}/api/mcp/autofix/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      statuses.push(res.status);
    }
    assert.ok(statuses.every((s) => s === 400 || s === 429), `only 400/429 expected; got ${statuses}`);
    const firstLimitedIndex = statuses.indexOf(429);
    assert.ok(firstLimitedIndex !== -1, `the limiter never kicked in; got ${statuses}`);
    assert.ok(statuses.slice(firstLimitedIndex).every((s) => s === 429), `once limited, every subsequent request must stay 429; got ${statuses}`);
  });
});
