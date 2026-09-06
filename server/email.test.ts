import { test } from 'node:test';
import assert from 'node:assert/strict';

// email.ts reads RESEND_API_KEY and REPLY_TO_EMAIL once at module load, so
// each case that needs a particular combination gets its own dynamic import
// of a fresh module instance rather than mutating a shared one.
async function freshEmailModule(env: Record<string, string | undefined>) {
  const saved: Record<string, string | undefined> = {};
  for (const k of ['RESEND_API_KEY', 'REPLY_TO_EMAIL', 'EMAIL_FROM']) {
    saved[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    // Cache-busting query param forces Node to re-evaluate the module with
    // the env vars set above, rather than returning the already-loaded one.
    return await import(`./email.js?t=${Date.now()}-${Math.random()}`);
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

function mockFetch(capture: { body?: unknown }) {
  const original = globalThis.fetch;
  globalThis.fetch = (async (_url: string, init: RequestInit) => {
    capture.body = JSON.parse(String(init.body));
    return new Response('{}', { status: 200 });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

test('sendEmail attaches reply_to when REPLY_TO_EMAIL is set', async () => {
  const { sendEmail } = await freshEmailModule({
    RESEND_API_KEY: 'test-key',
    REPLY_TO_EMAIL: 'hello@seclayer.app',
  });

  const capture: { body?: unknown } = {};
  const restore = mockFetch(capture);
  try {
    await sendEmail({ to: 'user@example.com', subject: 'Hi', html: '<p>hi</p>' });
  } finally {
    restore();
  }

  assert.equal((capture.body as { reply_to?: string }).reply_to, 'hello@seclayer.app');
});

test('sendEmail omits reply_to when REPLY_TO_EMAIL is unset', async () => {
  const { sendEmail } = await freshEmailModule({
    RESEND_API_KEY: 'test-key',
    REPLY_TO_EMAIL: undefined,
  });

  const capture: { body?: unknown } = {};
  const restore = mockFetch(capture);
  try {
    await sendEmail({ to: 'user@example.com', subject: 'Hi', html: '<p>hi</p>' });
  } finally {
    restore();
  }

  assert.equal('reply_to' in (capture.body as object), false);
});

test('sendEmail trims REPLY_TO_EMAIL and ignores an empty value', async () => {
  const { sendEmail } = await freshEmailModule({
    RESEND_API_KEY: 'test-key',
    REPLY_TO_EMAIL: '   ',
  });

  const capture: { body?: unknown } = {};
  const restore = mockFetch(capture);
  try {
    await sendEmail({ to: 'user@example.com', subject: 'Hi', html: '<p>hi</p>' });
  } finally {
    restore();
  }

  assert.equal('reply_to' in (capture.body as object), false);
});
