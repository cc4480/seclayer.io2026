import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

// DEEPSEEK_BASE_URL is captured as a module-level const at import time, so it
// must be set before the first import — same pattern as db.test.ts's
// DB_PATH override. This file exists solely to test the timeout wiring
// against a stalled backend, so one fixed base URL for the whole file is fine.
async function withHangingServer(fn: (port: number) => Promise<void>) {
  const server = http.createServer(() => {
    // Never responds — simulates a stalled DeepSeek call or a hung proxy in
    // front of it, the exact scenario the timeout exists to bound.
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as any).port;
  try {
    await fn(port);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
}

test('callDeepSeek aborts a stalled request at timeoutMs instead of hanging forever', async () => {
  await withHangingServer(async (port) => {
    process.env.DEEPSEEK_API_KEY = 'test-key';
    process.env.DEEPSEEK_BASE_URL = `http://127.0.0.1:${port}`;
    const { callDeepSeek } = await import('./deepseekClient.js');

    const start = Date.now();
    await assert.rejects(
      callDeepSeek('deepseek-v4-flash', 'prompt', { thinking: 'disabled', maxTokens: 100, timeoutMs: 300 }),
      /timed out after 300ms/,
      'a stalled call must reject with a clear timeout message, not hang'
    );
    const elapsed = Date.now() - start;
    // Generous upper bound so this isn't flaky under CI load, but tight
    // enough to prove it didn't just hang until some unrelated default.
    assert.ok(elapsed < 3000, `expected the abort to fire near timeoutMs=300, took ${elapsed}ms`);
  });
});
