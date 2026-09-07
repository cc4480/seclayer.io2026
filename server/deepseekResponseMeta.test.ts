import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

// Separate file from deepseekClient.test.ts on purpose: DEEPSEEK_BASE_URL is
// captured as a module-level const at import time, so one base URL per file is
// the constraint. Node runs each test file in its own process, so this gets a
// clean import against its own stub server.
//
// What this pins: a completion that stops on 'length' — reasoning ate the whole
// token budget before any JSON was emitted — must surface finish_reason and the
// token spend. generateAiReport's empty-content branch logs those, and without
// them a silent degrade to the local summary is indistinguishable in the logs
// from a healthy run. That was exactly the gap that made "the AI report isn't
// working" impossible to confirm from the outside.
test('callDeepSeek surfaces finish_reason and completion tokens on a budget-exhausted call', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      choices: [{
        // Truncated before the answer: reasoning present, content empty.
        message: { content: '', reasoning_content: 'thought at length…' },
        finish_reason: 'length',
      }],
      usage: { completion_tokens: 32000 },
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as any).port;

  try {
    process.env.DEEPSEEK_API_KEY = 'test-key';
    process.env.DEEPSEEK_BASE_URL = `http://127.0.0.1:${port}`;
    const { callDeepSeek } = await import('./deepseekClient.js');

    const r = await callDeepSeek('deepseek-v4-pro', 'prompt', {
      thinking: 'enabled', reasoningEffort: 'high', maxTokens: 32000, timeoutMs: 5000,
    });

    // Empty content is what trips generateAiReport's fallback…
    assert.equal(r.content, '');
    // …and these are what let it say WHY rather than degrading silently.
    assert.equal(r.finishReason, 'length');
    assert.equal(r.completionTokens, 32000);
    assert.match(r.reasoningContent || '', /thought at length/);
  } finally {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
  }
});
