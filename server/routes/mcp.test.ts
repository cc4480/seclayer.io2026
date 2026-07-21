import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';

process.env.DB_PATH = ':memory:';
const { registerMcpRoutes } = await import('./mcp.js');

async function withMcpApp(fn: (base: string) => Promise<void>) {
  const app = express();
  app.use(express.json());
  registerMcpRoutes(app, {
    requireAuth: (_req, _res, next) => next(),
    getUserId: () => '',
    processScanJob: () => {},
    cookieOptions: { httpOnly: true },
    sessionCookie: 'sl_session',
  });

  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('POST /api/mcp/scan is rate-limited per caller', async () => {
  // Regression test: this endpoint used to have no rateLimit() at all, unlike
  // every other scan-launching route, so a caller could burst unlimited
  // concurrent full-pipeline scans. The limiter runs ahead of the handler, so
  // sending requests missing `url`/`apiKey` (a fast 400, no real scan work)
  // is enough to prove the middleware is wired up without needing a live target.
  await withMcpApp(async (base) => {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      const res = await fetch(`${base}/api/mcp/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      statuses.push(res.status);
    }
    assert.ok(statuses.slice(0, 5).every((s) => s === 400), `first 5 should reach the handler (400 for missing params); got ${statuses}`);
    assert.ok(statuses.slice(5).every((s) => s === 429), `requests past the limit must be rejected by the limiter; got ${statuses}`);
  });
});
