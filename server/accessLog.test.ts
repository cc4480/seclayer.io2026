import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { accessLog, formatAccessLogLine } from './accessLog.js';

async function withApp(app: express.Express, fn: (base: string) => Promise<void>) {
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('formatAccessLogLine produces a single structured line', () => {
  const line = formatAccessLogLine({ method: 'GET', path: '/api/x', status: 200, durationMs: 3, ip: '1.2.3.4' });
  assert.equal(line, '[access] GET /api/x 200 3ms ip=1.2.3.4');
});

test('logs one line per finished request with the real status code', async () => {
  const lines: string[] = [];
  const app = express();
  app.use(accessLog({ write: (l) => lines.push(l) }));
  app.get('/ok', (_req, res) => res.json({ ok: true }));
  app.get('/missing', (_req, res) => res.status(404).json({ error: 'nope' }));

  await withApp(app, async (base) => {
    await fetch(`${base}/ok`);
    await fetch(`${base}/missing`);
  });

  assert.equal(lines.length, 2);
  assert.match(lines[0], /GET \/ok 200 \d+ms/);
  assert.match(lines[1], /GET \/missing 404 \d+ms/);
});

test('skips the configured skip paths (health probe by default)', async () => {
  const lines: string[] = [];
  const app = express();
  app.use(accessLog({ write: (l) => lines.push(l) }));
  app.get('/api/system/health', (_req, res) => res.json({ status: 'Online' }));
  app.get('/api/scan', (_req, res) => res.json({ ok: true }));

  await withApp(app, async (base) => {
    await fetch(`${base}/api/system/health`);
    await fetch(`${base}/api/scan`);
  });

  assert.equal(lines.length, 1, 'the health probe must not be logged');
  assert.match(lines[0], /\/api\/scan/);
});
