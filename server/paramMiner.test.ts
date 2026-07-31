import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mineReflectedParams, buildGuessedTargets } from './paramMiner.js';
import { ALWAYS_TEST_PARAMS } from './paramWordlist.js';

// Same loopback-allowlist pattern as paramFuzzer.test.ts: mining goes through
// safeFetch, which blocks loopback unless SCAN_DEV_ALLOW_HOSTS names this host.
async function withServer(handler: http.RequestListener, fn: (port: number) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const HEADERS = { 'User-Agent': 'test', 'Cache-Control': 'no-cache' };

test('mineReflectedParams keeps only the parameters the app reflects', async () => {
  // Reflects the values of `id` and `search`; ignores everything else.
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const id = u.searchParams.get('id') || '';
    const search = u.searchParams.get('search') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>id=${id} search=${search}</body></html>`);
  }, async (port) => {
    const live = await mineReflectedParams(`http://127.0.0.1:${port}/`, HEADERS, ['id', 'search', 'nope', 'other', 'file']);
    assert.ok(live.includes('id'), 'reflected "id" must be mined');
    assert.ok(live.includes('search'), 'reflected "search" must be mined');
    assert.ok(!live.includes('nope'), 'a non-reflected param must not be mined');
    assert.ok(!live.includes('file'), 'a non-reflected param must not be mined');
  });
});

test('mineReflectedParams returns nothing for a target that reflects no input', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>static page, echoes nothing</body></html>');
  }, async (port) => {
    const live = await mineReflectedParams(`http://127.0.0.1:${port}/`, HEADERS, ['id', 'q', 'search']);
    assert.equal(live.length, 0, 'no reflection → no mined params');
  });
});

test('buildGuessedTargets always includes the high-signal always-test params, plus reflected ones', async () => {
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    // Reflect a param that is NOT in the always-test set, to prove reflection adds it.
    const tag = u.searchParams.get('tag') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>tag=${tag}</body></html>`);
  }, async (port) => {
    const targets = await buildGuessedTargets([`http://127.0.0.1:${port}/`], HEADERS);
    assert.equal(targets.length, 1, 'one base path → one guessed target');
    const params = targets[0].params;
    for (const p of ALWAYS_TEST_PARAMS) {
      assert.ok(params.includes(p), `always-test param "${p}" must be present even without reflection`);
    }
    assert.ok(params.includes('tag'), 'a reflected non-default param must be added to the target');
    assert.equal(targets[0].method, 'GET');
  });
});
