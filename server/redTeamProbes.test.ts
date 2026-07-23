import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runRedTeamProbes } from './redTeamProbes.js';
import { probeSqlInjection } from './redTeam/sqlInjection.js';
import { probeReflectedXss } from './redTeam/reflectedXss.js';
import { probeBlindSsrf } from './redTeam/blindSsrf.js';
import type { ProbeContext } from './redTeam/types.js';

// Probes fetch through safeFetch, which blocks loopback unless the dev-only
// SCAN_DEV_ALLOW_HOSTS escape hatch names this exact host:port (see
// scanner.test.ts). Same pattern here so the units run against an owned local
// target with no real network access.
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

function ctxFor(port: number): ProbeContext {
  return {
    url: `http://127.0.0.1:${port}`,
    fuzzHeaders: { 'User-Agent': 'test', 'Cache-Control': 'no-cache' },
  };
}

test('probeSqlInjection returns a PROVEN finding against a DB-erroring target', async () => {
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    let body = '<!doctype html><html><body>store';
    if (u.searchParams.has('id')) {
      body += `<div>You have an error in your SQL syntax; near '${u.searchParams.get('id')}'</div>`;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body + '</body></html>');
  }, async (port) => {
    const finding = await probeSqlInjection(ctxFor(port));
    assert.ok(finding, 'expected a SQLi finding');
    assert.equal(finding!.severity, 'critical');
    assert.match(finding!.evidence!.signal.quote, /SQL syntax/i);
    // Core invariant: the quoted proof is literally present in the captured response.
    assert.ok(finding!.evidence!.attack.response.includes(finding!.evidence!.signal.quote));
  });
});

test('probeSqlInjection returns null against a benign target (no false positive)', async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>all good, no errors here</body></html>');
  }, async (port) => {
    assert.equal(await probeSqlInjection(ctxFor(port)), null);
  });
});

test('probeReflectedXss returns null when the marker is reflected inside a non-executing context', async () => {
  // Reflected, but as a JSON content-type — the execution gate must reject it.
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ echo: u.searchParams.get('q') }));
  }, async (port) => {
    assert.equal(await probeReflectedXss(ctxFor(port)), null);
  });
});

test('probeBlindSsrf no-ops when no out-of-band collaborator is configured', async () => {
  // No server needed — it must short-circuit before making any request.
  const finding = await probeBlindSsrf({ url: 'http://127.0.0.1:1', fuzzHeaders: {} });
  assert.equal(finding, null);
});

test('runRedTeamProbes isolates a throwing probe and still returns other findings', async () => {
  // The SQLi path destroys the socket (forcing that probe to throw), while the
  // XSS path reflects an executing marker. The orchestrator must swallow the
  // SQLi failure and still surface the XSS finding — proving one probe's error
  // never aborts the rest.
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.searchParams.has('id')) {
      req.destroy(); // abrupt connection reset -> fetch rejects inside probeSqlInjection
      return;
    }
    let body = '<!doctype html><html><body>';
    const q = u.searchParams.get('q');
    if (q) body += `<div>${q}</div>`; // reflected unescaped into HTML -> executes
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body + '</body></html>');
  }, async (port) => {
    const findings = await runRedTeamProbes(`http://127.0.0.1:${port}`, { 'User-Agent': 'test' });
    assert.ok(findings.some((f) => /XSS/i.test(f.testName)), 'XSS finding must survive the SQLi probe throwing');
  });
});
