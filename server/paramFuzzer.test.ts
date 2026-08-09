import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fuzzDiscoveredTargets } from './paramFuzzer.js';
import type { InjectableTarget } from './crawler.js';

// The fuzzer reaches targets through safeFetch, which blocks loopback unless the
// dev-only SCAN_DEV_ALLOW_HOSTS escape hatch names this exact host:port (see
// scanner.test.ts / redTeamProbes.test.ts). Same pattern here so the units run
// against an owned local target with no real network access.
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

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => (d += c));
    req.on('end', () => resolve(d));
  });
}

const HEADERS = { 'User-Agent': 'test', 'Cache-Control': 'no-cache' };

test('fuzzer confirms reflected XSS in a POST form field (PROVEN, POST receipt)', async () => {
  // A form endpoint that reflects the posted `q` field unescaped into HTML —
  // the classic reflected-XSS-via-POST case the GET-only fuzzer used to miss.
  await withServer(async (req, res) => {
    if (req.method !== 'POST') { res.writeHead(405); return res.end('GET not allowed'); }
    const body = await readBody(req);
    const q = new URLSearchParams(body).get('q') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body><div>${q}</div></body></html>`);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/search`, method: 'POST', params: ['q'], source: 'form' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    const xss = findings.find((f) => /Reflected XSS/i.test(f.testName));
    assert.ok(xss, 'expected a reflected-XSS finding on the POST form field');
    // Core invariant: the quoted proof is literally present in the captured response.
    assert.ok(xss.evidence.attack.response.includes(xss.evidence.signal.quote));
    // The receipt must show the real POST exchange, not a fabricated GET.
    assert.match(xss.evidence.attack.request, /^POST \/search/m, 'raw request must be a POST');
    assert.match(xss.evidence.attack.request, /Content-Type: application\/x-www-form-urlencoded/i);
    assert.match(xss.evidence.reproduction, /-X POST/, 'reproduction curl must be a POST');
  });
});

test('fuzzer confirms SQL injection in a POST form field (PROVEN, differential baseline stays clean)', async () => {
  // Emits a DB error only when the posted `id` carries a SQL metacharacter, so a
  // benign baseline stays clean and the differential guard lets the finding fire.
  await withServer(async (req, res) => {
    const body = await readBody(req);
    const id = new URLSearchParams(body).get('id') || '';
    let html = '<!doctype html><html><body>orders';
    if (/['"]/.test(id)) html += `<pre>You have an error in your SQL syntax; near '${id}'</pre>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html + '</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/orders`, method: 'POST', params: ['id'], source: 'form' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    const sqli = findings.find((f) => /SQL Injection/i.test(f.testName));
    assert.ok(sqli, 'expected a SQLi finding on the POST form field');
    assert.equal(sqli.severity, 'critical');
    assert.match(sqli.evidence.signal.quote, /SQL syntax/i);
    assert.ok(sqli.evidence.attack.response.includes(sqli.evidence.signal.quote));
    assert.match(sqli.evidence.attack.request, /^POST \/orders/m);
  });
});

test('fuzzer confirms SQLi via a REAL raw `pg` (node-postgres) error message (regression)', async () => {
  // Confirmed empirically against a real local Postgres instance
  // (test-targets/tier3-baas-supabase): a genuine `pg` client's syntax error
  // for the fuzzer's very first breaker (a bare "'") is exactly
  // `unterminated quoted string at or near "' limit 10"` — not the
  // "PostgreSQL.*?ERROR"/"PG::\w*Error" wrapped forms other-language
  // drivers print, which is all the previous signature covered.
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const query = u.searchParams.get('query') || '';
    let html = '<!doctype html><html><body>results';
    if (query.includes("'")) {
      html += `<pre>{"error":"unterminated quoted string at or near \\"' limit 10\\""}</pre>`;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html + '</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/api/search`, method: 'GET', params: ['query'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    const sqli = findings.find((f) => /SQL Injection/i.test(f.testName));
    assert.ok(sqli, 'expected a SQLi finding from the real pg driver error text');
    assert.equal(sqli.severity, 'critical');
    assert.match(sqli.evidence.signal.quote, /unterminated quoted string at or near/i);
  });
});

test('fuzzer reports no false positive for a POST form that safely echoes into JSON', async () => {
  // Reflects the posted value, but as application/json — the XSS execution gate
  // must reject it, and there is no DB error, so nothing should be reported.
  await withServer(async (req, res) => {
    const body = await readBody(req);
    const q = new URLSearchParams(body).get('q') || '';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ youSent: q }));
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/api/echo`, method: 'POST', params: ['q'], source: 'form' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    assert.equal(findings.length, 0, 'a JSON-echoing POST form must not yield any finding');
  });
});

test('fuzzer still confirms reflected XSS in a GET query parameter (regression)', async () => {
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const q = u.searchParams.get('q') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body><div>${q}</div></body></html>`);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/page`, method: 'GET', params: ['q'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    const xss = findings.find((f) => /Reflected XSS/i.test(f.testName));
    assert.ok(xss, 'GET-parameter XSS must still be detected');
    assert.match(xss.evidence.attack.request, /^GET \/page/m, 'GET receipt unchanged');
    assert.match(xss.evidence.reproduction, /^curl -s "http/, 'GET reproduction unchanged');
  });
});

test('aggressive tier confirms TIME-BASED BLIND SQLi via a response-time differential', async () => {
  // A blind endpoint: no SQL error, no reflection — the ONLY signal is that a
  // response is delayed by however many seconds the injected SLEEP(n) asked for.
  // The probe must confirm via the scaling differential (4s clearly > 1s > base).
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const id = u.searchParams.get('id') || '';
    const m = /SLEEP\((\d+)\)/i.exec(id); // simulate a DB sleep that tracks the payload
    const delayMs = m ? Math.min(Number(m[1]), 8) * 1000 : 0;
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body>ok</body></html>'); // nothing reflected, no error
    }, delayMs);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/data`, method: 'GET', params: ['id'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    const timed = findings.find((f) => /time-based blind/i.test(f.testName));
    assert.ok(timed, 'expected a time-based blind SQLi finding on the delaying parameter');
    assert.equal(timed.severity, 'critical');
    assert.ok(!timed.evidence, 'a time-based finding carries no inline receipt — the proof is the timing');
  });
});

test('time-based blind SQLi does NOT false-positive on a uniformly slow endpoint', async () => {
  // Every response is slow by a FIXED amount regardless of payload. The delay does
  // not scale with the injected sleep, so the scaling confirmation must reject it.
  await withServer((req, res) => {
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><html><body>ok</body></html>');
    }, 300); // constant latency, unrelated to any SLEEP(n) — must not read as a delay
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/slow`, method: 'GET', params: ['id'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    assert.ok(!findings.some((f) => /time-based blind/i.test(f.testName)), 'fixed latency must not be reported as time-based SQLi');
  });
});

test('fuzzer confirms SQLi injected into a JSON request body (application/json)', async () => {
  // An API endpoint that only accepts JSON. The fuzzer must send a JSON body and
  // the receipt must reflect the real application/json POST, not a form body.
  await withServer(async (req, res) => {
    const body = await readBody(req);
    let id = '';
    try { id = String(JSON.parse(body).id ?? ''); } catch { /* not json */ }
    let html = '<!doctype html><html><body>orders';
    if (/['"]/.test(id)) html += `<pre>You have an error in your SQL syntax; near '${id}'</pre>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html + '</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/api/orders`, method: 'POST', params: ['id'], source: 'script', contentType: 'json' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    const sqli = findings.find((f) => /SQL Injection/i.test(f.testName));
    assert.ok(sqli, 'expected a SQLi finding via the JSON body');
    assert.ok(sqli.evidence.attack.response.includes(sqli.evidence.signal.quote));
    assert.match(sqli.evidence.attack.request, /^POST \/api\/orders/m, 'raw request must be a POST');
    assert.match(sqli.evidence.attack.request, /Content-Type: application\/json/i, 'body must be sent as JSON');
  });
});

test('aggressive tier confirms SSTI in a POST form field (arithmetic oracle)', async () => {
  // Evaluates the posted `name` as a template only when it is a {{a*b}} form,
  // returning the computed product (which the literal payload never contains).
  await withServer(async (req, res) => {
    const body = await readBody(req);
    const name = new URLSearchParams(body).get('name') || '';
    let rendered = name;
    const m = /^\{\{(\d+)\*(\d+)\}\}$/.exec(name);
    if (m) rendered = String(Number(m[1]) * Number(m[2]));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!doctype html><html><body>Hello ${rendered}</body></html>`);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/greet`, method: 'POST', params: ['name'], source: 'form' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    const ssti = findings.find((f) => /Template Injection/i.test(f.testName));
    assert.ok(ssti, 'expected an SSTI finding on the POST form field');
    assert.ok(ssti.evidence.attack.response.includes(ssti.evidence.signal.quote));
    assert.match(ssti.evidence.attack.request, /^POST \/greet/m);
  });
});
