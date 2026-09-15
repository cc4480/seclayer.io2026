import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  fuzzDiscoveredTargets,
  normalizeForComparison,
  responsesEquivalent,
  responsesDistinct,
  booleanBlindConfirmed,
  extractHiddenToken,
  type CmpResponse,
} from './paramFuzzer.js';
import { isProven } from './scoring.js';
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
    // It now carries a receipt — the benign baseline and the injected-sleep
    // exchanges with their measured latencies. The proof is the timing, so
    // there is no reflected quote (signal.quote empty) and it stays CONFIRMED,
    // never PROVEN (isProven is false without a quote).
    assert.ok(timed.evidence, 'a time-based finding now carries a differential receipt');
    assert.equal(timed.evidence.method, 'differential');
    assert.ok(timed.evidence.baseline, 'the receipt includes the benign baseline exchange');
    assert.equal(timed.evidence.signal.quote, '', 'timing proof has no reflected quote');
    assert.equal(isProven(timed), false, 'a timing differential is CONFIRMED, not PROVEN');
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

// --- Boolean-based blind SQLi: the pure oracle (false-positive-critical) -----

const R = (status: number, norm: string): CmpResponse => ({ status, norm });
// A stable 400-char normalized page, and a clearly-different one (~200 chars).
const FULL = "x".repeat(400);
const EMPTY = "x".repeat(200);

test('normalizeForComparison strips the volatile parts a boolean compare must ignore', () => {
  const a = normalizeForComparison('<html> id 12345 <script>var t=1699999999</script> <b>Results</b> token=abcdef0123456789</html>');
  const b = normalizeForComparison('<html> id 98765 <script>var t=1700000042</script> <b>Results</b> token=fedcba9876543210</html>');
  // Different digits, script bodies and tokens — same structural text.
  assert.equal(a, b);
});

test('responsesEquivalent / responsesDistinct honour the status and the dead zone', () => {
  assert.equal(responsesEquivalent(R(200, FULL), R(200, FULL)), true);
  assert.equal(responsesEquivalent(R(200, FULL), R(500, FULL)), false, 'status mismatch is never equivalent');
  assert.equal(responsesDistinct(R(200, FULL), R(200, EMPTY)), true);
  // An 18-char (~4.5%) difference sits in the dead zone: past the 2% equivalence
  // tolerance (12 chars) but short of the 5% distinctness floor (24 chars).
  const near = "x".repeat(418);
  assert.equal(responsesEquivalent(R(200, FULL), R(200, near)), false);
  assert.equal(responsesDistinct(R(200, FULL), R(200, near)), false);
});

test('booleanBlindConfirmed fires only on the true≈base / false≠base pattern, twice', () => {
  const base = R(200, FULL);
  // Real boolean-blind: both TRUE match baseline, both FALSE clearly differ and agree.
  assert.equal(booleanBlindConfirmed(base, R(200, FULL), R(200, EMPTY), R(200, FULL), R(200, EMPTY)), true);
});

test('booleanBlindConfirmed rejects a page that never changes (no injection)', () => {
  const base = R(200, FULL);
  assert.equal(booleanBlindConfirmed(base, R(200, FULL), R(200, FULL), R(200, FULL), R(200, FULL)), false);
});

test('booleanBlindConfirmed rejects when only ONE pair separates (coincidence, not reproduced)', () => {
  const base = R(200, FULL);
  // First pair looks right, the confirmation pair does not reproduce it.
  assert.equal(booleanBlindConfirmed(base, R(200, FULL), R(200, EMPTY), R(200, FULL), R(200, FULL)), false);
});

test('booleanBlindConfirmed rejects when the TRUE condition already differs from baseline', () => {
  const base = R(200, FULL);
  // e.g. a page that reflects the payload: TRUE no longer matches baseline.
  assert.equal(booleanBlindConfirmed(base, R(200, EMPTY), R(200, EMPTY), R(200, EMPTY), R(200, EMPTY)), false);
});

// --- Boolean-based blind SQLi: end to end -----------------------------------

// Simulate SELECT ... WHERE id='<id>': a benign value and any TRUE condition
// match a row (full page); a FALSE condition (1=2 / 7=8) matches nothing (short
// page). Nothing is reflected and no error is shown — pure boolean-blind.
function conditionIsFalse(v: string): boolean {
  return /and\s+1\s*=\s*2/i.test(v) || /and\s+7\s*=\s*8/i.test(v);
}

test('fuzzer confirms boolean-based blind SQLi (differential, two-pair confirmed)', async () => {
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const id = u.searchParams.get('id') || '';
    const found = !conditionIsFalse(id);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    // No reflection of `id`, no SQL error — only the row count moves the page.
    res.end(found
      ? `<!doctype html><html><body><h1>Order</h1>${'<li>item</li>'.repeat(30)}</body></html>`
      : `<!doctype html><html><body><h1>Order</h1><p>No matching order.</p></body></html>`);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/orders`, method: 'GET', params: ['id'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    const bool = findings.find((f) => /boolean-based blind/i.test(f.testName));
    assert.ok(bool, 'expected a boolean-based blind SQLi finding');
    assert.equal(bool.severity, 'critical');
    assert.equal(bool.evidence.method, 'differential');
    // The proof is timing/differential, not a reflected byte: no quote.
    assert.equal(bool.evidence.signal.quote, '');
    assert.ok(!isProven(bool.evidence), 'a differential is CONFIRMED, not PROVEN (no substring proof)');
    assert.match(bool.evidence.attack.request, /^GET \/orders/m);
  });
});

test('fuzzer does NOT false-positive boolean-blind on a stable page that ignores the param', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    // Identical every request, whatever the param — no injection to find.
    res.end(`<!doctype html><html><body><h1>Static</h1>${'<li>x</li>'.repeat(30)}</body></html>`);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/page`, method: 'GET', params: ['id'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    assert.ok(!findings.some((f) => /boolean-based blind/i.test(f.testName)), 'stable page must not yield a boolean-blind finding');
  });
});

test('fuzzer does NOT false-positive boolean-blind on a volatile page (stability guard)', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    // Random amount of non-normalizable letter content each request — the
    // two-baseline stability guard must reject this before any comparison.
    const n = 100 + Math.floor(Math.random() * 400);
    res.end(`<!doctype html><html><body>${'q'.repeat(n)}</body></html>`);
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/vol`, method: 'GET', params: ['id'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    assert.ok(!findings.some((f) => /boolean-based blind/i.test(f.testName)), 'volatile page must not yield a boolean-blind finding');
  });
});

// --- Session-aware form submission (stateful scanning slice) -----------------

test('extractHiddenToken pulls the anti-CSRF token across frameworks and attribute orders', () => {
  assert.deepEqual(extractHiddenToken('<input type="hidden" name="csrf_token" value="abc123">'), { name: 'csrf_token', value: 'abc123' });
  // value-before-name attribute order
  assert.deepEqual(extractHiddenToken('<input value="tok999" name="authenticity_token" type="hidden">'), { name: 'authenticity_token', value: 'tok999' });
  assert.deepEqual(extractHiddenToken('<input type=hidden name=_token value=laravel1>'), { name: '_token', value: 'laravel1' });
  // a non-token hidden field is ignored
  assert.equal(extractHiddenToken('<input type="hidden" name="return_to" value="/home">'), null);
  assert.equal(extractHiddenToken('<p>no inputs here</p>'), null);
});

test('fuzzer reaches a CSRF-token-protected form sink it would otherwise be 403-blocked on', async () => {
  // The endpoint mints a token bound to a session cookie on GET, and REJECTS any
  // POST whose token/cookie is missing or wrong (403). Only once the fuzzer
  // carries the session cookie AND resubmits the token does the injectable `id`
  // sink become reachable — and then a SQL metacharacter provokes the DB error.
  let issued: string | null = null;
  await withServer(async (req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'GET') {
      issued = 'tok-' + Math.random().toString(16).slice(2, 10);
      res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': `sid=session-xyz; Path=/` });
      res.end(`<!doctype html><html><body>
        <form method="POST" action="/orders">
          <input type="hidden" name="csrf_token" value="${issued}">
          <input name="id" placeholder="order id">
        </form></body></html>`);
      return;
    }
    // POST: enforce the CSRF token + session cookie, exactly like a real app.
    const body = await readBody(req);
    const params = new URLSearchParams(body);
    const cookieOk = /(?:^|;\s*)sid=session-xyz/.test(req.headers.cookie || '');
    const tokenOk = params.get('csrf_token') === issued;
    if (!cookieOk || !tokenOk) { res.writeHead(403); return res.end('CSRF check failed'); }
    const id = params.get('id') || '';
    let html = '<!doctype html><html><body>order';
    if (/['"]/.test(id)) html += `<pre>You have an error in your SQL syntax; check the manual near '${id}'</pre>`;
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html + '</body></html>');
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const targets: InjectableTarget[] = [
      // A form target whose page (discoveredOnPage) issues the token+cookie.
      { url: `${base}/orders`, method: 'POST', params: ['id', 'csrf_token'], source: 'form', discoveredOnPage: `${base}/order-form` },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS);
    const sqli = findings.find((f) => /SQL Injection/i.test(f.testName));
    assert.ok(sqli, 'the SQLi sink behind the CSRF token must now be reached and confirmed');
    assert.match(sqli.evidence.signal.quote, /SQL syntax/i);
    assert.ok(sqli.evidence.attack.response.includes(sqli.evidence.signal.quote));
    // The receipt must not leak the session cookie value.
    assert.ok(!JSON.stringify(sqli.evidence).includes('session-xyz'), 'cookie value must be redacted in the receipt');
  });
});

test('aggressive tier confirms LDAP injection via a filter-syntax error (differential baseline stays clean)', async () => {
  // The endpoint concatenates `q` into an LDAP filter. An unbalanced filter
  // metacharacter provokes a real JNDI filter error; a benign value does not.
  await withServer((req, res) => {
    const q = new URL(req.url!, 'http://x').searchParams.get('q') ?? '';
    let html = '<!doctype html><html><body>directory';
    if (/[*()|]/.test(q)) {
      html += '<pre>javax.naming.directory.InvalidSearchFilterException: invalid attribute description</pre>';
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html + '</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/dir`, method: 'GET', params: ['q'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    const ldap = findings.find((f) => /LDAP Injection/i.test(f.testName));
    assert.ok(ldap, 'expected an LDAP injection finding on the filter parameter');
    assert.equal(ldap.severity, 'critical');
    assert.match(ldap.evidence.signal.quote, /InvalidSearchFilterException/i);
    assert.ok(ldap.evidence.attack.response.includes(ldap.evidence.signal.quote));
  });
});

test('LDAP probe does NOT false-positive when the filter error is inherent page content', async () => {
  // The page always contains an LDAP error string regardless of input. The
  // differential guard must see it in the benign baseline and suppress.
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>Bad search filter (see docs)</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/dir`, method: 'GET', params: ['q'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    assert.ok(!findings.some((f) => /LDAP Injection/i.test(f.testName)), 'inherent LDAP error text must not be reported as injection');
  });
});

test('aggressive tier confirms XPath injection via an expression error (differential baseline stays clean)', async () => {
  // The endpoint concatenates `name` into an XPath query. An unbalanced quote
  // breaks the expression and the engine emits an XPath error; benign input does not.
  await withServer((req, res) => {
    const name = new URL(req.url!, 'http://x').searchParams.get('name') ?? '';
    let html = '<!doctype html><html><body>lookup';
    if (/['"]/.test(name)) {
      html += '<pre>System.Xml.XPath.XPathException: Expression must evaluate to a node-set.</pre>';
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html + '</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/lookup`, method: 'GET', params: ['name'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    const xpath = findings.find((f) => /XPath Injection/i.test(f.testName));
    assert.ok(xpath, 'expected an XPath injection finding on the parameter');
    assert.equal(xpath.severity, 'high');
    assert.match(xpath.evidence.signal.quote, /XPath/i);
    assert.ok(xpath.evidence.attack.response.includes(xpath.evidence.signal.quote));
  });
});

test('XPath probe does NOT false-positive when the expression error is inherent page content', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>Invalid expression: example in our XPath tutorial</body></html>');
  }, async (port) => {
    const targets: InjectableTarget[] = [
      { url: `http://127.0.0.1:${port}/lookup`, method: 'GET', params: ['name'], source: 'query' },
    ];
    const { findings } = await fuzzDiscoveredTargets(targets, HEADERS, { aggressive: true });
    assert.ok(!findings.some((f) => /XPath Injection/i.test(f.testName)), 'inherent XPath error text must not be reported as injection');
  });
});
