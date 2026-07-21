import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { assertScanTargetSafe, isBlockedIp, looksLikeHtml, compileStaticFindings, compileScanEvidence, runDiagnostics, windowAround, firstBlockedAddress, guardedFetch } from './scanner.js';
import { SEVERITY_WEIGHTS, isProven } from './scoring.js';

function baseDiag(overrides: any = {}): any {
  return {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: '' },
    redTeamFindings: [], apiSecFindings: [], ...overrides,
  };
}

test('isBlockedIp blocks internal/reserved ranges', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '192.168.1.1', '169.254.169.254', '172.16.0.1', '100.64.0.1', '::1', 'fe80::1', 'fc00::1']) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '1.1.1.1']) {
    assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
  }
});

test('assertScanTargetSafe rejects internal hosts and non-http schemes', async () => {
  for (const t of ['localhost', 'http://127.0.0.1', 'http://169.254.169.254/', 'ftp://example.com', 'file:///etc/passwd', 'admin.internal', 'http://[::1]/']) {
    await assert.rejects(assertScanTargetSafe(t), `${t} should be rejected`);
  }
});

test('assertScanTargetSafe allows a public literal IP', async () => {
  await assert.doesNotReject(assertScanTargetSafe('https://93.184.216.34'));
});

test('SCAN_DEV_ALLOW_HOSTS opens a loopback target only in dev, only for exact matches', async () => {
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  const prevEnv = process.env.NODE_ENV;
  try {
    // Off by default: loopback stays blocked.
    delete process.env.SCAN_DEV_ALLOW_HOSTS;
    await assert.rejects(assertScanTargetSafe('http://127.0.0.1:4100'), 'blocked without the flag');

    // Dev + exact host:port allowlisted -> permitted.
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4100';
    await assert.doesNotReject(assertScanTargetSafe('http://127.0.0.1:4100'), 'allowed in dev when listed');
    // A different port on the same host is NOT covered.
    await assert.rejects(assertScanTargetSafe('http://127.0.0.1:9999'), 'other port still blocked');

    // Production hard-disables the escape hatch even when the flag is set.
    process.env.NODE_ENV = 'production';
    await assert.rejects(assertScanTargetSafe('http://127.0.0.1:4100'), 'never allowed in production');
  } finally {
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
  }
});

test('firstBlockedAddress refuses a rebinding answer set (public + internal)', () => {
  // A host that resolves purely to public IPs is allowed.
  assert.equal(firstBlockedAddress('good.example', ['93.184.216.34', '1.1.1.1']), null);
  // DNS rebinding: the resolver mixes a public IP with an internal one. Even one
  // internal address must sink the whole connection — this is the exact bypass
  // the connect-time lookup closes that the resolve-then-connect check could miss.
  assert.equal(firstBlockedAddress('evil.example', ['93.184.216.34', '127.0.0.1']), '127.0.0.1');
  assert.equal(firstBlockedAddress('evil.example', ['169.254.169.254']), '169.254.169.254');
  assert.equal(firstBlockedAddress('evil.example', ['::1']), '::1');
});

test('firstBlockedAddress honors the dev allowlist at connect time', () => {
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  const prevEnv = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4100';
    // The listed loopback test target may resolve to an otherwise-blocked IP.
    assert.equal(firstBlockedAddress('127.0.0.1', ['127.0.0.1']), null);
    // A host NOT on the allowlist is still refused.
    assert.equal(firstBlockedAddress('other.host', ['127.0.0.1']), '127.0.0.1');
    // Production hard-disables the escape hatch.
    process.env.NODE_ENV = 'production';
    assert.equal(firstBlockedAddress('127.0.0.1', ['127.0.0.1']), '127.0.0.1');
  } finally {
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
  }
});

test('guardedFetch pins the socket: a hostname resolving to an internal IP is refused at connect', async () => {
  // Bind a real loopback server, then ask guardedFetch for a hostname that
  // (via the OS hosts file) maps to 127.0.0.1. With no dev allowlist the pinned
  // dispatcher must refuse the connection rather than reach the internal server.
  const server = http.createServer((_req, res) => res.end('reached-internal'));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    delete process.env.SCAN_DEV_ALLOW_HOSTS; // ensure loopback is NOT allowlisted
    // "localhost" resolves to 127.0.0.1/::1 — a stand-in for any hostname a
    // hostile resolver could rebind to an internal address.
    await assert.rejects(
      guardedFetch(`http://localhost:${port}/`, { redirect: 'manual' }),
      'guardedFetch must refuse a host resolving to an internal address',
    );
  } finally {
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    server.close();
  }
});

test('looksLikeHtml separates a SPA shell from a raw config file', () => {
  assert.equal(looksLikeHtml('<!doctype html><html><head>'), true);
  assert.equal(looksLikeHtml('DB_PASSWORD=secret\nAPI_KEY=abc'), false);
});

test('a clean target produces no findings and a full score (no SPA .env false positive)', () => {
  const diag = baseDiag({ probedPaths: [{ path: '/.env', status: 200, exposed: false }] });
  const r = compileStaticFindings(diag);
  assert.equal(r.findings.length, 0);
  assert.equal(r.score, 100);
});

test('a confirmed exposed .env yields a critical finding', () => {
  const diag = baseDiag({ probedPaths: [{ path: '/.env', status: 200, exposed: true }] });
  const r = compileStaticFindings(diag);
  assert.equal(r.severity, 'critical');
  assert.ok(r.findings.some((f) => /env/i.test(f.title)));
});

test('missing security headers are reported as defense-in-depth gaps, not high severity', () => {
  const diag = baseDiag({ missingHeaders: ['content-security-policy', 'strict-transport-security', 'x-frame-options'] });
  const r = compileStaticFindings(diag);
  const headerFindings = r.findings.filter((f) => /content-security-policy|strict-transport|x-frame/i.test(f.title));
  assert.equal(headerFindings.length, 3);
  // A missing header is a gap, never a confirmed high/critical vulnerability.
  assert.ok(headerFindings.every((f) => f.severity === 'medium' || f.severity === 'low'),
    'missing-header findings must be medium or lower');
});

test('every finding gets a fallback impact + agent prompt, even without DeepSeek', () => {
  const diag = baseDiag({ missingHeaders: ['content-security-policy'] });
  const r = compileStaticFindings(diag);
  assert.ok(r.findings.length > 0);
  for (const f of r.findings) {
    assert.ok(f.impact && f.impact.length > 0, `${f.title} should have an impact fallback`);
    assert.ok(f.agentPrompt && f.agentPrompt.includes(f.title), `${f.title} should have an agent prompt mentioning itself`);
  }
});

test('an unverified target surfaces an info finding noting active probes were skipped', () => {
  const diag = baseDiag({ activeProbesSkipped: true });
  const r = compileStaticFindings(diag);
  const skipped = r.findings.find((f) => /Active Exploit Probing Skipped/i.test(f.title));
  assert.ok(skipped && skipped.severity === 'info');
  // The skipped notice must NOT masquerade as an active-exploit finding — the
  // RED_TEAM / API_SEC pillars must never show a count for probes that never
  // fired. It is a scan-coverage note, categorized DAST.
  assert.equal(skipped.category, 'DAST');
  assert.equal(r.findings.filter((f) => f.category === 'RED_TEAM').length, 0);
  assert.equal(r.findings.filter((f) => f.category === 'API_SEC').length, 0);
  // Informational: it only nudges the score by the small info weight (2) rather
  // than a perfect 100, so the score never contradicts a non-empty findings list
  // — but it stays comfortably in the top grade band.
  assert.equal(r.score, 100 - SEVERITY_WEIGHTS.info);
  assert.ok(r.score >= 90);
});

test('a verified target (default) does not surface the skipped-probes notice', () => {
  const diag = baseDiag(); // activeProbesSkipped defaults to falsy/undefined
  const r = compileStaticFindings(diag);
  assert.ok(!r.findings.some((f) => /Active Exploit Probing Skipped/i.test(f.title)));
});

test('compileScanEvidence distils the real diagnostics into display evidence', () => {
  const diag = baseDiag({
    responseStatus: 200,
    missingHeaders: ['content-security-policy'],
    headers: { server: 'gws' },
    probedPaths: [
      { path: '/.env', status: 404, exposed: false },
      { path: '/config.json', status: 200, exposed: true },
    ],
    scaLibraries: [{ name: 'jQuery', version: '1.12.4', status: 'vuln', advisories: [], severity: 'medium', description: '', fix: '' }],
    easmPerimeter: {
      ip: '93.184.216.34', nameserver: 'ns1.example.com', protocol: 'HTTPS',
      subdomains: [
        { domain: 'api.x.test', status: 'live', port: '443' },
        { domain: 'dev.x.test', status: 'inactive', port: '0' },
      ],
    },
    crawl: { pagesVisited: 3, endpointsDiscovered: 5, paramsTested: 4, sampleEndpoints: ['/a?id'] },
    activeProbesSkipped: false,
  });
  const ev = compileScanEvidence(diag);
  assert.equal(ev.resolvedIp, '93.184.216.34');
  assert.equal(ev.nameserver, 'ns1.example.com');
  assert.equal(ev.serverHeader, 'gws');
  assert.deepEqual(ev.liveSubdomains, ['api.x.test']); // only the live one
  assert.equal(ev.subdomainsChecked, 2);
  assert.ok(ev.presentSecurityHeaders.includes('strict-transport-security'));
  assert.ok(ev.missingSecurityHeaders.includes('content-security-policy'));
  assert.equal(ev.probedPaths.length, 2);
  assert.equal(ev.detectedLibraries[0].name, 'jQuery');
  assert.equal(ev.detectedLibraries[0].vulnerable, true);
  assert.equal(ev.crawl!.paramsTested, 4);
  assert.equal(ev.activeProbesRun, true);
});

test('compileScanEvidence marks active probes as not run when they were skipped', () => {
  const ev = compileScanEvidence(baseDiag({ activeProbesSkipped: true }));
  assert.equal(ev.activeProbesRun, false);
});

test('windowAround keeps the proof intact and marks truncation explicitly', () => {
  // Short body: returned whole, no markers.
  assert.equal(windowAround('abcDEFghi', 3, 3, 2000), 'abcDEFghi');
  // Long body: the match survives and both sides are marked.
  const big = 'x'.repeat(5000) + 'PROOF' + 'y'.repeat(5000);
  const out = windowAround(big, 5000, 5, 200);
  assert.ok(out.includes('PROOF'), 'the proof must survive truncation');
  assert.ok(/\[…truncated \d+ bytes\]/.test(out), 'truncation must be explicit');
  assert.ok(out.length < big.length);
});

test('active XSS probe against a reflecting target yields a PROVEN finding with a valid receipt', async () => {
  // A minimal target that reflects the `q` parameter back unescaped — exactly the
  // shape the reflected-XSS probe is designed to catch.
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const q = u.searchParams.get('q');
    let body = '<!doctype html><html><body><h1>hi</h1>';
    if (q) body += `<div>Search results for: ${q}</div>`;
    body += '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;

  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    // Open the dev-only loopback escape hatch for this exact host:port so the
    // active pipeline can run against the owned local target.
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;

    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });

    const xss = (diag.redTeamFindings || []).find((f) => /XSS/i.test(f.testName));
    assert.ok(xss, 'expected a reflected-XSS red-team finding');
    assert.ok(xss!.evidence, 'the XSS finding must carry an exploit receipt');
    // The core invariant: the quoted proof is literally present in the stored response.
    assert.ok(
      xss!.evidence!.attack.response.includes(xss!.evidence!.signal.quote),
      'signal.quote must be a literal substring of the stored attack response',
    );
    assert.equal(isProven({ evidence: xss!.evidence } as any), true);
    assert.ok(xss!.evidence!.reproduction.includes(`127.0.0.1:${port}`), 'receipt carries a replayable curl');

    // And it survives compilation into a PROVEN Finding the report can render.
    const compiled = compileStaticFindings(diag);
    const proven = compiled.findings.find((f) => f.category === 'RED_TEAM' && /XSS/i.test(f.title));
    assert.ok(proven && isProven(proven), 'the compiled XSS finding must be PROVEN');
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('active SQLi probe against a DB-erroring target yields a PROVEN finding quoting the DB error', async () => {
  // Target that leaks a MySQL error when `id` is present — what the SQLi probe hunts.
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    let body = '<!doctype html><html><body><h1>store</h1>';
    if (u.searchParams.has('id')) {
      body += `<div class="err">Database error: You have an error in your SQL syntax; `
        + `check the manual near '${u.searchParams.get('id')}' at line 1</div>`;
    }
    body += '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;

  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;

    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });

    const sqli = (diag.redTeamFindings || []).find((f) => /SQL Injection/i.test(f.testName));
    assert.ok(sqli, 'expected a SQL injection red-team finding');
    assert.ok(sqli!.evidence, 'the SQLi finding must carry an exploit receipt');
    assert.equal(sqli!.evidence!.method, 'error-signature');
    // The receipt quotes the actual DB error, and it is literally in the response.
    assert.match(sqli!.evidence!.signal.quote, /SQL syntax/i);
    assert.ok(sqli!.evidence!.attack.response.includes(sqli!.evidence!.signal.quote));
    assert.equal(isProven({ evidence: sqli!.evidence } as any), true);

    const compiled = compileStaticFindings(diag);
    const proven = compiled.findings.find((f) => f.category === 'RED_TEAM' && /SQL Injection/i.test(f.title));
    assert.ok(proven && isProven(proven), 'the compiled SQLi finding must be PROVEN');
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('cmd-injection arithmetic oracle proves execution via the computed sum, not a page string', async () => {
  // A target that actually evaluates `expr A + B` from the ping param — so only a
  // real execution produces the sum. It never echoes the literal payload, ensuring
  // the proof cannot be a coincidental reflection.
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    let body = '<!doctype html><html><body>';
    const ping = u.searchParams.get('ping');
    const m = ping && /expr\s+(\d+)\s*\+\s*(\d+)/.exec(ping);
    if (m) body += `<pre>${Number(m[1]) + Number(m[2])}</pre>`;
    body += '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });
    const cmd = (diag.redTeamFindings || []).find((f) => /Command Injection/i.test(f.testName));
    assert.ok(cmd, 'expected a command-injection finding');
    assert.ok(cmd!.evidence, 'the cmd-injection finding must carry a receipt');
    assert.equal(cmd!.evidence!.method, 'oracle');
    // The quote is the computed sum — a pure number — and it is literally present.
    assert.match(cmd!.evidence!.signal.quote, /^\d+$/);
    assert.ok(cmd!.evidence!.attack.response.includes(cmd!.evidence!.signal.quote));
    assert.equal(isProven({ evidence: cmd!.evidence } as any), true);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test('out-of-band probe proves BLIND SSRF via a real collaborator callback', async () => {
  const { createOobCollaborator } = await import('./oob.js');
  // Fake collaborator store + a real listener the target will call back on. The
  // listener records a callback for any token the collaborator registered.
  const tokens = new Set<string>();
  const events = new Map<string, any[]>();
  const store = {
    registerOobToken: (t: string) => { tokens.add(t); },
    getOobEvents: (t: string) => events.get(t) || [],
  };
  const listener = http.createServer((req, res) => {
    const m = (req.url || '').match(/^\/api\/oob\/([a-f0-9]+)/i);
    if (m && tokens.has(m[1])) {
      const arr = events.get(m[1]) || [];
      arr.push({ id: 'e' + arr.length, token: m[1], method: req.method, sourceIp: '127.0.0.1', path: req.url, receivedAt: new Date().toISOString() });
      events.set(m[1], arr);
    }
    res.writeHead(200); res.end('ok');
  });
  await new Promise<void>((r) => listener.listen(0, '127.0.0.1', () => r()));
  const listenerPort = (listener.address() as any).port;

  // A target that performs a REAL blind SSRF: it fetches the attacker-supplied
  // `url` param server-side (fire-and-forget) and reflects NOTHING about it.
  const target = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const urlParam = u.searchParams.get('url');
    if (urlParam && /^https?:\/\//i.test(urlParam)) fetch(urlParam).catch(() => {});
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>ok</body></html>'); // no echo of urlParam
  });
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', () => r()));
  const targetPort = (target.address() as any).port;

  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${targetPort}`;
    const oob = createOobCollaborator(store as any, `http://127.0.0.1:${listenerPort}`);
    const diag = await runDiagnostics(`http://127.0.0.1:${targetPort}`, undefined, { allowActiveProbes: true, oob });
    const blind = (diag.redTeamFindings || []).find((f) => /out-of-band/i.test(f.testName));
    assert.ok(blind, 'expected a blind out-of-band SSRF finding');
    assert.ok(blind!.evidence, 'the blind SSRF finding must carry a receipt');
    assert.equal(blind!.evidence!.method, 'out-of-band');
    // The proof is the unique token, present verbatim in the recorded callback.
    assert.ok(blind!.evidence!.attack.response.includes(blind!.evidence!.signal.quote));
    assert.equal(isProven({ evidence: blind!.evidence } as any), true);
    assert.equal(blind!.severity, 'critical');
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => target.close(() => r()));
    await new Promise<void>((r) => listener.close(() => r()));
  }
});

test('out-of-band probe is skipped (no false finding) when the target makes no callback', async () => {
  const { createOobCollaborator } = await import('./oob.js');
  const store = { registerOobToken: () => {}, getOobEvents: () => [] as any[] };
  // A target that ignores the url param entirely — no SSRF.
  const target = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>ok</body></html>');
  });
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', () => r()));
  const targetPort = (target.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${targetPort}`;
    const oob = createOobCollaborator(store as any, `http://127.0.0.1:9`);
    // Short-circuit the 8s poll wait for a no-callback target.
    (oob as any).poll = async () => null;
    const diag = await runDiagnostics(`http://127.0.0.1:${targetPort}`, undefined, { allowActiveProbes: true, oob });
    const blind = (diag.redTeamFindings || []).find((f) => /out-of-band/i.test(f.testName));
    assert.equal(blind, undefined, 'no callback → no blind SSRF finding');
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => target.close(() => r()));
  }
});

// --- GraphQL + BOLA (API_SEC) receipts -------------------------------------

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

test('GraphQL introspection port yields a PROVEN finding (high, not critical)', async () => {
  await withServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'POST' && u.pathname === '/graphql') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { __schema: { types: [{ name: 'Query' }, { name: 'User' }, { name: 'Order' }] } } }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body>home</body></html>');
  }, async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });
    const gql = (diag.apiSecFindings || []).find((f) => /Introspection/i.test(f.testName));
    assert.ok(gql, 'expected a GraphQL introspection finding');
    assert.equal(gql!.severity, 'high', 'introspection is a disclosure — high, never critical');
    assert.ok(gql!.evidence && gql!.evidence.method === 'introspection');
    assert.ok(gql!.evidence!.attack.response.includes(gql!.evidence!.signal.quote));
    assert.equal(isProven({ evidence: gql!.evidence } as any), true);
  });
});

// A store where /api/orders/:id is readable by ANY authenticated token (BOLA) or,
// in `mode`, either enforces ownership or requires no auth at all.
function ordersHandler(mode: 'bola' | 'secure' | 'public'): http.RequestListener {
  const ORDERS: Record<string, any> = {
    '1001': { id: '1001', owner: 'tok-A', email: 'alice@example.test' },
    '1002': { id: '1002', owner: 'tok-B', email: 'bob@example.test' },
  };
  return (req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    const m = u.pathname.match(/^\/api\/orders\/(\d+)$/);
    if (!m) { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><html><body>home</body></html>'); return; }
    const order = ORDERS[m[1]];
    if (!order) { res.writeHead(404); res.end('not found'); return; }
    const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    if (mode !== 'public' && !token) { res.writeHead(401); res.end('unauthorized'); return; }
    if (mode === 'secure' && token !== order.owner) { res.writeHead(403); res.end('forbidden'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(order));
  };
}

const IDS: [any, any] = [
  { label: 'tenant-A', authHeader: 'Bearer tok-A', ownResource: '/api/orders/1001', ownMarker: 'alice@example.test' },
  { label: 'tenant-B', authHeader: 'Bearer tok-B', ownResource: '/api/orders/1002', ownMarker: 'bob@example.test' },
];

test('two-identity BOLA: A reads B\'s object → PROVEN with baseline+attack+control', async () => {
  await withServer(ordersHandler('bola'), async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true, bolaIdentities: IDS });
    const bola = (diag.apiSecFindings || []).find((f) => /^Broken Object Level Authorization/i.test(f.testName));
    assert.ok(bola, 'expected a PROVEN BOLA finding');
    assert.equal(bola!.severity, 'critical');
    const ev = bola!.evidence!;
    assert.equal(ev.method, 'differential');
    assert.equal(ev.signal.quote, 'bob@example.test'); // B's data in A's response
    assert.ok(ev.attack.response.includes('bob@example.test'));
    assert.ok(ev.baseline, 'baseline (A reads own) must be captured');
    assert.ok(ev.control && /401/.test(ev.control.response), 'control (unauth) must be denied');
    assert.equal(isProven({ evidence: ev } as any), true);
  });
});

test('two-identity BOLA: authorization enforced → passing info note, no BOLA', async () => {
  await withServer(ordersHandler('secure'), async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true, bolaIdentities: IDS });
    const bola = (diag.apiSecFindings || []).find((f) => /^Broken Object Level Authorization/i.test(f.testName));
    assert.equal(bola, undefined, 'must NOT report BOLA when authorization holds');
    const held = (diag.apiSecFindings || []).find((f) => /Authorization Enforced/i.test(f.testName));
    assert.ok(held && held.severity === 'info', 'should surface a passing authorization note');
  });
});

test('exposed user-object endpoint gets a PROVEN receipt and never collides with the real BOLA', async () => {
  // Serves BOTH the fixed-path user endpoint the legacy probe hits AND a BOLA-
  // vulnerable orders API, so we prove they coexist as two distinct findings
  // (the legacy probe no longer shadows the two-identity PROVEN BOLA by title).
  const handler: http.RequestListener = (req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname === '/api/v1/users/admin') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ email: 'admin@corp.test', role: 'admin' }));
      return;
    }
    // reuse the BOLA-vulnerable orders handler behaviour
    return ordersHandler('bola')(req, res);
  };
  await withServer(handler, async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true, bolaIdentities: IDS });
    const findings = diag.apiSecFindings || [];
    const exposed = findings.find((f) => /Exposed User Object Endpoint/i.test(f.testName));
    assert.ok(exposed, 'the fixed-path user endpoint must be reported');
    assert.ok(exposed!.evidence && exposed!.evidence.signal.quote === 'admin@corp.test', 'with a receipt quoting the leaked field');
    assert.equal(isProven({ evidence: exposed!.evidence } as any), true);
    assert.ok(!/BOLA/i.test(exposed!.testName), 'and it must NOT claim BOLA');

    const bola = findings.find((f) => /^Broken Object Level Authorization/i.test(f.testName));
    assert.ok(bola && bola.evidence, 'the real two-identity BOLA still appears alongside it');
    // Two distinct titles → both survive title-dedup in compileStaticFindings.
    const compiled = compileStaticFindings(diag);
    assert.ok(compiled.findings.some((f) => /Exposed User Object Endpoint/i.test(f.title)));
    assert.ok(compiled.findings.some((f) => /^Broken Object Level Authorization/i.test(f.title)));
  });
});

test('two-identity BOLA: public endpoint → Unauthenticated Access (§3.1b), not BOLA', async () => {
  await withServer(ordersHandler('public'), async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true, bolaIdentities: IDS });
    assert.equal((diag.apiSecFindings || []).some((f) => /^Broken Object Level Authorization/i.test(f.testName)), false);
    const unauth = (diag.apiSecFindings || []).find((f) => /Unauthenticated Access/i.test(f.testName));
    assert.ok(unauth, 'a world-readable per-user resource is unauthenticated exposure');
    assert.equal(isProven({ evidence: unauth!.evidence } as any), true);
  });
});

test('smart discovered-parameter fuzzer proves XSS + SQLi and skips an inert param', async () => {
  // Root links to three parameterized endpoints; the crawler discovers them and
  // the fuzzer injects. /search reflects (XSS), /item errors (SQLi), /static is inert.
  const handler: http.RequestListener = (req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname === '/search') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!doctype html><html><body><div>Results for: ${u.searchParams.get('q') || ''}</div></body></html>`);
      return;
    }
    if (u.pathname === '/item') {
      let body = '<!doctype html><html><body>item';
      if (u.searchParams.has('id')) body += `<div>Database error: You have an error in your SQL syntax; near '${u.searchParams.get('id')}'</div>`;
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(body + '</body></html>'); return;
    }
    if (u.pathname === '/static') {
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><html><body>static, input ignored</body></html>'); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>home</h1>'
      + '<a href="/search?q=hello">search</a><a href="/item?id=1">item</a><a href="/static?ref=x">static</a>'
      + '</body></html>');
  };
  await withServer(handler, async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });
    const rt = diag.redTeamFindings || [];
    const xss = rt.find((f) => /Reflected XSS \(discovered parameter/i.test(f.testName));
    const sqli = rt.find((f) => /SQL Injection \(discovered parameter/i.test(f.testName));
    assert.ok(xss && xss.evidence && isProven({ evidence: xss.evidence } as any), 'XSS on the reflecting param must be PROVEN');
    assert.match(xss!.payload, /q=/);
    assert.ok(sqli && sqli.evidence && isProven({ evidence: sqli.evidence } as any), 'SQLi on the erroring param must be PROVEN');
    // The inert /static?ref param must never be flagged.
    assert.ok(!rt.some((f) => /ref=/.test(f.payload || '')), 'the inert param must not be flagged');
    assert.ok((diag.crawl?.paramsTested || 0) >= 2, 'multiple discovered params were fuzzed');
  });
});

test('two distinct endpoints vulnerable to the same injection class both survive the report', async () => {
  // /alpha and /beta both leak the same SQL error signature on their own `id`
  // param. Before the fix, paramFuzzer gave every discovered-parameter SQLi
  // finding the same fixed title, so compileStaticFindings' title-based dedup
  // kept only the first and silently dropped the second — a real, distinct,
  // PROVEN vulnerability disappearing from the report.
  const handler: http.RequestListener = (req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (u.pathname === '/alpha' || u.pathname === '/beta') {
      let body = '<!doctype html><html><body>page';
      if (u.searchParams.has('id')) body += `<div>Database error: You have an error in your SQL syntax; near '${u.searchParams.get('id')}'</div>`;
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(body + '</body></html>'); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>home</h1>'
      + '<a href="/alpha?id=1">alpha</a><a href="/beta?id=1">beta</a>'
      + '</body></html>');
  };
  await withServer(handler, async (port) => {
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });
    const compiled = compileStaticFindings(diag);
    const sqliFindings = compiled.findings.filter((f) => /SQL Injection \(discovered parameter/i.test(f.title));
    assert.equal(sqliFindings.length, 2, 'both distinct-endpoint SQLi findings must survive the report, not just the first');
    assert.equal(new Set(sqliFindings.map((f) => f.title)).size, 2, 'titles must actually differ so the dedup step keeps both');
  });
});

test('passive mode stays passive: a would-be-vulnerable target is crawled but never gets an exploit payload', async () => {
  // This target would trip EVERY active probe if they ran: it reflects `q`
  // unescaped (XSS), leaks a SQL error on `id` (SQLi), evaluates `expr` in
  // `ping` (cmd-injection), fetches the `url` param (SSRF), and answers GraphQL
  // introspection. It also links to parameterized endpoints the crawler will
  // discover. In passive mode NONE of the exploit payloads may be sent.
  const seenUrls: string[] = [];
  const handler: http.RequestListener = (req, res) => {
    seenUrls.push(req.url || '');
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    if (req.method === 'POST' && u.pathname === '/graphql') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { __schema: { types: [{ name: 'Query' }] } } }));
      return;
    }
    if (u.pathname === '/search') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!doctype html><html><body><div>Results for: ${u.searchParams.get('q') || ''}</div></body></html>`);
      return;
    }
    if (u.pathname === '/item') {
      let body = '<!doctype html><html><body>item';
      if (u.searchParams.has('id')) body += `<div>Database error: You have an error in your SQL syntax; near '${u.searchParams.get('id')}'</div>`;
      res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(body + '</body></html>'); return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><html><body><h1>home</h1>'
      + '<a href="/search?q=hello">search</a><a href="/item?id=1">item</a>'
      + '</body></html>');
  };
  await withServer(handler, async (port) => {
    // allowActiveProbes omitted → passive black-box recon only.
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined);

    // No active exploit findings whatsoever.
    assert.equal((diag.redTeamFindings || []).length, 0, 'passive mode must produce no red-team findings');
    assert.equal((diag.apiSecFindings || []).length, 0, 'passive mode must produce no API-sec findings');
    // The diag is flagged so the report can surface the skipped-probes notice.
    assert.equal(diag.activeProbesSkipped, true);
    // Passive recon still ran: the crawler mapped the surface (GET /item?id=1 etc.)
    // but reported zero params actively fuzzed.
    assert.ok((diag.crawl?.endpointsDiscovered || 0) >= 1, 'passive crawl must still map the surface');
    assert.equal(diag.crawl?.paramsTested, 0, 'no parameter may be actively fuzzed in passive mode');

    // The decisive guarantee: the target never received an injection payload. The
    // scanner may passively GET discovered links with their benign HTML values
    // (?q=hello, ?id=1), but no request may carry a probe signature.
    const attackSignatures = [
      "OR%201%3D1", "or 1=1", "'", "%27",      // SQLi
      "<script", "%3Cscript", "onerror",         // XSS
      "expr", "%20%2B%20", ";id", "%3Bid",       // cmd-injection
      "url=http", "127.0.0.1:22",                // SSRF
    ];
    const offending = seenUrls.filter((raw) => {
      const s = raw.toLowerCase();
      return attackSignatures.some((sig) => s.includes(sig.toLowerCase()));
    });
    assert.deepEqual(offending, [], `passive mode must never send an exploit payload; sent: ${offending.join(', ')}`);
    // And it must never POST a GraphQL introspection query.
    assert.ok(!seenUrls.some((raw) => raw.includes('/graphql')), 'passive mode must not probe /graphql');
  });
});

test('SSRF probe proves server-side fetch by quoting the leaked internal banner', async () => {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url || '/', 'http://127.0.0.1');
    let body = '<!doctype html><html><body>';
    if ((u.searchParams.get('url') || '').includes('127.0.0.1:22')) {
      body += `<pre>Response from internal fetch:\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1</pre>`;
    }
    body += '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = 'development';
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    const diag = await runDiagnostics(`http://127.0.0.1:${port}`, undefined, { allowActiveProbes: true });
    const ssrf = (diag.redTeamFindings || []).find((f) => /SSRF/i.test(f.testName));
    assert.ok(ssrf, 'expected an SSRF finding');
    assert.ok(ssrf!.evidence, 'the SSRF finding must carry a receipt');
    assert.match(ssrf!.evidence!.signal.quote, /^SSH-2\.0-/);
    assert.ok(ssrf!.evidence!.attack.response.includes(ssrf!.evidence!.signal.quote));
    assert.equal(isProven({ evidence: ssrf!.evidence } as any), true);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
});
