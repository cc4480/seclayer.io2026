import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertScanTargetSafe, isBlockedIp, looksLikeHtml, compileStaticFindings, compileScanEvidence } from './scanner.js';
import { SEVERITY_WEIGHTS } from './scoring.js';

function baseDiag(overrides: any = {}): any {
  return {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: '' },
    dastInputs: [], redTeamFindings: [], apiSecFindings: [], ...overrides,
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
