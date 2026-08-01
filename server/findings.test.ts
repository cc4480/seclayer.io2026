import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileStaticFindings, splitMissingHeaders } from './findings.js';

// Minimal DiagnosticResult, mirroring the helper in scanner.test.ts.
function baseDiag(overrides: any = {}): any {
  return {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: '' },
    redTeamFindings: [], apiSecFindings: [], ...overrides,
  };
}

const isClickjacking = (f: { title: string }) => /x-frame-options|clickjack/i.test(f.title);

// Regression for the lovable.dev report: cookie-flag findings — all on analytics
// (rs_*) or preference (locale/currency/country) cookies — cratered a clean site.
// Those flags are irrelevant/by-design on such cookies (they must be JS-readable
// and carry no secret), so under a ZERO-FALSE-POSITIVE policy they are dropped
// entirely rather than shown as low/suppressed noise the user still has to triage.
const LOVABLE_COOKIE_ISSUES = [
  'Cookie "USER_COUNTRY" is set without the HttpOnly attribute',
  'Cookie "USER_CURRENCY" is set without the HttpOnly attribute',
  'Cookie "LOCALE" is set without the Secure attribute over HTTPS',
  'Cookie "LOCALE" is set without the HttpOnly attribute',
  'Cookie "rs_visitor_id" is set without the HttpOnly attribute',
];

test('analytics/preference cookie flag gaps are not reported at all (zero false positives)', () => {
  const diag = baseDiag({ cookieIssues: LOVABLE_COOKIE_ISSUES });
  const r = compileStaticFindings(diag);
  const cookieFindings = r.findings.filter((f) => /Cookie "/.test(f.title));

  // Every one is an analytics or preference cookie — none should surface at all.
  assert.equal(cookieFindings.length, 0, 'no analytics/preference cookie flag finding should be produced');
  // Nothing real to score → the site reads clean.
  assert.equal(r.score, 100, `expected a clean score, got ${r.score}`);
});

test('a genuine session cookie missing HttpOnly is still scored medium at high confidence', () => {
  const diag = baseDiag({ cookieIssues: ['Cookie "sl_session" is set without the HttpOnly attribute'] });
  const r = compileStaticFindings(diag);
  const f = r.findings.find((x) => /sl_session/.test(x.title));
  assert.ok(f && !f.isFalsePositive && f.severity === 'medium', 'session cookie HttpOnly gap must remain a medium finding');
  assert.equal(f!.confidence, 'high', 'a session-named cookie is a confident finding');
});

test('an unclassifiable cookie is reported but at medium confidence so it can be damped, not crater the grade', () => {
  const diag = baseDiag({ cookieIssues: ['Cookie "foo_bar" is set without the HttpOnly attribute'] });
  const r = compileStaticFindings(diag);
  const f = r.findings.find((x) => /foo_bar/.test(x.title));
  assert.ok(f && !f.isFalsePositive, 'still reported — never silently dropped');
  assert.equal(f!.severity, 'medium');
  assert.equal(f!.confidence, 'medium', "we can't confirm it carries session state");
});

test('a leaked Server/framework banner is informational context, not a scored weakness', () => {
  const diag = baseDiag({ techLeaked: ['Server: nginx/1.18.0'] });
  const r = compileStaticFindings(diag);
  const f = r.findings.find((x) => /Signature Leaked/i.test(x.title));
  assert.ok(f, 'still surfaced for hardening');
  assert.equal(f!.severity, 'info');
  assert.equal(r.score, 100, 'fingerprinting must not deduct from the score');
});

test('clickjacking finding fires when neither X-Frame-Options nor CSP frame-ancestors is present', () => {
  const diag = baseDiag({ missingHeaders: ['x-frame-options'] });
  const r = compileStaticFindings(diag);
  assert.ok(r.findings.some(isClickjacking), 'should flag clickjacking exposure when no anti-framing control exists');
});

test('clickjacking finding is SUPPRESSED when CSP frame-ancestors covers framing (no X-Frame-Options header)', () => {
  // Real-world false positive: a site protects against framing with modern CSP
  // frame-ancestors and omits the legacy X-Frame-Options header. Flagging it
  // would be wrong AND would contradict the finding's own wording.
  const diag = baseDiag({
    missingHeaders: ['x-frame-options'],
    headers: { 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" },
  });
  const r = compileStaticFindings(diag);
  assert.ok(!r.findings.some(isClickjacking), 'CSP frame-ancestors must suppress the missing-XFO finding');
});

test('CSP frame-ancestors matching is case-insensitive and directive-position independent', () => {
  const diag = baseDiag({
    missingHeaders: ['x-frame-options'],
    headers: { 'content-security-policy': "script-src 'self'; FRAME-ANCESTORS https://trusted.example" },
  });
  const r = compileStaticFindings(diag);
  assert.ok(!r.findings.some(isClickjacking), 'frame-ancestors anywhere in the CSP suppresses the finding');
});

const isHsts = (f: { title: string }) => /strict-transport|hsts/i.test(f.title);

test('missing HSTS is flagged over HTTPS', () => {
  const diag = baseDiag({ sslSecure: true, missingHeaders: ['strict-transport-security'] });
  assert.ok(compileStaticFindings(diag).findings.some(isHsts));
});

test('missing HSTS is NOT double-counted on a plaintext-HTTP target', () => {
  // The "Insecure Connection Protocol (HTTP)" finding already covers this, and
  // HSTS is meaningless without TLS — so it must not add a second finding.
  const diag = baseDiag({ sslSecure: false, missingHeaders: ['strict-transport-security'] });
  assert.ok(!compileStaticFindings(diag).findings.some(isHsts), 'no HSTS finding on an HTTP target');
});

test('splitMissingHeaders treats Referrer-Policy as advisory, everything else essential', () => {
  const { essential, advisory } = splitMissingHeaders([
    'content-security-policy', 'referrer-policy', 'x-frame-options',
  ]);
  assert.deepEqual(advisory, ['referrer-policy']);
  assert.deepEqual(essential, ['content-security-policy', 'x-frame-options']);
});

test('Referrer-Policy alone never produces a scored finding', () => {
  const diag = baseDiag({ missingHeaders: ['referrer-policy'] });
  const r = compileStaticFindings(diag);
  assert.equal(r.findings.filter((f) => /referrer/i.test(f.title)).length, 0);
});

test('every finding carries a plain-English verification note', () => {
  const diag = baseDiag({
    sslSecure: false, // EASM no-TLS finding
    missingHeaders: ['content-security-policy'], // IAST
    sastFindings: [{ file: 'x', issue: 'Exposed Credential Signature (Stripe Secret Key)', severity: 'critical', confidence: 'high', type: 'hardcoded_secrets', description: 'd', fix: 'f' }],
    probedPaths: [{ path: '/.env', status: 200, exposed: true }],
  });
  const r = compileStaticFindings(diag);
  assert.ok(r.findings.length > 0);
  for (const f of r.findings) {
    assert.ok(typeof f.verification === 'string' && f.verification.length > 0, `missing verification: ${f.title}`);
  }
  // Category-appropriate basis, not a generic catch-all.
  const sast = r.findings.find((f) => f.category === 'SAST');
  assert.match(sast!.verification!, /signature match/i);
  const dast = r.findings.find((f) => /\.env/i.test(f.title));
  assert.match(dast!.verification!, /response body|signature/i);
});

test('a finding with an exploit receipt is verified as actively confirmed', () => {
  const diag = baseDiag({
    redTeamFindings: [{ testName: 'Active SQL Injection Probe', description: 'd', severity: 'critical', fix: 'f', evidence: { method: 'error-signature' } }],
  });
  const r = compileStaticFindings(diag);
  const rt = r.findings.find((f) => /sql injection/i.test(f.title));
  assert.match(rt!.verification!, /active exploitation|replayable|receipt/i);
});
