import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compileStaticFindings } from './findings.js';

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
