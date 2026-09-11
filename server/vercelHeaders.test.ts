import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { CONTENT_SECURITY_POLICY } from './securityHeaders.js';

// vercel.json carries the security headers for a Vercel-hosted deployment,
// where the SPA shell is served by Vercel's edge and never passes through the
// Express middleware. Railway serves seclayer.app today, so this file is not in
// the live path — which is exactly why it rots silently: a CSP change to
// securityHeaders.ts will not update it, and a later Vercel deploy would then
// ship a stale policy that nothing in the test suite noticed.
//
// Pinning them together means the alternative deployment path stays correct, or
// CI says so. If Vercel is ever dropped for good, delete the file AND this test
// together — deliberately, rather than by drift.
const vercel = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'vercel.json'), 'utf-8'));

function headerValue(key: string): string | undefined {
  for (const rule of vercel.headers ?? []) {
    const hit = (rule.headers ?? []).find((h: any) => h.key.toLowerCase() === key.toLowerCase());
    if (hit) return hit.value;
  }
  return undefined;
}

const directives = (csp: string) => new Set(csp.split(';').map((d) => d.trim()).filter(Boolean));

test('vercel.json CSP matches the one Express actually serves', () => {
  const vcsp = headerValue('Content-Security-Policy');
  assert.ok(vcsp, 'vercel.json must define a Content-Security-Policy');
  assert.deepEqual(
    directives(vcsp!),
    directives(CONTENT_SECURITY_POLICY),
    'vercel.json has drifted from server/securityHeaders.ts — a Vercel deploy would serve a stale policy',
  );
});

test('vercel.json carries the same hardening headers as Express', () => {
  // The ones whose absence is a finding our own scanner would raise.
  for (const [key, expected] of [
    ['X-Frame-Options', 'DENY'],
    ['X-Content-Type-Options', 'nosniff'],
    ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ] as const) {
    assert.equal(headerValue(key), expected, `${key} missing or wrong in vercel.json`);
  }
  assert.match(headerValue('Strict-Transport-Security') ?? '', /max-age=\d+/, 'HSTS missing in vercel.json');
});

test('vercel.json does not set headers on /api (Express owns those)', () => {
  // Duplicated headers on API responses is the failure this exclusion prevents.
  const sources = (vercel.headers ?? []).map((r: any) => r.source);
  assert.ok(sources.length > 0, 'expected at least one header rule');
  for (const s of sources) assert.match(s, /\(\?!api\//, `rule must exclude /api: ${s}`);
});
