import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { securityHeaders, CONTENT_SECURITY_POLICY } from './securityHeaders.js';

// Exercise the middleware with a minimal fake res/next, capturing the headers it
// sets — no Express app or network needed.
function run(isProd: boolean) {
  const headers: Record<string, string> = {};
  const res = { setHeader: (k: string, v: string) => { headers[k] = v; } } as any;
  let nexted = false;
  securityHeaders({ isProd })({} as any, res, () => { nexted = true; });
  return { headers, nexted };
}

test('baseline headers are set on every response regardless of env', () => {
  for (const isProd of [true, false]) {
    const { headers } = run(isProd);
    assert.equal(headers['X-Frame-Options'], 'DENY');
    assert.equal(headers['X-Content-Type-Options'], 'nosniff');
    assert.equal(headers['Referrer-Policy'], 'strict-origin-when-cross-origin');
  }
});

test('HSTS and CSP are production-only (dev stays HMR-friendly)', () => {
  const dev = run(false).headers;
  assert.equal(dev['Strict-Transport-Security'], undefined);
  assert.equal(dev['Content-Security-Policy'], undefined);

  const prod = run(true).headers;
  assert.equal(prod['Strict-Transport-Security'], 'max-age=31536000; includeSubDomains; preload');
  assert.equal(prod['Content-Security-Policy'], CONTENT_SECURITY_POLICY);
});

// The whole point of the finding fix: a CSP is now present AND it is not
// self-defeatingly permissive on scripts.
test('the CSP is strict on scripts but grants the SPA the inline styles/data images it needs', () => {
  // 'self' first, then only the Google Identity Services loader — the single
  // third-party script origin this app admits, for "Sign in with Google".
  assert.match(CONTENT_SECURITY_POLICY, /(^|; )script-src 'self' https:\/\/accounts\.google\.com\/gsi\/client(;|$)/);
  assert.ok(!/script-src[^;]*'unsafe-inline'/.test(CONTENT_SECURITY_POLICY), "script-src must not allow 'unsafe-inline'");
  assert.ok(!/'unsafe-eval'/.test(CONTENT_SECURITY_POLICY), "CSP must not allow 'unsafe-eval'");
  assert.match(CONTENT_SECURITY_POLICY, /style-src 'self' 'unsafe-inline'/);
  assert.match(CONTENT_SECURITY_POLICY, /img-src 'self' data:/);
  assert.match(CONTENT_SECURITY_POLICY, /frame-ancestors 'none'/);
  assert.match(CONTENT_SECURITY_POLICY, /object-src 'none'/);
});

// Any third-party origin in this policy is a place an attacker could serve
// script from if that origin were ever compromised or its path loosened, so the
// allowlist is asserted exhaustively rather than only checked for what it adds.
test('accounts.google.com is the ONLY third-party origin, and only on the GSI paths', () => {
  const origins = CONTENT_SECURITY_POLICY.match(/https?:\/\/[^\s;]+/g) ?? [];
  for (const o of origins) {
    assert.ok(
      o.startsWith('https://accounts.google.com/gsi/'),
      `unexpected third-party origin in CSP: ${o}`,
    );
  }
  // The button renders in a Google-served iframe; without frame-src it would
  // fall back to default-src 'self' and be blocked in production only.
  assert.match(CONTENT_SECURITY_POLICY, /frame-src https:\/\/accounts\.google\.com\/gsi\//);
});

test('the middleware always calls next()', () => {
  assert.equal(run(true).nexted, true);
  assert.equal(run(false).nexted, true);
});

// The Vercel edge (which serves the SPA shell directly) and the Express app must
// enforce the SAME policy — otherwise the deployed landing page and the API would
// diverge. Guard against the two copies drifting.
test('vercel.json enforces the identical CSP served by Express', () => {
  const vercel = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
  const rule = vercel.headers.find((h: any) => h.source && h.source.includes('api'));
  const csp = rule.headers.find((h: any) => h.key === 'Content-Security-Policy');
  assert.equal(csp.value, CONTENT_SECURITY_POLICY);
});
