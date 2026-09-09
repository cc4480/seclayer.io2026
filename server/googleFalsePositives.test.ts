import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isHstsPreloaded, PRELOADED_DOMAIN_COUNT } from './hstsPreload.js';
import { classifyCookie } from './cookieClassify.js';
import { analyzeSecrets } from './staticAnalysis.js';

// Regression suite for the false positives a scan of google.com produced on
// 2026-09-08: 61/100, grade D, on a target whose real posture is excellent.
// Each case below is a finding that report contained and should not have.

test('HSTS: a preloaded apex is not reported as missing HSTS', () => {
  // hstspreload.org answers "unknown" for google.com and http://google.com
  // redirects to http://www.google.com without upgrading, so neither an API
  // lookup nor a behavioural probe catches this — hence the bundled list.
  assert.equal(isHstsPreloaded('google.com'), true);
  assert.equal(isHstsPreloaded('www.google.com'), true, 'subdomains are included');
  assert.equal(isHstsPreloaded('GOOGLE.COM'), true, 'case-insensitive');
  assert.equal(isHstsPreloaded('google.com.'), true, 'trailing dot tolerated');
});

test('HSTS: a domain not on the list is still reported', () => {
  assert.equal(isHstsPreloaded('example.com'), false);
  assert.equal(isHstsPreloaded(''), false);
  // Must not match by substring: this is a different registrable domain.
  assert.equal(isHstsPreloaded('notgoogle.com'), false);
  assert.equal(isHstsPreloaded('google.com.evil.test'), false);
});

test('HSTS: the bundled list is non-trivial', () => {
  assert.ok(PRELOADED_DOMAIN_COUNT > 20, `expected a real list, got ${PRELOADED_DOMAIN_COUNT}`);
});

test('cookies: Google ads/preference cookies are not scored as session cookies', () => {
  // NID and AEC were both reported medium on google.com with a description
  // warning about session hijacking. Neither carries session state.
  assert.equal(classifyCookie('NID'), 'analytics');
  assert.equal(classifyCookie('AEC'), 'analytics');
});

test('cookies: genuine session cookies still classify as session', () => {
  // The suppression above must not widen into under-reporting.
  for (const n of ['sessionid', 'JSESSIONID', 'PHPSESSID', 'connect.sid', 'auth_token', 'jwt']) {
    assert.equal(classifyCookie(n), 'session', `${n} must stay a session cookie`);
  }
});

test('secrets: a Google browser API key is not reported on its own', () => {
  // AIzaSy… keys must ship to the client for Maps/Firebase/reCAPTCHA to work.
  // google.com was flagged for its own. Presence is the designed behaviour.
  const html = 'var cfg={apiKey:"AIzaSyB1cD3fGh1jKlMn0pQrStUvWxYz012345a"};';
  const hits = analyzeSecrets(html).filter((f) => /google/i.test(f.issue ?? ''));
  assert.equal(hits.length, 0, 'a browser API key alone is not a finding');
});

test('secrets: genuinely secret credentials are still reported', () => {
  // The removal above must not blunt the signatures that matter.
  const aws = analyzeSecrets('const k="AKIA3XKWQZJ7NRVB4TMD";');
  assert.ok(aws.length > 0, 'AWS access key id must still be reported');
});
