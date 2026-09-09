import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyCookie, isCsrfToken } from './cookieClassify.js';

test('third-party analytics cookies are recognized (and win over session-looking names)', () => {
  assert.equal(classifyCookie('rs_visitor_id'), 'analytics');   // the lovable.dev FP
  assert.equal(classifyCookie('rs_session_id'), 'analytics');   // "session" substring must NOT flip it
  assert.equal(classifyCookie('_ga'), 'analytics');
  assert.equal(classifyCookie('_ga_ABC123'), 'analytics');
  assert.equal(classifyCookie('_gid'), 'analytics');
  assert.equal(classifyCookie('ajs_anonymous_id'), 'analytics');
  assert.equal(classifyCookie('_fbp'), 'analytics');
  assert.equal(classifyCookie('mp_abc_mixpanel'), 'analytics');
  assert.equal(classifyCookie('_hjSessionUser_123'), 'analytics');
});

test('non-secret preference cookies are recognized', () => {
  // The exact lovable.dev cookies that were flagged at medium.
  assert.equal(classifyCookie('USER_COUNTRY'), 'preference');
  assert.equal(classifyCookie('USER_CURRENCY'), 'preference');
  assert.equal(classifyCookie('LOCALE'), 'preference');
  assert.equal(classifyCookie('lang'), 'preference');
  assert.equal(classifyCookie('theme'), 'preference');
  assert.equal(classifyCookie('tz'), 'preference');
});

test('genuine session/auth cookies stay classified as session', () => {
  assert.equal(classifyCookie('sl_session'), 'session');
  assert.equal(classifyCookie('connect.sid'), 'session');
  assert.equal(classifyCookie('PHPSESSID'), 'session');
  assert.equal(classifyCookie('jwt'), 'session');
  assert.equal(classifyCookie('access_token'), 'session');
  assert.equal(classifyCookie('csrf_token'), 'session');
  assert.equal(classifyCookie('auth'), 'session');
});

test('an unrecognized cookie stays "unknown" so it is never under-reported', () => {
  assert.equal(classifyCookie('foo'), 'unknown');
  assert.equal(classifyCookie(''), 'unknown');
  assert.equal(classifyCookie('X-Custom-Thing'), 'unknown');
});

test('third-party bot-management / CDN cookies are classified infra (not the operator to fix)', () => {
  // Flagged live on nytimes, reuters, etsy (datadome) and ebay (bm_so).
  assert.equal(classifyCookie('datadome'), 'infra');
  assert.equal(classifyCookie('bm_so'), 'infra');
  assert.equal(classifyCookie('ak_bmsc'), 'infra');
  assert.equal(classifyCookie('__cf_bm'), 'infra');
  assert.equal(classifyCookie('cf_clearance'), 'infra');
  assert.equal(classifyCookie('visid_incap_123'), 'infra');
});

test('a double-submit CSRF token is exempt from HttpOnly but stays a session cookie', () => {
  // dropbox's __Host-js_csrf was flagged for missing HttpOnly, which would break
  // the CSRF defence — the page must be able to read it.
  assert.equal(isCsrfToken('__Host-js_csrf'), true);
  assert.equal(isCsrfToken('csrftoken'), true);
  assert.equal(isCsrfToken('XSRF-TOKEN'), true);
  // Still needs Secure/SameSite, so it is still a session-class cookie.
  assert.equal(classifyCookie('__Host-js_csrf'), 'session');
  // An ambiguous name that also looks like a session id is NOT exempt.
  assert.equal(isCsrfToken('csrf_sessionid'), false);
  assert.equal(isCsrfToken('theme'), false);
});
