import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyCookie } from './cookieClassify.js';

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
