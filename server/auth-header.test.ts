import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuthHeader } from './scanner.js';

test('empty input yields no headers', () => {
  assert.deepEqual(parseAuthHeader(undefined), {});
  assert.deepEqual(parseAuthHeader('  '), {});
});

test('bare Bearer/Basic tokens become an Authorization header', () => {
  assert.deepEqual(parseAuthHeader('Bearer eyJhbGciOiJIUzI1.abc.def'), { Authorization: 'Bearer eyJhbGciOiJIUzI1.abc.def' });
  assert.deepEqual(parseAuthHeader('Basic dXNlcjpwYXNz'), { Authorization: 'Basic dXNlcjpwYXNz' });
});

test('explicit Header: value form is honored', () => {
  assert.deepEqual(parseAuthHeader('Cookie: session=abc; theme=dark'), { Cookie: 'session=abc; theme=dark' });
  assert.deepEqual(parseAuthHeader('X-API-Key: secret123'), { 'X-API-Key': 'secret123' });
  assert.deepEqual(parseAuthHeader('Authorization: Bearer xyz'), { Authorization: 'Bearer xyz' });
});

test('scheme-prefixed value with no header name stays Authorization', () => {
  // "Bearer ..." is not parsed as a header even though it contains no colon.
  assert.deepEqual(parseAuthHeader('Bearer token-without-colon'), { Authorization: 'Bearer token-without-colon' });
});
