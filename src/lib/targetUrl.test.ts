import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTargetUrl, sameTarget } from './targetUrl.js';

test('normalizeTargetUrl canonicalizes scheme, trailing slash, and host case', () => {
  assert.equal(normalizeTargetUrl('vibe-scan.replit.app'), 'https://vibe-scan.replit.app');
  assert.equal(normalizeTargetUrl('https://vibe-scan.replit.app'), 'https://vibe-scan.replit.app');
  assert.equal(normalizeTargetUrl('https://vibe-scan.replit.app/'), 'https://vibe-scan.replit.app');
  assert.equal(normalizeTargetUrl('HTTPS://Vibe-Scan.Replit.App/'), 'https://vibe-scan.replit.app');
});

test('sameTarget treats the missing-scheme and explicit-https forms as one target', () => {
  // The exact mismatch that made the scan-diff pick the wrong baseline.
  assert.ok(sameTarget('vibe-scan.replit.app', 'https://vibe-scan.replit.app'));
  assert.ok(sameTarget('https://x.com/', 'x.com'));
});

test('sameTarget keeps genuinely different targets distinct', () => {
  assert.ok(!sameTarget('http://x.com', 'https://x.com'), 'http and https are different origins');
  assert.ok(!sameTarget('x.com/app', 'x.com/admin'), 'different paths are different targets');
  assert.ok(!sameTarget('a.com', 'b.com'));
});
