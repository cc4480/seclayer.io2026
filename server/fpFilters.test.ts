import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLikelyPlaceholderSecret, xssReflectionExecutes } from './fpFilters.js';

test('placeholder secrets: documented AWS example key is filtered', () => {
  assert.equal(isLikelyPlaceholderSecret('AKIAIOSFODNN7EXAMPLE'), true);
});

test('placeholder secrets: marker words are filtered', () => {
  assert.equal(isLikelyPlaceholderSecret('sk_live_YOUR_API_KEY_HERE'), true);
  assert.equal(isLikelyPlaceholderSecret('AIzaSyDUMMYKEYplaceholder1234567890abc'), true);
  assert.equal(isLikelyPlaceholderSecret('sk_live_examplekeyexamplekeyexample'), true);
  assert.equal(isLikelyPlaceholderSecret('AKIAXXXXXXXXXXXXXXXX'), true);
});

test('placeholder secrets: low-entropy / repeated / sequential filler is filtered', () => {
  assert.equal(isLikelyPlaceholderSecret('sk_live_000000000000000000000000'), true); // all zeros
  assert.equal(isLikelyPlaceholderSecret('sk_live_aaaaaaaaaaaaaaaaaaaaaaaa'), true); // one char
  assert.equal(isLikelyPlaceholderSecret('sk_live_0123456789abcdefghijklmn'), true); // ascending run
});

test('placeholder secrets: realistic random keys are NOT filtered', () => {
  assert.equal(isLikelyPlaceholderSecret('sk_live_51H8xN2eZvKYlo2Cq7Bd4RtP9wMz'), false);
  assert.equal(isLikelyPlaceholderSecret('AKIA3F7K9QZ2WLMN8XYT'), false);
  assert.equal(isLikelyPlaceholderSecret('gho_16C7e42F292c6912E7710c838347Ae178B4a'), false);
});

test('xss gate: HTML reflection in an executing context is exploitable', () => {
  const html = '<html><body><div><script>xss_probe_ab12</script></div></body></html>';
  const idx = html.indexOf('<script>xss_probe_ab12</script>');
  assert.equal(xssReflectionExecutes('text/html; charset=utf-8', html, idx), true);
});

test('xss gate: reflection in a non-HTML (JSON) response is suppressed', () => {
  const body = '{"q":"<script>xss_probe_ab12</script>"}';
  const idx = body.indexOf('<script>');
  assert.equal(xssReflectionExecutes('application/json', body, idx), false);
});

test('xss gate: reflection inside an HTML comment is suppressed', () => {
  const html = '<html><body><!-- debug: <script>xss_probe_ab12</script> --></body></html>';
  const idx = html.indexOf('<script>xss');
  assert.equal(xssReflectionExecutes('text/html', html, idx), false);
});

test('xss gate: reflection inside <textarea> / <title> is suppressed', () => {
  const ta = '<html><body><textarea><script>xss_probe_ab12</script></textarea></body></html>';
  assert.equal(xssReflectionExecutes('text/html', ta, ta.indexOf('<script>xss')), false);

  const ti = '<html><head><title>Search: <script>xss_probe_ab12</script></title></head></html>';
  assert.equal(xssReflectionExecutes('text/html', ti, ti.indexOf('<script>xss')), false);
});

test('xss gate: reflection after a CLOSED comment still executes', () => {
  const html = '<html><body><!-- note --><div><script>xss_probe_ab12</script></div></body></html>';
  const idx = html.indexOf('<script>xss');
  assert.equal(xssReflectionExecutes('text/html', html, idx), true);
});

test('xss gate: absent content-type is treated as possibly-HTML (no false negative)', () => {
  const html = '<div><script>xss_probe_ab12</script></div>';
  assert.equal(xssReflectionExecutes(null, html, html.indexOf('<script>')), true);
});
