import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLibraries, extractResourceRefs, analyzeSecrets } from './staticAnalysis.js';

const scriptTag = (url: string) => `<html><head><script src="${url}"></script></head><body></body></html>`;

test('flags a vulnerable jQuery loaded via <script src>', () => {
  const libs = analyzeLibraries(scriptTag('/vendor/jquery-1.12.4.min.js'));
  assert.equal(libs.length, 1);
  assert.equal(libs[0].name, 'jQuery');
  assert.equal(libs[0].version, '1.12.4');
});

test('does NOT flag a version string that only appears in prose/comments (SCA false positive)', () => {
  // A changelog/comment mentioning an old version must not be read as a loaded dep.
  const html = `<html><body><p>We migrated off jquery-1.9.0 last year.</p><!-- was lodash-4.17.4 --></body></html>`;
  assert.deepEqual(analyzeLibraries(html), []);
});

test('extractResourceRefs pulls only src/href URLs', () => {
  const refs = extractResourceRefs(`<script src="/a/jquery-1.12.4.js"></script><link href="/b.css"><p>jquery-2.0.0</p>`);
  assert.match(refs, /jquery-1\.12\.4/);
  assert.match(refs, /b\.css/);
  assert.ok(!refs.includes('2.0.0'), 'prose text is not a resource ref');
});

test('Lodash: vulnerable 4.17.x line (< 4.17.21) is now flagged', () => {
  for (const v of ['4.17.4', '4.17.11', '4.17.20', '4.16.6', '4.0.0']) {
    const libs = analyzeLibraries(scriptTag(`https://cdn.example/lodash@${v}/lodash.min.js`));
    assert.equal(libs.length, 1, `lodash ${v} should be flagged`);
    assert.equal(libs[0].version, v);
  }
});

test('Lodash: patched 4.17.21+ is NOT flagged', () => {
  for (const v of ['4.17.21', '4.17.22', '4.18.0']) {
    assert.deepEqual(analyzeLibraries(scriptTag(`https://cdn.example/lodash@${v}/lodash.min.js`)), [],
      `lodash ${v} must not be flagged`);
  }
});

test('secret detection screens low-entropy placeholders but flags a high-entropy key', () => {
  // Low-entropy filler (all one character) is screened out as a placeholder.
  assert.equal(analyzeSecrets('const k = "sk_live_' + 'a'.repeat(30) + '";').length, 0, 'filler is a placeholder');
  // A high-entropy key is detected. Built at runtime from base64 so no literal
  // secret is ever committed to the repo (which would trip secret push protection).
  const body = Buffer.from('seclayer-synthetic-entropy-seed-01').toString('base64').replace(/[^0-9a-zA-Z]/g, '').slice(0, 26);
  const detected = analyzeSecrets('const k = "sk_live_' + body + '";');
  assert.equal(detected.length, 1, 'a high-entropy sk_live-shaped key is a real detection');
  assert.match(detected[0].issue, /Stripe/);
});
