import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isSourceMap, extractScriptSrcs, extractSourceMappingUrls } from './sourceMapProbe.js';

test('isSourceMap accepts a real Source Map v3 and rejects the SPA HTML fallback', () => {
  const real = JSON.stringify({ version: 3, file: 'app.js', sources: ['src/app.ts'], sourcesContent: ['const x=1'], mappings: 'AAAA,SAAS' });
  assert.equal(isSourceMap(real), true);
  assert.equal(isSourceMap('<!doctype html><html><body>app</body></html>'), false);
  // JSON that merely has a "version" but is not a source map must not match.
  assert.equal(isSourceMap('{"version":"1.0.0","name":"app"}'), false);
  assert.equal(isSourceMap(''), false);
});

test('extractScriptSrcs returns same-origin JS bundles, resolving relative URLs', () => {
  const html = `
    <script src="/assets/index-abc123.js"></script>
    <script src="https://target.test/vendor.mjs"></script>
    <script src="https://cdn.other.com/analytics.js"></script>
    <script>inline()</script>`;
  const srcs = extractScriptSrcs(html, 'https://target.test/');
  assert.ok(srcs.includes('https://target.test/assets/index-abc123.js'), 'relative → absolute same-origin');
  assert.ok(srcs.includes('https://target.test/vendor.mjs'), 'absolute same-origin .mjs');
  assert.ok(!srcs.some((s) => s.includes('cdn.other.com')), 'cross-origin bundle excluded');
});

test('extractSourceMappingUrls resolves a same-origin comment ref and skips inline data: maps', () => {
  const js = 'console.log(1)\n//# sourceMappingURL=index-abc123.js.map\n';
  const urls = extractSourceMappingUrls(js, 'https://target.test/assets/index-abc123.js');
  assert.deepEqual(urls, ['https://target.test/assets/index-abc123.js.map']);
  // Inline base64 maps are already in the bundle — not separately exposed.
  assert.deepEqual(extractSourceMappingUrls('x\n//# sourceMappingURL=data:application/json;base64,eyJ9\n', 'https://target.test/a.js'), []);
});
