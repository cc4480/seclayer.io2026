import { test } from 'node:test';
import assert from 'node:assert/strict';
import { metaForPath, applyPageMeta } from './pageMeta.js';

// A shell shaped like the real built index.html.
const SHELL = `<!doctype html><html><head>
<title>Seclayer — Black-Box Penetration Testing SaaS &amp; MCP Server</title>
<meta name="description" content="Point Seclayer at a public URL." />
<meta name="robots" content="index, follow, max-image-preview:large" />
<link rel="canonical" href="https://seclayer.app/" />
<meta property="og:title" content="Seclayer" />
<meta property="og:description" content="Old description." />
<meta property="og:url" content="https://seclayer.app/" />
</head><body></body></html>`;

// Shaped like the real built index.html's <body>, which the plain SHELL above
// doesn't have — the noscript-rewrite tests need the actual paragraph the
// rewrite matches against.
const SHELL_WITH_NOSCRIPT = `<!doctype html><html><head>
<title>Seclayer</title>
<meta name="description" content="Old." />
<meta name="robots" content="index, follow" />
<link rel="canonical" href="https://seclayer.app/" />
</head><body>
<noscript>
  <h1>Seclayer — black-box penetration testing SaaS &amp; MCP server</h1>
  <p>Point Seclayer at a public URL and get a real black-box penetration test.</p>
  <p>Seclayer needs JavaScript to run a scan interactively. These pages read fine without it:</p>
  <nav><ul><li><a href="/">Home</a></li></ul></nav>
</noscript>
<div id="root"></div>
</body></html>`;

test('a non-JS crawler on /docs gets that route\'s subject, not just the homepage noscript copy', () => {
  const html = applyPageMeta(SHELL_WITH_NOSCRIPT, metaForPath('/docs')!);
  assert.match(html, /<h2>Documentation — Seclayer<\/h2>/);
  assert.match(html, /<p>How to run a Seclayer scan/);
  // Still ahead of the nav, so it doesn't look tacked on after the links.
  assert.ok(html.indexOf('<h2>Documentation') < html.indexOf('<nav>'));
});

test('noindex routes are left out of the noscript rewrite', () => {
  const meta = metaForPath('/r/AbC123_-xy')!;
  const html = applyPageMeta(SHELL_WITH_NOSCRIPT, meta);
  assert.doesNotMatch(html, /<h2>/);
});

test('the homepage keeps the built metadata', () => {
  assert.equal(metaForPath('/'), null);
});

test('each content route gets its own canonical, not the homepage', () => {
  // This is the bug that stopped these pages being indexed: every URL claimed
  // the homepage as its canonical, so Google treated them as duplicates.
  for (const [p, expected] of [
    ['/docs', 'https://seclayer.app/docs'],
    ['/privacy', 'https://seclayer.app/privacy'],
    ['/terms', 'https://seclayer.app/terms'],
  ] as const) {
    const meta = metaForPath(p);
    assert.ok(meta, `no meta for ${p}`);
    const html = applyPageMeta(SHELL, meta);
    assert.match(html, new RegExp(`<link rel="canonical" href="${expected}" />`));
    assert.doesNotMatch(html, /canonical" href="https:\/\/seclayer\.app\/"/);
  }
});

test('a trailing slash does not produce a doubled canonical path', () => {
  const meta = metaForPath('/privacy/');
  assert.ok(meta);
  assert.match(applyPageMeta(SHELL, meta), /href="https:\/\/seclayer\.app\/privacy"/);
});

test('each route gets a distinct title and description', () => {
  const docs = applyPageMeta(SHELL, metaForPath('/docs')!);
  const terms = applyPageMeta(SHELL, metaForPath('/terms')!);
  assert.match(docs, /<title>Documentation — Seclayer<\/title>/);
  assert.match(terms, /<title>Terms of Service — Seclayer<\/title>/);
  assert.doesNotMatch(docs, /Point Seclayer at a public URL\./);
});

test('og tags track the canonical rather than being left behind', () => {
  const html = applyPageMeta(SHELL, metaForPath('/terms')!);
  assert.match(html, /og:url" content="https:\/\/seclayer\.app\/terms"/);
  assert.match(html, /og:title" content="Terms of Service — Seclayer"/);
  assert.doesNotMatch(html, /og:description" content="Old description\."/);
});

test('shared report links are noindex', () => {
  // A share link points at somebody's private scan results. Indexing one would
  // publish findings the owner shared with a specific person.
  const meta = metaForPath('/r/AbC123_-xy');
  assert.ok(meta);
  assert.equal(meta.noindex, true);
  const html = applyPageMeta(SHELL, meta);
  assert.match(html, /<meta name="robots" content="noindex, nofollow" \/>/);
  assert.doesNotMatch(html, /content="index, follow/);
});

test('indexable routes keep the original robots directive', () => {
  const html = applyPageMeta(SHELL, metaForPath('/docs')!);
  assert.match(html, /content="index, follow, max-image-preview:large"/);
});

test('unknown paths get no metadata, so the 404 path is unaffected', () => {
  assert.equal(metaForPath('/wp-login.php'), null);
  assert.equal(metaForPath('/docs/extra'), null);
});
