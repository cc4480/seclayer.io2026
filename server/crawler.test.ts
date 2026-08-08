import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractLinks,
  extractForms,
  extractScriptEndpoints,
  targetsFromHtml,
  paramsOf,
  dedupeTargets,
  sameOrigin,
  crawlSite,
} from './crawler.js';

const BASE = 'https://app.test/';

test('extractLinks keeps same-origin page links and drops assets/external/mailto', () => {
  const html = `
    <a href="/about">About</a>
    <a href="search?q=1">Search</a>
    <a href="https://other.test/x">External</a>
    <a href="mailto:a@b.com">Mail</a>
    <a href="/logo.png">Logo</a>
    <a href="#section">Anchor</a>
    <a href="https://app.test/contact#top">Contact</a>`;
  const links = extractLinks(html, BASE);
  assert.ok(links.includes('https://app.test/about'));
  assert.ok(links.includes('https://app.test/search?q=1'));
  assert.ok(links.includes('https://app.test/contact')); // fragment stripped
  assert.ok(!links.some((l) => l.includes('other.test')));
  assert.ok(!links.some((l) => l.includes('mailto')));
  assert.ok(!links.some((l) => l.includes('logo.png')));
});

test('extractForms captures action, method, and field names', () => {
  const html = `
    <form action="/login" method="POST">
      <input name="username"><input name="password" type="password">
    </form>
    <form action="search">
      <input name="q"><select name="cat"></select>
    </form>
    <form action="/empty"></form>`;
  const forms = extractForms(html, BASE);
  const login = forms.find((f) => f.url.endsWith('/login'))!;
  assert.equal(login.method, 'POST');
  assert.deepEqual(login.params.sort(), ['password', 'username']);
  assert.equal(login.discoveredOnPage, BASE, 'stamps the page the form was found on, not just its action URL');
  const search = forms.find((f) => f.url.endsWith('/search'))!;
  assert.equal(search.method, 'GET');
  assert.deepEqual(search.params.sort(), ['cat', 'q']);
  assert.ok(!forms.some((f) => f.url.endsWith('/empty'))); // no fields -> skipped
});

test('extractScriptEndpoints finds same-origin api paths in inline JS', () => {
  const html = `<script>
    fetch("/api/users?id=1");
    const u = '/graphql';
    axios.get("/v2/orders?status=open");
    fetch("https://cdn.other.test/api/x");
  </script>`;
  const eps = extractScriptEndpoints(html, BASE);
  assert.ok(eps.some((e) => e.endsWith('/api/users?id=1')));
  assert.ok(eps.some((e) => e.endsWith('/graphql')));
  assert.ok(eps.some((e) => e.endsWith('/v2/orders?status=open')));
  assert.ok(!eps.some((e) => e.includes('other.test')));
});

test('paramsOf and sameOrigin behave correctly', () => {
  assert.deepEqual(paramsOf('https://app.test/x?a=1&b=2').sort(), ['a', 'b']);
  assert.deepEqual(paramsOf('https://app.test/x'), []);
  assert.equal(sameOrigin('https://app.test/a', 'https://app.test/b'), true);
  assert.equal(sameOrigin('https://app.test', 'https://evil.test'), false);
});

test('dedupeTargets collapses same endpoint+params and drops param-less targets', () => {
  const deduped = dedupeTargets([
    { url: 'https://app.test/s?q=1', method: 'GET', params: ['q'], source: 'query' },
    { url: 'https://app.test/s?q=2', method: 'GET', params: ['q'], source: 'query' },
    { url: 'https://app.test/s', method: 'GET', params: [], source: 'query' },
    { url: 'https://app.test/login', method: 'POST', params: ['user'], source: 'form' },
  ]);
  assert.equal(deduped.length, 2); // one /s?q + one POST /login
});

test('targetsFromHtml combines forms, script endpoints, and parameterized links', () => {
  const html = `
    <a href="/products?category=books">Books</a>
    <a href="/about">About</a>
    <form action="/login" method="post"><input name="email"></form>
    <script>fetch("/api/cart?itemId=5")</script>`;
  const targets = targetsFromHtml(html, BASE);
  const keys = targets.map((t) => `${t.method} ${new URL(t.url).pathname}`).sort();
  assert.deepEqual(keys, ['GET /api/cart', 'GET /products', 'POST /login']);
  // /about has no params -> not an injectable target
  assert.ok(!targets.some((t) => t.url.includes('/about')));
});

test('crawlSite discovers targets from seeded root HTML without extra fetches for a static seed', async () => {
  const seedHtml = `
    <a href="/products?category=books">Books</a>
    <form action="/login" method="post"><input name="email"></form>
    <script>fetch("/api/cart?itemId=5")</script>`;
  // fetchFn returns non-HTML so crawl does not expand beyond the seed.
  const fetchFn = async () =>
    new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
  const result = await crawlSite(BASE, fetchFn as any, { seedHtml, maxPages: 5, budgetMs: 2000 });
  const paths = result.targets.map((t) => {
    const u = new URL(t.url);
    return `${t.method} ${u.pathname}`;
  });
  assert.ok(paths.includes('GET /products'));
  assert.ok(paths.includes('POST /login'));
  assert.ok(paths.includes('GET /api/cart'));
});

test('crawlSite captures every fetched response (HTML or not) for passive analysis, with Set-Cookie', async () => {
  // Regression coverage: captures used to not exist at all — a crawled page's
  // body/headers were discarded the instant it wasn't text/html, so secret-
  // signature and cookie-flag analysis (which run against captures — see
  // scanner.ts) never saw non-HTML endpoints like a JSON API response.
  const seedHtml = `<a href="/api/settings">settings</a><a href="/dashboard">dashboard</a>`;
  const fetchFn = async (url: string) => {
    if (url.endsWith('/api/settings')) {
      return new Response('{"apiKey":"secret-shaped-value"}', { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.endsWith('/dashboard')) {
      return new Response('<!doctype html><html><body>dashboard</body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html', 'set-cookie': 'sessionId=abc' },
      });
    }
    return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } });
  };
  const result = await crawlSite(BASE, fetchFn as any, { seedHtml, maxPages: 5, budgetMs: 2000 });

  const settings = result.captures.find((c) => c.url.endsWith('/api/settings'));
  assert.ok(settings, 'the JSON endpoint must be captured even though it is never an HTML "page"');
  assert.equal(settings!.contentType, 'application/json');
  assert.match(settings!.text, /secret-shaped-value/);
  assert.ok(!result.pages.includes(settings!.url), 'a non-HTML response is captured but not counted as a crawled page');

  const dashboard = result.captures.find((c) => c.url.endsWith('/dashboard'));
  assert.ok(dashboard, 'the HTML page must ALSO be captured (captures is a superset of pages)');
  assert.deepEqual(dashboard!.setCookie, ['sessionId=abc']);
});
