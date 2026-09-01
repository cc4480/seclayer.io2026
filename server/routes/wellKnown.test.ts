import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AddressInfo } from 'node:net';
import { registerWellKnownRoutes, buildRobotsTxt, buildSecurityTxt, buildSitemapXml } from './wellKnown.js';

async function withApp(app: express.Express, fn: (base: string) => Promise<void>) {
  const server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('robots.txt keeps the API surface out of indexes', () => {
  const body = buildRobotsTxt();
  assert.match(body, /User-agent: \*/);
  assert.match(body, /Disallow: \/api\//);
});

test('robots.txt points crawlers at the sitemap', () => {
  assert.match(buildRobotsTxt(), /^Sitemap: https?:\/\/.+\/sitemap\.xml$/m);
});

test('sitemap.xml is valid XML listing only public pages', () => {
  const body = buildSitemapXml();
  assert.match(body, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(body, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.match(body, /<loc>https?:\/\/[^<]+\/<\/loc>/);
  assert.match(body, /<loc>https?:\/\/[^<]+\/docs<\/loc>/);
  // Never leak session-gated or API routes into the public sitemap.
  assert.doesNotMatch(body, /\/api\//);
  assert.doesNotMatch(body, /\/dashboard/);
});

test('security.txt is RFC 9116-valid: has Contact and a future Expires', () => {
  const body = buildSecurityTxt();
  assert.match(body, /^Contact: /m);
  const expiresLine = body.split('\n').find((l) => l.startsWith('Expires:'));
  assert.ok(expiresLine, 'security.txt must carry an Expires field');
  const expires = new Date(expiresLine!.replace('Expires:', '').trim()).getTime();
  assert.ok(expires > Date.now(), 'Expires must be in the future');
});

test('SECURITY_CONTACT overrides the default contact', () => {
  const prev = process.env.SECURITY_CONTACT;
  process.env.SECURITY_CONTACT = 'mailto:hackers@example.com';
  try {
    assert.match(buildSecurityTxt(), /Contact: mailto:hackers@example\.com/);
  } finally {
    if (prev === undefined) delete process.env.SECURITY_CONTACT;
    else process.env.SECURITY_CONTACT = prev;
  }
});

test('serves the files over HTTP as text/plain', async () => {
  const app = express();
  registerWellKnownRoutes(app);
  await withApp(app, async (base) => {
    const robots = await fetch(`${base}/robots.txt`);
    assert.equal(robots.status, 200);
    assert.match(robots.headers.get('content-type') || '', /text\/plain/);

    const sec = await fetch(`${base}/.well-known/security.txt`);
    assert.equal(sec.status, 200);
    assert.match(await sec.text(), /Contact:/);

    const secLegacy = await fetch(`${base}/security.txt`);
    assert.equal(secLegacy.status, 200);

    const sitemap = await fetch(`${base}/sitemap.xml`);
    assert.equal(sitemap.status, 200);
    assert.match(sitemap.headers.get('content-type') || '', /application\/xml/);
  });
});

// The sitemap tells crawlers which URLs exist; server.ts's SPA_ROUTES decides
// which URLs actually return the app rather than a 404. They are declared in
// separate files, so a page added to one and not the other is advertised to
// Google and then answers 404 — invisible until a crawler finds it.
test('every page in the sitemap is a path the server actually serves', () => {
  const serverSrc = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'server.ts'),
    'utf8',
  );
  const routesLine = serverSrc.match(/const SPA_ROUTES = \[(.*?)\];/s);
  assert.ok(routesLine, 'could not find SPA_ROUTES in server.ts');

  // Rebuild the regexes from source and check each advertised path against them.
  const patterns = (routesLine![1].match(/\/\^[^,]*?\$\//g) ?? []).map((literal) => {
    const body = literal.slice(1, literal.lastIndexOf('/'));
    return new RegExp(body);
  });
  assert.ok(patterns.length > 0, 'parsed no route patterns from SPA_ROUTES');

  for (const loc of buildSitemapXml().match(/<loc>([^<]+)<\/loc>/g) ?? []) {
    const path = new URL(loc.replace(/<\/?loc>/g, '')).pathname;
    assert.ok(
      patterns.some((re) => re.test(path)),
      `sitemap advertises ${path}, but SPA_ROUTES would 404 it`,
    );
  }
});
