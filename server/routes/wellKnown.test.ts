import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
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
