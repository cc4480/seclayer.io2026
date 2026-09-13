#!/usr/bin/env node
// Pings IndexNow (Bing, Yandex, Seznam, Naver) with every URL in this site's
// own sitemap, so a fresh deploy doesn't have to wait on organic re-crawl.
//
// The key is not a secret: it's already published at /<key>.txt, which is
// how IndexNow verifies the submitter owns the site. See indexnow.org.
// Run from CI after a push to the deploy branch; a failure here should never
// fail the build, so callers should treat a non-zero exit as informational.

const SITE = process.argv[2] || process.env.SITE_URL;
const KEY = '9accf697f6284608d522578041abe59e';

if (!SITE) {
  console.error('Usage: node indexnow-ping.mjs <site-url>');
  process.exit(1);
}

const origin = SITE.replace(/\/$/, '');

// A sitemap index points at child sitemaps instead of pages directly
// (<sitemap><loc>...) — resolve one level of that so this also works for
// generators (e.g. Astro's) that always emit an index.
async function fetchLocs(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetching ${url}: HTTP ${res.status}`);
  const xml = await res.text();
  return [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
}

async function main() {
  let urlList = await fetchLocs(`${origin}/sitemap.xml`);
  if (urlList.every((u) => u.endsWith('.xml'))) {
    const child = await Promise.all(urlList.map(fetchLocs));
    urlList = child.flat();
  }
  if (urlList.length === 0) throw new Error('sitemap had no page <loc> entries');

  const host = new URL(origin).host;
  const submit = await fetch('https://api.indexnow.org/indexnow', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ host, key: KEY, keyLocation: `${origin}/${KEY}.txt`, urlList }),
  });

  console.log(`IndexNow: submitted ${urlList.length} URL(s) for ${host} -> HTTP ${submit.status}`);
  if (!submit.ok) process.exit(1);
}

main().catch((err) => {
  console.error('IndexNow ping failed:', err.message);
  process.exit(1);
});
