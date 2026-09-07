// Public, unauthenticated site-policy files served from a trusted, static
// source (never from user input):
//   - /robots.txt                    crawler policy — keep the API surface out
//                                     of search indexes.
//   - /sitemap.xml                   the indexable marketing/docs pages.
//   - /.well-known/security.txt      RFC 9116 vulnerability-disclosure contact,
//                                     which a security product in particular is
//                                     expected to publish.
// SECURITY_CONTACT / SECURITY_POLICY_URL override the defaults; when no contact
// is configured we fall back to a security@<host> mailto derived from APP_URL so
// the file is still valid rather than empty.
import type express from 'express';
import { config } from '../config.js';

// Public site origin used to build absolute URLs in the sitemap and OG/canonical
// tags server-side. Falls back to the real production domain (matching the
// static canonical/OG tags already hardcoded in index.html) so these stay valid
// even when APP_URL isn't set, e.g. in local dev.
function siteOrigin(): string {
  return config.appUrl || 'https://seclayer.app';
}

function securityContact(): string {
  const explicit = (process.env.SECURITY_CONTACT || '').trim();
  if (explicit) return explicit;
  try {
    if (config.appUrl) return `mailto:security@${new URL(config.appUrl).hostname}`;
  } catch { /* fall through */ }
  return 'mailto:security@seclayer.app';
}

// THE robots.txt. There is deliberately no public/robots.txt: this route is
// registered before express.static(dist), so a static file of that name is
// unreachable and silently dead. One existed for a while and drifted out of
// sync with this function — it still carried the `Disallow: /r/` rule below,
// which had therefore never actually been served to a crawler. Edit crawler
// policy HERE.
//
// This is not the whole story in production: Cloudflare's "managed robots.txt"
// feature, when enabled on the zone, PREPENDS its own AI-crawler block above
// whatever this returns, so the served file can disagree with this function.
// That is a dashboard setting, not something this file can control.
export function buildRobotsTxt(): string {
  // Allow the marketing surface to be indexed; keep the API and app internals out.
  return [
    'User-agent: *',
    'Disallow: /api/',
    'Disallow: /dashboard',
    // Per-report share links are somebody's private scan of their own
    // site. They already carry <meta name="robots" content="noindex,
    // nofollow"> (server/pageMeta.ts), but a crawler has to fetch the
    // page to discover that; this keeps it from being requested at all.
    'Disallow: /r/',
    'Allow: /',
    `Sitemap: ${siteOrigin()}/sitemap.xml`,
    '',
  ].join('\n');
}

// Every publicly indexable, unauthenticated page. Keep in sync with the SPA's
// path-based routes in useSeclayer.ts AND with SPA_ROUTES in server.ts — a page
// listed here that isn't in SPA_ROUTES is advertised to crawlers and then
// answers 404. Every other view is session-gated or has no stable URL of its own.
const PUBLIC_PAGES = ['/', '/docs', '/privacy', '/terms'];

// Per-page crawl hints for the sitemap.
//
// lastmod is maintained by hand, deliberately. Deriving it from the deploy
// time would claim every page changed on every deploy, which Google learns to
// ignore — and an ignored lastmod is worse than none, because the signal is
// gone exactly when a page really has changed. Update a date when that page's
// content actually changes.
const PAGE_META: Record<string, { lastmod: string; changefreq: string; priority: string }> = {
  '/':        { lastmod: '2026-09-06', changefreq: 'weekly',  priority: '1.0' },
  '/docs':    { lastmod: '2026-09-06', changefreq: 'monthly', priority: '0.8' },
  '/privacy': { lastmod: '2026-09-06', changefreq: 'yearly',  priority: '0.3' },
  '/terms':   { lastmod: '2026-09-06', changefreq: 'yearly',  priority: '0.3' },
};

export function buildSitemapXml(): string {
  const origin = siteOrigin();
  const urls = PUBLIC_PAGES.map((path) => {
    const m = PAGE_META[path];
    const hints = m
      ? `\n    <lastmod>${m.lastmod}</lastmod>\n    <changefreq>${m.changefreq}</changefreq>\n    <priority>${m.priority}</priority>`
      : '';
    return `  <url>\n    <loc>${origin}${path}</loc>${hints}\n  </url>`;
  }).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
}

export function buildSecurityTxt(): string {
  const contact = securityContact();
  const lines = [`Contact: ${contact}`];
  const policy = (process.env.SECURITY_POLICY_URL || '').trim();
  if (policy) lines.push(`Policy: ${policy}`);
  // Expiry is required by RFC 9116; publish a rolling one year out.
  const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  lines.push(`Expires: ${expires}`);
  lines.push('Preferred-Languages: en');
  lines.push('');
  return lines.join('\n');
}

export function registerWellKnownRoutes(app: express.Express) {
  app.get('/robots.txt', (_req, res) => {
    res.type('text/plain').send(buildRobotsTxt());
  });

  app.get('/sitemap.xml', (_req, res) => {
    res.type('application/xml').send(buildSitemapXml());
  });

  const securityTxtHandler = (_req: express.Request, res: express.Response) => {
    res.type('text/plain').send(buildSecurityTxt());
  };
  app.get('/.well-known/security.txt', securityTxtHandler);
  // Legacy top-level location some scanners still check.
  app.get('/security.txt', securityTxtHandler);
}
