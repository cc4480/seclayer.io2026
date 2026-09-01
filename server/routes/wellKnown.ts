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

export function buildRobotsTxt(): string {
  // Allow the marketing surface to be indexed; keep the API and app internals out.
  return [
    'User-agent: *',
    'Disallow: /api/',
    'Disallow: /dashboard',
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

export function buildSitemapXml(): string {
  const origin = siteOrigin();
  const urls = PUBLIC_PAGES.map((path) => `  <url><loc>${origin}${path}</loc></url>`).join('\n');
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
