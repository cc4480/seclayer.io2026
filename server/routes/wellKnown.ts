// Public, unauthenticated site-policy files served from a trusted, static
// source (never from user input):
//   - /robots.txt                    crawler policy — keep the API surface out
//                                     of search indexes.
//   - /.well-known/security.txt      RFC 9116 vulnerability-disclosure contact,
//                                     which a security product in particular is
//                                     expected to publish.
// SECURITY_CONTACT / SECURITY_POLICY_URL override the defaults; when no contact
// is configured we fall back to a security@<host> mailto derived from APP_URL so
// the file is still valid rather than empty.
import type express from 'express';
import { config } from '../config.js';

function securityContact(): string {
  const explicit = (process.env.SECURITY_CONTACT || '').trim();
  if (explicit) return explicit;
  try {
    if (config.appUrl) return `mailto:security@${new URL(config.appUrl).hostname}`;
  } catch { /* fall through */ }
  return 'mailto:security@seclayer.io';
}

export function buildRobotsTxt(): string {
  // Allow the marketing surface to be indexed; keep the API and app internals out.
  return [
    'User-agent: *',
    'Disallow: /api/',
    'Disallow: /dashboard',
    'Allow: /',
    '',
  ].join('\n');
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

  const securityTxtHandler = (_req: express.Request, res: express.Response) => {
    res.type('text/plain').send(buildSecurityTxt());
  };
  app.get('/.well-known/security.txt', securityTxtHandler);
  // Legacy top-level location some scanners still check.
  app.get('/security.txt', securityTxtHandler);
}
