import type { Request, Response, NextFunction } from 'express';

// The production Content-Security-Policy, tuned for THIS app specifically.
//
// The client is a Vite-built SPA whose ONLY scripts are same-origin ES modules
// (the built dist/index.html contains no inline <script> — verified), so
// script-src can stay strict at 'self' with no 'unsafe-inline'/'unsafe-eval'.
// What the app genuinely needs loosened:
//   - style-src 'unsafe-inline' — framer-motion and React style={{…}} write
//     inline style attributes at runtime; there is no hash-based alternative for
//     style attributes. (Style injection is low-severity next to script.)
//   - img-src data:  — target screenshots are embedded as data: URIs
//     (see TargetScreenshot.dataUri), and inline SVG/canvas exports.
//   - font-src data: — belt-and-suspenders for any inlined font.
// frame-ancestors 'none' also closes the clickjacking finding at the modern
// layer; X-Frame-Options: DENY below keeps legacy browsers covered.
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "form-action 'self'",
].join('; ');

export interface SecurityHeaderOptions {
  isProd: boolean;
}

// Baseline security headers on every response — API, HTML, and errors alike.
//
// HSTS and the strict CSP are production-only: HSTS must never be advertised
// over the plaintext dev origin, and the CSP's `script-src 'self'` would break
// Vite's dev HMR client (which relies on inline scripts, eval, and a ws://
// connection). In dev, the three baseline headers still apply.
export function securityHeaders({ isProd }: SecurityHeaderOptions) {
  return (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (isProd) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
      res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    }
    next();
  };
}
