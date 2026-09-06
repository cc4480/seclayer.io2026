// Per-route <head> metadata for the SPA shell.
//
// Every route was served the same index.html, which meant every URL carried
// <link rel="canonical" href="https://seclayer.app/">. That is an explicit
// instruction to a search engine that /docs, /privacy and /terms are duplicates
// of the homepage and should not be indexed separately — and Google obeyed it,
// reporting them as "Discovered - currently not indexed". A crawler cannot be
// expected to wait for client-side JavaScript to correct a canonical it was
// handed in the HTML.
//
// So the shell is rewritten per route before it is sent. Client-side SEO still
// runs and still matters for in-app navigation; this is what the crawler sees
// on the first byte.

export interface PageMeta {
  title: string;
  description: string;
  /** Absolute path used for canonical and og:url. */
  path: string;
  /** Share links point at somebody's private scan; they must never be indexed. */
  noindex?: boolean;
}

const SITE = 'https://seclayer.app';

const ROUTES: { match: RegExp; meta: (path: string) => PageMeta }[] = [
  {
    match: /^\/docs\/?$/,
    meta: () => ({
      path: '/docs',
      title: 'Documentation — Seclayer',
      description:
        'How to run a Seclayer scan: the REST API, the MCP server for coding agents, scan tiers, and what each finding means.',
    }),
  },
  {
    match: /^\/privacy\/?$/,
    meta: () => ({
      path: '/privacy',
      title: 'Privacy Policy — Seclayer',
      description:
        'What Seclayer collects when you run a scan, how long it is kept, who it is shared with, and how to have it deleted.',
    }),
  },
  {
    match: /^\/terms\/?$/,
    meta: () => ({
      path: '/terms',
      title: 'Terms of Service — Seclayer',
      description:
        'The terms that apply when you use Seclayer, including what you are permitted to scan.',
    }),
  },
  {
    match: /^\/r\/[A-Za-z0-9_-]+\/?$/,
    meta: (path) => ({
      path,
      title: 'Shared scan report — Seclayer',
      description: 'A Seclayer scan report shared by its owner.',
      noindex: true,
    }),
  },
];

/** Homepage metadata is whatever the built index.html already carries. */
export function metaForPath(path: string): PageMeta | null {
  for (const r of ROUTES) {
    if (r.match.test(path)) return r.meta(path);
  }
  return null;
}

function escapeAttr(v: string): string {
  return v.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Rewrite the shell's head for one route.
 *
 * Replaces rather than appends: a second <link rel="canonical"> alongside the
 * original leaves the crawler to choose between them, and it may well choose
 * the one we were trying to override.
 */
export function applyPageMeta(html: string, meta: PageMeta): string {
  const url = `${SITE}${meta.path.replace(/\/$/, '') || '/'}`;
  const title = escapeAttr(meta.title);
  const desc = escapeAttr(meta.description);

  let out = html
    .replace(/<title>[\s\S]*?<\/title>/i, `<title>${title}</title>`)
    .replace(
      /<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i,
      `<meta name="description" content="${desc}" />`,
    )
    .replace(
      /<link\s+rel="canonical"\s+href="[^"]*"\s*\/?>/i,
      `<link rel="canonical" href="${url}" />`,
    )
    .replace(
      /<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i,
      `<meta property="og:title" content="${title}" />`,
    )
    .replace(
      /<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i,
      `<meta property="og:description" content="${desc}" />`,
    )
    .replace(
      /<meta\s+property="og:url"\s+content="[^"]*"\s*\/?>/i,
      `<meta property="og:url" content="${url}" />`,
    )
    .replace(
      /<meta\s+name="twitter:title"\s+content="[^"]*"\s*\/?>/i,
      `<meta name="twitter:title" content="${title}" />`,
    )
    .replace(
      /<meta\s+name="twitter:description"\s+content="[^"]*"\s*\/?>/i,
      `<meta name="twitter:description" content="${desc}" />`,
    );

  if (meta.noindex) {
    out = out.replace(
      /<meta\s+name="robots"\s+content="[^"]*"\s*\/?>/i,
      '<meta name="robots" content="noindex, nofollow" />',
    );
  }

  return out;
}
