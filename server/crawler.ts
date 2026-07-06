// Lightweight, bounded same-origin crawler + parameter discovery. Maps the real
// attack surface (page links, forms, and JS-referenced API endpoints) so the
// active probes can be aimed at parameters the application actually uses,
// instead of only a few hardcoded names. All network I/O is performed through
// an injected fetch (the scanner passes its SSRF-safe fetch), keeping this
// module free of circular dependencies and easy to unit test.

export type HttpMethod = "GET" | "POST";

export interface InjectableTarget {
  url: string; // absolute URL (for GET targets, includes the query string)
  method: HttpMethod;
  params: string[]; // parameter names available to fuzz
  source: "query" | "form" | "script";
}

export interface CrawlResult {
  pagesVisited: number;
  pages: string[];
  targets: InjectableTarget[];
}

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  perRequestMs?: number;
  budgetMs?: number;
  concurrency?: number;
  seedHtml?: string; // root HTML already fetched by the scanner (avoids a re-fetch)
}

const STATIC_ASSET_RE = /\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|cjs|map|woff2?|ttf|eot|otf|pdf|zip|gz|mp4|webm|mp3|wasm|avif)(?:$|\?)/i;

function resolveUrl(raw: string, base: string): string | null {
  try {
    return new URL(raw, base).toString();
  } catch {
    return null;
  }
}

export function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

function stripFragment(u: string): string {
  const i = u.indexOf("#");
  return i >= 0 ? u.slice(0, i) : u;
}

export function paramsOf(url: string): string[] {
  try {
    return [...new URL(url).searchParams.keys()];
  } catch {
    return [];
  }
}

// Extracts same-origin, non-asset page links from <a href> attributes.
export function extractLinks(html: string, baseUrl: string): string[] {
  const out = new Set<string>();
  const re = /<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const raw = m[1].trim();
    if (!raw || /^(mailto:|tel:|javascript:|data:|#)/i.test(raw)) continue;
    const abs = resolveUrl(raw, baseUrl);
    if (!abs || !/^https?:/i.test(abs)) continue;
    if (!sameOrigin(abs, baseUrl)) continue;
    if (STATIC_ASSET_RE.test(abs)) continue;
    out.add(stripFragment(abs));
  }
  return [...out];
}

// Extracts forms as injectable targets (action URL, method, and field names).
export function extractForms(html: string, baseUrl: string): InjectableTarget[] {
  const targets: InjectableTarget[] = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRe.exec(html))) {
    const attrs = fm[1];
    const inner = fm[2];
    const action = (attrs.match(/\baction\s*=\s*["']([^"']*)["']/i)?.[1] || "").trim();
    const url = resolveUrl(action || baseUrl, baseUrl);
    if (!url || !sameOrigin(url, baseUrl)) continue;
    const method: HttpMethod =
      (attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i)?.[1] || "GET").toUpperCase() === "POST" ? "POST" : "GET";
    const fields = new Set<string>();
    const fieldRe = /<(?:input|textarea|select)\b[^>]*?\bname\s*=\s*["']([^"']+)["']/gi;
    let f: RegExpExecArray | null;
    while ((f = fieldRe.exec(inner))) fields.add(f[1]);
    if (fields.size > 0) {
      targets.push({ url, method, params: [...fields], source: "form" });
    }
  }
  return targets;
}

// Extracts same-origin API-style endpoints referenced in inline/loaded scripts
// (e.g. fetch("/api/users?id=1"), "url":"/graphql"). Focused on /api, /graphql
// and versioned paths to avoid noise.
export function extractScriptEndpoints(html: string, baseUrl: string): string[] {
  const out = new Set<string>();
  const re = /["'`](\/(?:api|graphql|rest|v\d)[A-Za-z0-9_\-./]*(?:\?[^"'`\s]*)?)["'`]/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const abs = resolveUrl(m[1], baseUrl);
    if (abs && sameOrigin(abs, baseUrl) && !STATIC_ASSET_RE.test(abs)) out.add(abs);
  }
  return [...out];
}

// Extracts all injectable targets from a single HTML document: forms, JS-
// referenced API endpoints, and links that carry query parameters.
export function targetsFromHtml(html: string, baseUrl: string): InjectableTarget[] {
  const targets: InjectableTarget[] = [];
  targets.push(...extractForms(html, baseUrl));
  for (const ep of extractScriptEndpoints(html, baseUrl)) {
    const p = paramsOf(ep);
    if (p.length) targets.push({ url: ep, method: "GET", params: p, source: "script" });
  }
  for (const link of extractLinks(html, baseUrl)) {
    const p = paramsOf(link);
    if (p.length) targets.push({ url: link, method: "GET", params: p, source: "query" });
  }
  return targets;
}

// Collapses targets that fuzz the same endpoint + parameter set.
export function dedupeTargets(targets: InjectableTarget[]): InjectableTarget[] {
  const seen = new Map<string, InjectableTarget>();
  for (const t of targets) {
    if (!t.params.length) continue;
    let pathname = t.url;
    try {
      pathname = new URL(t.url).origin + new URL(t.url).pathname;
    } catch {}
    const key = `${t.method} ${pathname} ${[...t.params].sort().join(",")}`;
    if (!seen.has(key)) seen.set(key, t);
  }
  return [...seen.values()];
}

async function fetchWithTimeout(
  fetchFn: (url: string, init: RequestInit) => Promise<Response>,
  url: string,
  timeoutMs: number,
): Promise<Response> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetchFn(url, { method: "GET", signal: ctl.signal });
  } finally {
    clearTimeout(id);
  }
}

// Breadth-first, same-origin crawl bounded by page count, depth, and a wall-clock
// budget. Returns the deduped set of injectable targets discovered.
export async function crawlSite(
  rootUrl: string,
  fetchFn: (url: string, init: RequestInit) => Promise<Response>,
  opts: CrawlOptions = {},
): Promise<CrawlResult> {
  const maxPages = opts.maxPages ?? 10;
  const maxDepth = opts.maxDepth ?? 2;
  const perRequestMs = opts.perRequestMs ?? 3500;
  const budgetMs = opts.budgetMs ?? 15000;
  const concurrency = opts.concurrency ?? 3;

  const start = Date.now();
  const visited = new Set<string>();
  const pages: string[] = [];
  const targets: InjectableTarget[] = [];
  const queue: Array<{ url: string; depth: number }> = [{ url: stripFragment(rootUrl), depth: 0 }];

  const ingestHtml = (html: string, url: string, depth: number) => {
    pages.push(url);
    targets.push(...targetsFromHtml(html, url));
    if (depth < maxDepth) {
      for (const link of extractLinks(html, url)) {
        if (!visited.has(stripFragment(link))) queue.push({ url: link, depth: depth + 1 });
      }
    }
  };

  // Seed with the already-fetched root HTML to avoid an extra request.
  if (opts.seedHtml) {
    visited.add(stripFragment(rootUrl));
    ingestHtml(opts.seedHtml, stripFragment(rootUrl), 0);
  }

  while (queue.length && visited.size < maxPages && Date.now() - start < budgetMs) {
    const batch: Array<{ url: string; depth: number }> = [];
    while (queue.length && batch.length < concurrency && visited.size + batch.length < maxPages) {
      const item = queue.shift()!;
      if (visited.has(item.url)) continue;
      visited.add(item.url);
      batch.push(item);
    }
    if (!batch.length) break;

    await Promise.all(
      batch.map(async ({ url, depth }) => {
        try {
          const qp = paramsOf(url);
          if (qp.length) targets.push({ url, method: "GET", params: qp, source: "query" });
          const res = await fetchWithTimeout(fetchFn, url, perRequestMs);
          if (!/text\/html/i.test(res.headers.get("content-type") || "")) return;
          const html = await res.text();
          ingestHtml(html, url, depth);
        } catch {
          /* unreachable/blocked page — skip */
        }
      }),
    );
  }

  return { pagesVisited: pages.length, pages, targets: dedupeTargets(targets) };
}
