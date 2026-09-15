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
  source: "query" | "form" | "script" | "openapi";
  // POST body encoding. Defaults to form-urlencoded; "json" makes the fuzzer send
  // an application/json body (for API endpoints that only accept JSON).
  contentType?: "form" | "json";
  // For a "form" target, the page the <form> was found on — often DIFFERENT
  // from its action URL (e.g. a form on /post/1 posting to /api/comments).
  // The stored-XSS probe needs this: it's frequently the only page that
  // actually renders the persisted value back, so it must be a display
  // candidate alongside the action URL and site root.
  discoveredOnPage?: string;
}

// One fetched response from the crawl loop, captured regardless of content
// type (unlike `pages`, which is HTML only) — the raw material for passive
// analysis (secret signatures, cookie flags) to run against more than just
// the root document, e.g. a JSON API endpoint like /api/settings that the
// crawler visits but never treats as an HTML "page" to extract links from.
export interface CrawlCapture {
  url: string;
  status: number;
  contentType: string;
  text: string; // capped, see MAX_CAPTURE_CHARS
  setCookie: string[];
}

export interface CrawlResult {
  pagesVisited: number;
  pages: string[];
  targets: InjectableTarget[];
  captures: CrawlCapture[];
  // The cookies the crawl accumulated in-session (as a "name=value; …" Cookie
  // header), so the fuzzer and other post-crawl probes can stay in the same
  // session the crawl established. Empty when the app set no cookies.
  sessionCookie?: string;
}

// A minimal same-origin cookie jar for a session-aware crawl. The crawl is
// single-origin, so cookie domain/path scoping is unnecessary; it just carries
// name=value pairs forward and lets a later Set-Cookie overwrite an earlier one.
// A cookie deleted via Max-Age=0 / an expired Expires is dropped so a logout
// mid-crawl doesn't keep sending a dead session id.
export class CookieJar {
  private jar = new Map<string, string>();
  ingest(setCookieLines: string[]): void {
    for (const line of setCookieLines || []) {
      const first = (line || "").split(";")[0];
      const eq = first.indexOf("=");
      if (eq <= 0) continue;
      const name = first.slice(0, eq).trim();
      const value = first.slice(eq + 1).trim();
      if (!name) continue;
      const deleted = /;\s*max-age\s*=\s*0\b/i.test(line) || /;\s*expires\s*=\s*thu, 01 jan 1970/i.test(line);
      if (deleted) this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }
  header(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  get size(): number {
    return this.jar.size;
  }
}

// Per-page cap on captured body text — the crawl is already bounded to a
// handful of pages within a short wall-clock budget, so this is just a
// backstop against one unexpectedly huge response ballooning memory.
export const MAX_CAPTURE_CHARS = 300_000;

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  perRequestMs?: number;
  budgetMs?: number;
  concurrency?: number;
  seedHtml?: string; // root HTML already fetched by the scanner (avoids a re-fetch)
  initialCookies?: string[]; // root Set-Cookie lines, to seed the session jar
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
      targets.push({ url, method, params: [...fields], source: "form", discoveredOnPage: baseUrl });
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
  cookieHeader?: string,
): Promise<Response> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetchFn(url, {
      method: "GET",
      signal: ctl.signal,
      // Carry the crawl's accumulated session cookies. fetchFn (authedFetch in
      // the scanner) merges init.headers over its base, so this rides along.
      ...(cookieHeader ? { headers: { Cookie: cookieHeader } } : {}),
    });
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
  const captures: CrawlCapture[] = [];
  // Session-aware crawl: one cookie jar carried across every request, seeded with
  // the root response's cookies (the session cookie most apps set on first
  // contact), so pages that only render in-session are reached. Non-destructive —
  // it only carries cookies on the GET crawl, never issues a state-changing request.
  const jar = new CookieJar();
  jar.ingest(opts.initialCookies || []);
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
          // Send the session accumulated so far. Reads the jar snapshot before
          // the request; a batch runs concurrently, so mid-batch Set-Cookie
          // updates land on the next batch — acceptable for a best-effort crawl,
          // and the seeded root session (set before the loop) is the load-bearing one.
          const res = await fetchWithTimeout(fetchFn, url, perRequestMs, jar.size ? jar.header() : undefined);
          const contentType = res.headers.get("content-type") || "";
          const setCookie: string[] =
            typeof (res.headers as any).getSetCookie === "function" ? (res.headers as any).getSetCookie() : [];
          // Carry any session this page established forward to later requests.
          if (setCookie.length) jar.ingest(setCookie);
          const text = await res.text().catch(() => "");
          // Captured regardless of content type — a JSON/plain-text endpoint
          // (e.g. /api/settings) never becomes an HTML "page" below, but its
          // body is still fair game for secret-signature/cookie-flag analysis.
          captures.push({ url, status: res.status, contentType, text: text.slice(0, MAX_CAPTURE_CHARS), setCookie });
          if (!/text\/html/i.test(contentType)) return;
          ingestHtml(text, url, depth);
        } catch {
          /* unreachable/blocked page — skip */
        }
      }),
    );
  }

  return {
    pagesVisited: pages.length,
    pages,
    targets: dedupeTargets(targets),
    captures,
    sessionCookie: jar.size ? jar.header() : undefined,
  };
}
