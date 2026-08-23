// Exposed JavaScript source-map probe. A shipped `.js.map` reconstructs the
// ORIGINAL, un-minified source of a bundle — comments, internal structure,
// route/file names, feature flags, and any logic the minified build obscured —
// handing a reverse engineer the real code for free. Vibe-coder builds ship them
// by accident constantly (a Vite/webpack default left on).
//
// False-positive-proof: a source map is a very specific JSON shape
// (`{"version":3,"sources":[...],"mappings":"..."}`), so an SPA that serves
// index.html (HTTP 200) for an unknown `.map` path never matches. Passive and
// same-origin only — it just GETs the target's own asset paths, like the
// sensitive-path probing in server/perimeter.ts.
import { safeFetch } from "./ssrf.js";
import type { Severity } from "../src/types.js";

// True only for a real Source Map v3 document. Cheap regex pre-check guards the
// bounded JSON.parse so a large non-JSON body isn't parsed needlessly.
export function isSourceMap(text: string): boolean {
  if (!text || text.length < 20) return false;
  if (!/"version"\s*:/.test(text) || !/"mappings"\s*:/.test(text) || !/"sources"\s*:/.test(text)) return false;
  try {
    const j = JSON.parse(text) as any;
    return !!j && typeof j === "object" && typeof j.mappings === "string" && Array.isArray(j.sources);
  } catch {
    return false;
  }
}

// Same-origin <script src> bundle URLs referenced by an HTML document.
export function extractScriptSrcs(html: string, baseUrl: string): string[] {
  let base: URL;
  try { base = new URL(baseUrl); } catch { return []; }
  const out = new Set<string>();
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], base);
      if (abs.origin === base.origin && /\.m?js(\?|$)/i.test(abs.pathname)) out.add(abs.origin + abs.pathname);
    } catch { /* skip malformed src */ }
  }
  return [...out];
}

// Same-origin sourceMappingURL(s) declared inside a JS file, resolved against the
// JS file's URL. Inline `data:` maps are skipped — they're already in the bundle,
// not separately exposed.
export function extractSourceMappingUrls(jsText: string, jsUrl: string): string[] {
  const out = new Set<string>();
  let base: URL;
  try { base = new URL(jsUrl); } catch { return []; }
  const re = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(jsText)) !== null) {
    const ref = m[1].trim();
    if (ref.startsWith("data:")) continue;
    try {
      const abs = new URL(ref, base);
      if (abs.origin === base.origin) out.add(abs.origin + abs.pathname);
    } catch { /* skip malformed ref */ }
  }
  return [...out];
}

async function timedGet(url: string, headers: Record<string, string>): Promise<{ status: number; text: string } | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 4000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { status: res.status, text: await res.text().catch(() => "") };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

export interface SourceCapture { url: string; text: string }
export interface ExposedPathEntry {
  path: string;
  status: number;
  exposed: boolean;
  meta: { title: string; severity: Severity; description: string; fix: string };
}

// Given the HTML/JS the scan already fetched, derive candidate `.map` URLs (from
// <script src>.map and from sourceMappingURL comments), probe each, and return a
// probedPaths-shaped entry (with LOW `meta`) for every one that is a real source
// map. Bounded to `max` fetches. Empty when nothing is exposed.
export async function probeExposedSourceMaps(
  captures: SourceCapture[],
  baseUrl: string,
  headers: Record<string, string>,
  max = 6,
): Promise<ExposedPathEntry[]> {
  const candidates = new Set<string>();
  for (const c of captures) {
    let pathname = c.url;
    try { pathname = new URL(c.url).pathname; } catch { /* keep as-is */ }
    if (/\.m?js(\?|$)/i.test(pathname)) {
      // A captured JS bundle: trust its own sourceMappingURL, and also try the
      // conventional <bundle>.js.map sibling.
      for (const u of extractSourceMappingUrls(c.text, c.url)) candidates.add(u);
      try { const p = new URL(c.url); candidates.add(p.origin + p.pathname + ".map"); } catch { /* skip */ }
    } else {
      // An HTML document: derive its script bundles, then their .map siblings.
      for (const src of extractScriptSrcs(c.text, c.url)) candidates.add(src + ".map");
    }
  }

  const ua = headers["User-Agent"] || "Seclayer-Security-Scanner/2.0";
  const out: ExposedPathEntry[] = [];
  for (const mapUrl of [...candidates].slice(0, max)) {
    const r = await timedGet(mapUrl, { "User-Agent": ua });
    if (!r || r.status !== 200 || !isSourceMap(r.text)) continue;
    let path = mapUrl;
    try { path = new URL(mapUrl).pathname; } catch { /* keep full */ }
    out.push({
      path,
      status: 200,
      exposed: true,
      meta: {
        title: `Exposed JavaScript source map (${path})`,
        severity: "low",
        description: `A JavaScript source map (${path}) is publicly served. Source maps reconstruct the ORIGINAL, un-minified source of the bundle — including comments, internal structure, file/route names, and logic the minified bundle obscured — which hands a reverse engineer your real code with no effort.`,
        fix: `Stop shipping .map files to production, or restrict access to them. In Vite set build.sourcemap to false (or 'hidden'); in webpack pick a production devtool that doesn't emit public maps; or block *.map at the CDN / web server.`,
      },
    });
  }
  return out;
}
