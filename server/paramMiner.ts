// Parameter MINING — reflection-based discovery of processed query parameters.
//
// When the crawler finds few or no parameters (typical of a SPA or JSON API that
// renders nothing injectable into its static HTML), we still want the injection
// probes to have a surface to test. This module guesses common parameter names
// (server/paramWordlist.ts) and keeps the ones the target actually processes,
// detected by reflection: each candidate is sent a unique, unguessable marker and
// we keep any whose marker comes back in the response body. Candidates are batched
// (many params per request, each with its own marker) so mining a ~60-name list
// costs only a handful of requests.
//
// Reflection catches the parameters most relevant to XSS and, in practice, most
// error-based SQLi (apps commonly echo the looked-up id back). Non-reflecting
// blind sinks are covered by always-testing a small high-signal set
// (ALWAYS_TEST_PARAMS) regardless of reflection, and by the time-based blind SQLi
// probe in the fuzzer.
import crypto from "crypto";
import { safeFetch } from "./ssrf.js";
import type { InjectableTarget } from "./crawler.js";
import { COMMON_PARAMS, ALWAYS_TEST_PARAMS } from "./paramWordlist.js";

const MINE_TIMEOUT_MS = 5000;
const BATCH_SIZE = 20;      // params per mining request
const MAX_BATCHES = 4;      // hard cap on requests per base URL
const MAX_BASE_URLS = 4;    // hard cap on distinct paths we mine

// origin+pathname with the query and fragment stripped, so mined params attach to
// a clean base and two links to the same path collapse to one base.
function basePath(u: string): string | null {
  try {
    const parsed = new URL(u);
    return parsed.origin + parsed.pathname;
  } catch {
    return null;
  }
}

async function fetchText(url: string, headers: Record<string, string>): Promise<string | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), MINE_TIMEOUT_MS);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

// Returns the subset of `candidates` whose value the target reflects back at
// `baseUrl`. Batched: each request carries up to BATCH_SIZE params, each set to a
// distinct marker, and we attribute every reflected marker back to its parameter.
export async function mineReflectedParams(
  baseUrl: string,
  headers: Record<string, string>,
  candidates: string[] = COMMON_PARAMS,
): Promise<string[]> {
  const base = basePath(baseUrl);
  if (!base) return [];
  const uniq = [...new Set(candidates)];
  const live = new Set<string>();

  for (let b = 0; b < MAX_BATCHES && b * BATCH_SIZE < uniq.length; b++) {
    const batch = uniq.slice(b * BATCH_SIZE, (b + 1) * BATCH_SIZE);
    // A distinct, unguessable marker per parameter so a reflected value maps
    // unambiguously back to the one parameter that produced it.
    const markers = new Map<string, string>();
    let url: URL;
    try {
      url = new URL(base);
    } catch {
      return [...live];
    }
    for (const p of batch) {
      const marker = `slm${crypto.randomBytes(5).toString("hex")}`;
      markers.set(p, marker);
      url.searchParams.set(p, marker);
    }
    const body = await fetchText(url.toString(), headers);
    if (body === null) continue;
    for (const [param, marker] of markers) {
      if (body.includes(marker)) live.add(param);
    }
  }
  return [...live];
}

// Orchestrates mining across the root plus a few parameter-less crawled pages and
// returns ready-to-fuzz GET targets. Each target carries the parameters that
// reflected on that path UNION the always-test high-signal names, so injection
// probing reaches a surface even on an app that linked/formed nothing.
export async function buildGuessedTargets(
  baseUrls: string[],
  headers: Record<string, string>,
): Promise<InjectableTarget[]> {
  // Dedupe to distinct paths, keep the first few.
  const seen = new Set<string>();
  const bases: string[] = [];
  for (const u of baseUrls) {
    const bp = basePath(u);
    if (!bp || seen.has(bp)) continue;
    seen.add(bp);
    bases.push(bp);
    if (bases.length >= MAX_BASE_URLS) break;
  }

  const targets: InjectableTarget[] = [];
  for (const base of bases) {
    const reflected = await mineReflectedParams(base, headers, COMMON_PARAMS);
    const params = [...new Set([...ALWAYS_TEST_PARAMS, ...reflected])];
    if (params.length) targets.push({ url: base, method: "GET", params, source: "query" });
  }
  return targets;
}
