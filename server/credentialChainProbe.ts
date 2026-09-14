// Cross-origin credential-chaining probe (T3-AnonKey-Abuse-001-shaped): a
// BaaS client key (e.g. a Supabase anon key) is meant to be public — it
// ships in every client bundle by design — but it directly unlocks any
// table/resource that was never explicitly restricted at the BACKEND. This
// is only provable by taking the key discovered on the SCANNED origin and
// testing it against the SEPARATE origin the same served content told us
// it's for (a `<PREFIX>_URL` sitting next to a `<PREFIX>_..._KEY`) — unlike
// every other probe in this codebase, which only ever calls back to the one
// target URL the scan was pointed at.
//
// Bounded and read-only: at most a few requests, all GETs, no guessing of
// unrelated third-party hosts — the target origin is one the scanned
// application's OWN content named, not a guess. Reuses safeFetch's existing
// SSRF allow/deny logic unchanged, so a malicious/attacker-planted URL in the
// page still can't steer requests at internal infrastructure.
import { safeFetch } from "./ssrf.js";
import { SCANNER_USER_AGENT } from "./config.js";
import { renderRawRequest, windowAround } from "./evidence.js";
import type { ExploitEvidence } from "../src/types.js";

export interface UrlKeyPair {
  prefix: string;
  url: string;
  key: string;
}

// Capture the whole NAME sitting before _URL / _KEY, then normalizeName() strips
// any framework prefix so the pairing core is what's left. This makes
// NEXT_PUBLIC_SUPABASE_URL, VITE_SUPABASE_URL and a bare SUPABASE_URL all pair
// on the same "SUPABASE" core — a real Supabase app almost never writes the bare
// form. The name is captured reluctantly up to a known suffix, so
// VITE_SUPABASE_ANON_KEY yields NAME "VITE_SUPABASE" (→ "SUPABASE"), not "ANON".
// PUBLISHABLE_KEY is Supabase's newer name for the anon key.
const URL_DECL_RE = /\b([A-Z0-9_]+?)_URL\s*[=:]\s*["']?(https?:\/\/[^"'\s,}]+)["']?/g;
const KEY_DECL_RE = /\b([A-Z0-9_]+?)_(?:ANON_KEY|API_KEY|PUBLISHABLE_KEY|KEY)\s*[=:]\s*["']?([A-Za-z0-9_\-.]{20,})["']?/g;

// Build-tool prefixes that expose an env var to the client bundle. Stripped so
// the pairing core is the service name the developer chose, not the framework's.
const FRAMEWORK_PREFIXES = [
  "NEXT_PUBLIC", "VITE", "REACT_APP", "EXPO_PUBLIC", "GATSBY",
  "NUXT_PUBLIC", "VUE_APP", "PUBLIC", "NG",
];

// Strip a leading framework prefix so VITE_SUPABASE -> SUPABASE, leaving the
// developer-chosen service name (which may itself be multi-segment) to pair on.
function normalizeName(name: string): string {
  for (const p of FRAMEWORK_PREFIXES) {
    if (name.startsWith(p + "_") && name.length > p.length + 1) return name.slice(p.length + 1);
  }
  return name;
}

// The Supabase/PostgREST/GoTrue SDK's positional init — createClient(url, key)
// — pairs a URL and a key with NO shared variable name at all, so the
// name-prefix passes above never see it. Their being the first two arguments of
// the SAME createClient call is itself the pairing signal (stronger, if
// anything, than a shared prefix), so it carries the same false-positive bar.
const CREATE_CLIENT_RE =
  /createClient\s*(?:<[^>]*>)?\s*\(\s*["'](https?:\/\/[^"']+)["']\s*,\s*["']([A-Za-z0-9_\-.]{20,})["']/g;

// Name a synthetic prefix for a pair discovered positionally (no variable name
// to borrow). A *.supabase.co host is unmistakable and worth surfacing by name;
// anything else is a generic BaaS.
function prefixForUrl(url: string): string {
  try {
    return /(^|\.)supabase\.co$/i.test(new URL(url).hostname) ? "SUPABASE" : "BAAS";
  } catch {
    return "BAAS";
  }
}

// Pulls (URL, key) pairs out of served content by three means, in order:
//   1. Same-token env-var declarations — `SUPABASE_URL` next to
//      `SUPABASE_ANON_KEY`, or their `VITE_`/`NEXT_PUBLIC_`-prefixed forms.
//   2. The positional `createClient(url, key)` SDK call.
// The shared token (1) or shared call site (2) is what proves the two belong
// together, rather than pairing an arbitrary URL with an arbitrary key found
// anywhere on the page. Deduped by (url,key) and bounded to 3 pairs.
export function extractUrlKeyPairs(bodyText: string): UrlKeyPair[] {
  if (!bodyText) return [];
  const seen = new Set<string>();
  const out: UrlKeyPair[] = [];
  const push = (prefix: string, rawUrl: string, key: string) => {
    const url = rawUrl.replace(/\/+$/, "");
    const dedupeKey = `${url}|${key}`;
    if (seen.has(dedupeKey)) return;
    seen.add(dedupeKey);
    out.push({ prefix, url, key });
  };

  // 1. Same-core env-var pairs (framework prefix stripped before pairing).
  const urls = new Map<string, string>();
  let m: RegExpExecArray | null;
  URL_DECL_RE.lastIndex = 0;
  while ((m = URL_DECL_RE.exec(bodyText)) !== null) {
    const core = normalizeName(m[1]);
    if (!urls.has(core)) urls.set(core, m[2]);
  }
  KEY_DECL_RE.lastIndex = 0;
  while ((m = KEY_DECL_RE.exec(bodyText)) !== null && out.length < 3) {
    const core = normalizeName(m[1]);
    const url = urls.get(core);
    if (url) push(core, url, m[2]);
  }

  // 2. Positional createClient(url, key).
  CREATE_CLIENT_RE.lastIndex = 0;
  while ((m = CREATE_CLIENT_RE.exec(bodyText)) !== null && out.length < 3) {
    push(prefixForUrl(m[1]), m[1], m[2]);
  }

  return out.slice(0, 3);
}

async function timedGet(url: string, headers: Record<string, string>): Promise<{ res: Response; text: string } | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { res, text: await res.text().catch(() => "") };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

// A small, targeted guess list for the second step (table names), used only
// when the PostgREST root doesn't hand back an enumerable schema — same
// "targeted guess list, not a directory brute-force" discipline as
// EXPOSED_USER_OBJECT_PATHS in apiProbes.ts.
const COMMON_TABLE_GUESSES = ["config", "admin_config", "settings", "app_config", "users", "profiles"];

export async function probeCredentialUrlPairs(pairs: UrlKeyPair[]): Promise<any | null> {
  for (const pair of pairs) {
    const headers = { apikey: pair.key, Authorization: `Bearer ${pair.key}`, "User-Agent": SCANNER_USER_AGENT };

    // Step 1: PostgREST's own root lists every table exposed to this key's
    // role when schema introspection is on (the common case) — real
    // discovery, not a guess, when it works.
    const root = await timedGet(`${pair.url}/rest/v1/`, headers);
    const tableNames: string[] = [];
    if (root && root.res.status === 200) {
      try {
        const spec = JSON.parse(root.text);
        for (const path of Object.keys(spec?.paths || {})) {
          const name = path.replace(/^\//, "");
          if (name && !name.includes("/") && !name.includes("rpc")) tableNames.push(name);
        }
      } catch {
        /* not an OpenAPI doc — fall through to guesses */
      }
    }
    const candidates = tableNames.length ? tableNames.slice(0, 5) : COMMON_TABLE_GUESSES;

    for (const table of candidates) {
      const tableUrl = `${pair.url}/rest/v1/${table}?select=*&limit=5`;
      const attack = await timedGet(tableUrl, headers);
      if (!attack || attack.res.status !== 200) continue;
      let rows: unknown;
      try {
        rows = JSON.parse(attack.text);
      } catch {
        continue;
      }
      if (!Array.isArray(rows) || rows.length === 0) continue; // 200 + empty isn't proof of anything readable

      const proof = attack.text.slice(0, 300);
      const attackResponse = `HTTP/1.1 ${attack.res.status} ${attack.res.statusText}\n\n` + windowAround(attack.text, 0, proof.length, 1200);

      const evidence: ExploitEvidence = {
        method: "oracle",
        attack: {
          request: renderRawRequest("GET", tableUrl, { apikey: `${pair.key.slice(0, 12)}…` }),
          response: attackResponse,
        },
        signal: {
          quote: proof,
          offsetInResponse: attackResponse.indexOf(proof),
          why: `The client-side key found in this page's own JavaScript (window.${pair.prefix}_...) was accepted directly by ${pair.url}, a SEPARATE origin, and returned ${rows.length} real row(s) from table "${table}" with no application-level authorization at all.`,
        },
        demonstration: `We extracted the "${pair.prefix}_URL" and "${pair.prefix}_..._KEY" pair from this page's own client-side JavaScript, then called ${pair.url}'s REST API directly with that key — bypassing this application's own backend entirely — and it returned real data from "${table}".`,
        reproduction: `curl -s "${tableUrl}" -H "apikey: ${pair.key}"`,
        capturedAt: new Date().toISOString(),
      };

      return {
        testName: `Client-Side Key Grants Unrestricted Backend Access (${pair.prefix})`,
        payload: `${pair.url}/rest/v1/${table} with the client-exposed ${pair.prefix} key`,
        severity: "critical",
        description: `A client-side API key (window.${pair.prefix}_...) — intentionally public by design, since it ships in every client bundle — directly reads table "${table}" at ${pair.url} with no additional authorization. The backing service (e.g. a BaaS/RLS-style table) was never restricted to actually require an authenticated, authorized caller; the public key alone is sufficient.`,
        fix: "Restrict this table/resource so the public/anon client key alone is never sufficient to read it — require row-level security scoped to an authenticated caller's own identity, or move this data behind an authenticated backend endpoint that doesn't expose the client key's full access.",
        evidence,
      };
    }
  }
  return null;
}
