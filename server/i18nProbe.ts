// Locale-route auth bypass probe (T4-i18n-Bypass-001-shaped): a protected
// path is gated with auth under one locale prefix (/en/...) but its sibling
// under another locale (/es/...) isn't — a common real bug when an i18n
// route tree is generated/wired per-locale and auth middleware only gets
// attached to one. Read-only (GETs only, no auth header at all — this is
// about a locale swap, not a credential); the receipt is a `differential`
// bundle whose control is the gated locale's 401/403 and whose attack is the
// sibling locale's 200. Requires verified ownership (gated by the caller,
// like the other active probes) since it's new requests beyond what the
// crawler already fetched.
import { safeFetch } from "./ssrf.js";
import { renderRawRequest, windowAround } from "./evidence.js";
import type { ExploitEvidence } from "../src/types.js";

const DENIED = new Set([401, 403]);
const LOCALE_PATH_RE = /^\/(en|es)(\/.*)?$/i;

async function timedGet(url: string, headers: Record<string, string>): Promise<{ res: Response; text: string }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { res, text: await res.text().catch(() => "") };
  } finally {
    clearTimeout(id);
  }
}

// A distinctive line present in the unlocked sibling response but not the
// gated original's (denial) body — stronger proof than a bare status code
// when we can find it (real gated content the locale swap unlocked).
function distinctiveProof(unlocked: string, denied: string): string | null {
  const lines = unlocked.split(/[\n\r<>]+/).map((l) => l.trim()).filter((l) => l.length >= 8 && l.length <= 160);
  for (const l of lines) if (!denied.includes(l)) return l;
  return null;
}

export async function probeI18nAuthBypass(
  baseUrl: string,
  discoveredPaths: string[],
  headers: Record<string, string>,
): Promise<any | null> {
  const base = baseUrl.replace(/\/+$/, "");
  // No auth header at all — this differential is about the locale segment,
  // not a credential; either locale should demand the SAME thing from an
  // anonymous caller.
  const { Authorization, authorization, ...noAuth } = headers;
  void Authorization; void authorization;

  const tried = new Set<string>();
  for (const rawPath of discoveredPaths) {
    let path: string;
    try {
      path = new URL(rawPath, base).pathname;
    } catch {
      continue;
    }
    const m = LOCALE_PATH_RE.exec(path);
    if (!m) continue;
    const locale = m[1].toLowerCase();
    const otherLocale = locale === "en" ? "es" : "en";
    const siblingPath = path.replace(/^\/(en|es)(\/|$)/i, `/${otherLocale}$2`);
    const pairKey = [path, siblingPath].sort().join("|");
    if (tried.has(pairKey)) continue;
    tried.add(pairKey);

    let gated: { res: Response; text: string };
    try {
      gated = await timedGet(`${base}${path}`, noAuth);
    } catch {
      continue;
    }
    if (!DENIED.has(gated.res.status)) continue; // this locale isn't gated at all — no differential to prove here

    let sibling: { res: Response; text: string };
    try {
      sibling = await timedGet(`${base}${siblingPath}`, noAuth);
    } catch {
      continue;
    }
    if (DENIED.has(sibling.res.status) || sibling.res.status >= 400) continue; // sibling correctly gated too — no bug

    const proof = distinctiveProof(sibling.text, gated.text) || `${sibling.res.status} ${sibling.res.statusText}`;
    const attackResponse =
      `HTTP/1.1 ${sibling.res.status} ${sibling.res.statusText}\n\n` +
      windowAround(sibling.text || "(empty body)", Math.max(0, (sibling.text || "").indexOf(proof)), proof.length, 1200);

    const evidence: ExploitEvidence = {
      method: "differential",
      attack: {
        request: renderRawRequest("GET", `${base}${siblingPath}`, noAuth),
        response: attackResponse,
      },
      control: {
        request: renderRawRequest("GET", `${base}${path}`, noAuth),
        response: `HTTP/1.1 ${gated.res.status} ${gated.res.statusText}`,
      },
      signal: {
        quote: proof,
        offsetInResponse: attackResponse.indexOf(proof),
        why: `With no credentials, ${path} (locale "${locale}") returns ${gated.res.status} (auth is enforced), but the identical resource under ${siblingPath} (locale "${otherLocale}") returned ${sibling.res.status} with no auth at all — the same auth check was never applied to that locale's route.`,
      },
      demonstration: `We requested ${path} with no credentials and got ${gated.res.status}. We then requested the SAME resource under the "${otherLocale}" locale prefix (${siblingPath}), also with no credentials, and it returned ${sibling.res.status} — an attacker can reach this protected page just by switching the URL's language segment.`,
      reproduction: `curl -s -i "${base}${siblingPath}"`,
      capturedAt: new Date().toISOString(),
    };

    return {
      testName: `Language Route Auth Bypass (${locale} gated, ${otherLocale} is not)`,
      payload: `${siblingPath} (locale swapped from ${path})`,
      severity: "critical",
      description: `The route ${path} correctly requires authentication (${gated.res.status} with no credentials), but its "${otherLocale}"-locale sibling ${siblingPath} serves the same protected content with no auth check at all. i18n route trees are commonly wired per-locale; auth middleware attached to only one locale's tree leaves every other locale's copy of the same page unprotected.`,
      fix: "Apply authentication/authorization middleware globally across ALL locale prefixes for a given route (e.g. a single matcher like /(en|es)/admin/*), never per-locale-tree individually — or centralize the check in shared middleware that runs before locale-specific routing.",
      evidence,
    };
  }
  return null;
}
