// Passive black-box recon of the root document: fetch it once, analyze security
// headers, leaked tech signatures, and per-cookie flags, then run static
// secret/library analysis over the served markup and map the DNS/subdomain
// perimeter plus sensitive paths. Always runs (no ownership gate). Mutates the
// passed DiagnosticResult in place and returns the root HTML so the caller can
// seed the crawler with it. A failure reaching the target throws, so the scan is
// surfaced as failed rather than a misleading "clean" report.
import type { DiagnosticResult } from "./scanner.js";
import type { EmitFn } from "./scanEvents.js";
import { safeFetch } from "./ssrf.js";
import { analyzeSecrets, analyzeLibraries } from "./staticAnalysis.js";
import { scanPerimeter } from "./perimeter.js";

export const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
];

// Global cap across the WHOLE scan (root + every crawled page), not per-page —
// callers pass their running count via `alreadyFound` so the cap holds even
// when this is invoked multiple times.
export const MAX_COOKIE_ISSUES = 6;

// Evaluates EACH Set-Cookie individually. A prior version concatenated every
// cookie into one string and substring-tested it, so a flag present on *any*
// cookie masked its absence on *another* (both a false negative — missing a
// genuinely insecure cookie — and a misleading blanket finding).
//
// Only the two security-critical flags — Secure (over HTTPS) and HttpOnly —
// are flagged, naming the specific cookie. Missing SameSite is deliberately
// NOT flagged: modern browsers default absent cookies to SameSite=Lax, so
// reporting it produces low-signal, false-positive-flavored noise.
export function cookieFlagIssues(setCookieList: string[], isHttps: boolean, alreadyFound: number): string[] {
  const issues: string[] = [];
  const budget = () => alreadyFound + issues.length < MAX_COOKIE_ISSUES;
  for (const cookie of setCookieList) {
    if (!budget()) break;
    const nameMatch = cookie.match(/^\s*([^=;\s]+)=/);
    const name = nameMatch ? nameMatch[1] : "cookie";
    // A cookie explicitly scoped to be read by client JS can't carry
    // HttpOnly by design, so only the Secure gap is a clear issue there.
    if (isHttps && !/;\s*secure(\s*;|\s*$)/i.test(cookie)) {
      issues.push(`Cookie "${name}" is set without the Secure attribute over HTTPS`);
    }
    if (!budget()) break;
    if (!/;\s*httponly(\s*;|\s*$)/i.test(cookie)) {
      issues.push(`Cookie "${name}" is set without the HttpOnly attribute`);
    }
  }
  return issues;
}

// The initial root fetch gates the WHOLE scan: if it fails we abort with "did
// not respond" rather than emit a misleading clean report. But many real targets
// sleep when idle (Replit, Render, Fly and other free-tier PaaS) and cold-start
// on the first request, taking far longer than a few seconds to answer. So we
// try a normal window first and, ONLY on a timeout, retry once with a much
// longer warmup window — the first hit wakes the container, the retry reaches it
// once it's up. A warm target still answers on the first attempt with no penalty
// (the timeout is a ceiling, not a fixed wait).
const ROOT_FETCH_TIMEOUT_MS = 12000; // first attempt
const ROOT_FETCH_WARMUP_TIMEOUT_MS = 30000; // cold-start retry

async function fetchRoot(url: string, headers: Record<string, string>): Promise<Response> {
  const attempt = async (timeoutMs: number): Promise<Response> => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await safeFetch(url, { method: "GET", headers, signal: controller.signal });
    } finally {
      clearTimeout(id);
    }
  };
  try {
    return await attempt(ROOT_FETCH_TIMEOUT_MS);
  } catch (err: any) {
    // Cold start: the first request likely woke a sleeping host — retry once
    // with a longer window before giving up on the target entirely.
    if (err?.name === "AbortError") return await attempt(ROOT_FETCH_WARMUP_TIMEOUT_MS);
    throw err;
  }
}

export async function runPassiveScan(
  url: string,
  host: string,
  hostname: string,
  headers: Record<string, string>,
  result: DiagnosticResult,
  emit?: EmitFn,
): Promise<string> {
  let rootHtml = "";
  try {
    // 1. Core Header Analysis — cold-start-aware so a sleeping target that wakes
    // slowly (Replit/Render/Fly free tiers) still gets scanned instead of failing
    // the whole run on the first slow request.
    const response = await fetchRoot(url, headers);

    result.responseStatus = response.status;
    emit?.("recon", `Reachable — HTTP ${result.responseStatus} over ${result.sslSecure ? "HTTPS/TLS" : "plaintext HTTP (no TLS)"}.`);

    // Copy headers (lowercased)
    response.headers.forEach((value, key) => {
      result.headers[key.toLowerCase()] = value;
    });

    const htmlText = await response.text().catch(() => "");
    rootHtml = htmlText;

    // Missing security headers.
    for (const header of SECURITY_HEADERS) {
      if (!result.headers[header]) result.missingHeaders.push(header);
    }
    emit?.("recon", result.missingHeaders.length
      ? `${result.missingHeaders.length} security header(s) missing: ${result.missingHeaders.join(", ")}.`
      : "All tracked security headers present.");

    // Technology leaks checking (X-Powered-By, Server, etc.)
    const serverHeader = result.headers["server"];
    if (serverHeader && !/cloudflare/i.test(serverHeader)) {
      result.techLeaked.push(`Server: ${serverHeader}`);
    }
    const poweredBy = result.headers["x-powered-by"];
    if (poweredBy) {
      result.techLeaked.push(`X-Powered-By: ${poweredBy}`);
    }
    if (result.techLeaked.length) emit?.("recon", `Tech/server signatures disclosed: ${result.techLeaked.join(", ")}.`);

    // Cookie flag analysis — evaluate EACH Set-Cookie individually (see
    // cookieFlagIssues below), across the root response. Same function also
    // runs against every page the crawler visits (scanner.ts), so a cookie
    // set anywhere in the app — not only on the root response — gets caught.
    const setCookieList: string[] =
      typeof (response.headers as any).getSetCookie === "function"
        ? (response.headers as any).getSetCookie()
        : (result.headers["set-cookie"] ? [result.headers["set-cookie"]] : []);
    const isHttps = url.startsWith("https://");
    result.cookieIssues.push(...cookieFlagIssues(setCookieList, isHttps, result.cookieIssues.length));

    // 2. SAST secrets + 3. SCA libraries (over the served markup).
    // (DAST CSRF inference from static markup is intentionally omitted — it is
    // unreliable black-box and would violate the zero-false-positive goal.)
    result.sastFindings = analyzeSecrets(htmlText);
    result.scaLibraries = analyzeLibraries(htmlText);

    // 4. EASM perimeter (DNS, subdomains) + sensitive-path probing.
    await scanPerimeter(host, hostname, result);
    const liveSubs = result.easmPerimeter.subdomains.filter((s) => s.status === "live").map((s) => s.domain);
    emit?.("recon", `Perimeter: resolved ${result.easmPerimeter.ip || "n/a"}; ${liveSubs.length} live subdomain(s)${liveSubs.length ? ` — ${liveSubs.slice(0, 5).join(", ")}` : ""}.`);
    const exposedPaths = result.probedPaths.filter((p) => p.exposed).map((p) => p.path);
    emit?.("recon", exposedPaths.length
      ? `Exposed sensitive path(s): ${exposedPaths.join(", ")}.`
      : `Sensitive-path probe: ${result.probedPaths.length} checked, none exposed.`);
  } catch (err: any) {
    // A failure reaching the target means we cannot assess it. Surface this as
    // a failed scan rather than a misleading "clean" (no-findings) report.
    if (err?.name === "AbortError") {
      throw new Error(`Target ${url} did not respond within the timeout window.`);
    }
    throw new Error(`Unable to connect to ${url}: ${err?.message || "connection failed"}`);
  }
  return rootHtml;
}
