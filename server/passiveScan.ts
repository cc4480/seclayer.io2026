// Passive black-box recon of the root document: fetch it once, analyze security
// headers, leaked tech signatures, and per-cookie flags, then run static
// secret/library analysis over the served markup and map the DNS/subdomain
// perimeter plus sensitive paths. Always runs (no ownership gate). Mutates the
// passed DiagnosticResult in place and returns the root HTML so the caller can
// seed the crawler with it. A failure reaching the target throws, so the scan is
// surfaced as failed rather than a misleading "clean" report.
import type { DiagnosticResult } from "./scanner.js";
import { safeFetch } from "./ssrf.js";
import { analyzeSecrets, analyzeLibraries } from "./staticAnalysis.js";
import { scanPerimeter } from "./perimeter.js";

const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
];

export async function runPassiveScan(
  url: string,
  host: string,
  hostname: string,
  headers: Record<string, string>,
  result: DiagnosticResult,
): Promise<string> {
  let rootHtml = "";
  try {
    // 1. Core Header Analysis
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 6000); // 6s timeout max

    const response = await safeFetch(url, {
      method: "GET",
      headers,
      signal: controller.signal,
    });
    clearTimeout(id);

    result.responseStatus = response.status;

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

    // Technology leaks checking (X-Powered-By, Server, etc.)
    const serverHeader = result.headers["server"];
    if (serverHeader && !/cloudflare/i.test(serverHeader)) {
      result.techLeaked.push(`Server: ${serverHeader}`);
    }
    const poweredBy = result.headers["x-powered-by"];
    if (poweredBy) {
      result.techLeaked.push(`X-Powered-By: ${poweredBy}`);
    }

    // Cookie flag analysis — evaluate EACH Set-Cookie individually. A prior
    // version concatenated every cookie into one string and substring-tested
    // it, so a flag present on *any* cookie masked its absence on *another*
    // (both a false negative — missing a genuinely insecure cookie — and a
    // misleading blanket finding). We now read the real per-cookie list.
    //
    // We only flag the two security-critical flags — Secure (over HTTPS) and
    // HttpOnly — naming the specific cookie. Missing SameSite is deliberately
    // NOT flagged: modern browsers default absent cookies to SameSite=Lax, so
    // reporting it produces low-signal, false-positive-flavored noise.
    const setCookieList: string[] =
      typeof (response.headers as any).getSetCookie === "function"
        ? (response.headers as any).getSetCookie()
        : (result.headers["set-cookie"] ? [result.headers["set-cookie"]] : []);
    const isHttps = url.startsWith("https://");
    const MAX_COOKIE_ISSUES = 6;
    for (const cookie of setCookieList) {
      if (result.cookieIssues.length >= MAX_COOKIE_ISSUES) break;
      const nameMatch = cookie.match(/^\s*([^=;\s]+)=/);
      const name = nameMatch ? nameMatch[1] : "cookie";
      // A cookie explicitly scoped to be read by client JS can't carry
      // HttpOnly by design, so only the Secure gap is a clear issue there.
      if (isHttps && !/;\s*secure(\s*;|\s*$)/i.test(cookie)) {
        result.cookieIssues.push(`Cookie "${name}" is set without the Secure attribute over HTTPS`);
      }
      if (result.cookieIssues.length >= MAX_COOKIE_ISSUES) break;
      if (!/;\s*httponly(\s*;|\s*$)/i.test(cookie)) {
        result.cookieIssues.push(`Cookie "${name}" is set without the HttpOnly attribute`);
      }
    }

    // 2. SAST secrets + 3. SCA libraries (over the served markup).
    // (DAST CSRF inference from static markup is intentionally omitted — it is
    // unreliable black-box and would violate the zero-false-positive goal.)
    result.sastFindings = analyzeSecrets(htmlText);
    result.scaLibraries = analyzeLibraries(htmlText);

    // 4. EASM perimeter (DNS, subdomains) + sensitive-path probing.
    await scanPerimeter(host, hostname, result);
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
