import { Finding, Severity, ScanEvidence } from "../src/types.js";
import { scoreFindings } from "./scoring.js";
import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf, InjectableTarget } from "./crawler.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { mapOwasp } from "./owasp.js";
import { buildAgentPrompt, buildImpactFallback } from "./agentPrompt.js";
import { renderPage, isRenderingEnabled } from "./render.js";
import crypto from "crypto";
import net from "net";
import * as dns from "dns/promises";

// --- SSRF protection ---------------------------------------------------------
// The scanner issues server-side HTTP requests to user-supplied targets, so it
// must refuse internal/reserved destinations (loopback, RFC1918, link-local,
// cloud metadata, CGNAT, etc.) to avoid being abused as an SSRF proxy.
export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0) return true; // "this" network
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower === "::") return true; // loopback / unspecified
    if (lower.startsWith("fe80")) return true; // link-local
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/); // IPv4-mapped
    if (mapped) return isBlockedIp(mapped[1]);
    return false;
  }
  return true; // unrecognized format -> block
}

async function assertTargetIsScannable(parsedUrl: URL): Promise<void> {
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(
      `Unsupported protocol "${parsedUrl.protocol}". Only http(s) targets can be scanned.`,
    );
  }

  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  const lower = hostname.toLowerCase();

  // Block internal-only hostnames that may resolve via split-horizon DNS.
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".local") ||
    lower.endsWith(".internal")
  ) {
    throw new Error(`Refusing to scan internal hostname "${hostname}".`);
  }

  // Literal IP targets are validated directly.
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new Error(
        `Refusing to scan internal or reserved address "${hostname}".`,
      );
    }
    return;
  }

  // Otherwise resolve and validate every address the host maps to.
  const [v4, v6] = await Promise.all([
    dns.resolve4(hostname).catch(() => [] as string[]),
    dns.resolve6(hostname).catch(() => [] as string[]),
  ]);
  for (const ip of [...v4, ...v6]) {
    if (isBlockedIp(ip)) {
      throw new Error(
        `Target "${hostname}" resolves to a blocked internal address (${ip}); scan refused.`,
      );
    }
  }
}

// Public boundary check: validates a raw target string the same way
// runDiagnostics normalizes it, so callers can reject SSRF/malformed targets
// before spending credits or enqueuing work. Throws with a user-facing message.
export async function assertScanTargetSafe(targetUrl: string): Promise<void> {
  let url = (targetUrl || "").trim();
  if (!/^https?:\/\//i.test(url)) {
    // Reject explicit non-HTTP schemes (e.g. ftp://, file://, gopher://)
    // rather than silently coercing them into a bogus https host.
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
      throw new Error(
        `Unsupported protocol in "${targetUrl}". Only http(s) targets can be scanned.`,
      );
    }
    url = "https://" + url;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`"${targetUrl}" is not a valid URL.`);
  }
  await assertTargetIsScannable(parsed);
}

// Follows redirects manually, re-validating every hop against the SSRF guard so
// a target cannot 30x-redirect the scanner into internal infrastructure.
async function safeFetch(targetUrl: string, options: RequestInit, maxRedirects = 4): Promise<Response> {
  let current = targetUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertTargetIsScannable(new URL(current));
    const res = await fetch(current, { ...options, redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (loc) {
        current = new URL(loc, current).toString();
        continue;
      }
    }
    return res;
  }
  throw new Error(`Exceeded ${maxRedirects} redirects while scanning ${targetUrl}`);
}

// Heuristic: does this body look like an HTML document (e.g. a single-page-app
// catch-all that returns index.html for every path)? Used to suppress false
// positives where a 200 response is just the SPA shell, not a real exposed file.
export function looksLikeHtml(body: string): boolean {
  const head = body.slice(0, 512).toLowerCase();
  return /<!doctype html|<html|<head|<body|<title|<div|<script|<meta/.test(head);
}

// Parses a user-supplied credential into request headers for authenticated
// scans. Accepts either a bare Authorization value ("Bearer …", "Basic …") or
// an explicit "Header-Name: value" (e.g. "Cookie: session=…", "X-API-Key: …"),
// enabling token, basic, cookie, or custom-header authentication.
export function parseAuthHeader(authHeader?: string): Record<string, string> {
  const raw = (authHeader || "").trim();
  if (!raw) return {};
  const idx = raw.indexOf(":");
  if (idx > 0) {
    const name = raw.slice(0, idx).trim();
    const value = raw.slice(idx + 1).trim();
    if (name && value && /^[A-Za-z0-9-]+$/.test(name) && !/^(bearer|basic|negotiate|digest)$/i.test(name)) {
      return { [name]: value };
    }
  }
  return { Authorization: raw };
}

export interface DiagnosticResult {
  url: string;
  scannedAt: string;
  responseStatus: number;
  sslSecure: boolean;
  headers: Record<string, string>;
  missingHeaders: string[];
  techLeaked: string[];
  probedPaths: Array<{ path: string; status: number; exposed: boolean }>;
  cookieIssues: string[];

  // High-fidelity AppSec dimensions
  sastFindings: Array<{
    file: string;
    issue: string;
    severity: Severity;
    confidence: "low" | "medium" | "high";
    type: string;
    fix: string;
    description: string;
  }>;
  scaLibraries: Array<{
    name: string;
    version: string;
    status: "vuln" | "safe";
    advisories: string[];
    severity: Severity;
    description: string;
    fix: string;
  }>;
  easmPerimeter: {
    subdomains: Array<{
      domain: string;
      status: "live" | "inactive";
      port: string;
    }>;
    ip: string;
    nameserver: string;
    protocol: string;
  };
  dastInputs: Array<{
    formAction: string;
    method: string;
    csrfPresent: boolean;
    vulnerability: string;
    severity: Severity;
    description: string;
    fix: string;
  }>;
  redTeamFindings?: Array<{
    testName: string;
    payload: string;
    severity: Severity;
    description: string;
    fix: string;
  }>;
  crawl?: {
    pagesVisited: number;
    endpointsDiscovered: number;
    paramsTested: number;
    sampleEndpoints: string[];
  };
  templateFindings?: Finding[];
  apiSecFindings?: Array<{
    testName: string;
    severity: Severity;
    description: string;
    fix: string;
    endpoint: string;
    rawRequest: string;
    rawResponse: string;
  }>;
  // True when active exploit probing (SQLi/XSS/cmd-injection/SSRF/GraphQL/BOLA
  // fuzzing) was skipped because the target's domain ownership isn't verified.
  activeProbesSkipped?: boolean;
}

export interface ScanOptions {
  // Unlocks active exploit-attempt probing (red-team fuzzing, discovered-
  // parameter fuzzing, GraphQL/BOLA probes). Defaults to false so a target
  // only receives passive black-box recon until its owner verifies it — this
  // keeps the scanner from being usable as an anonymous attack proxy against
  // arbitrary third-party sites. See server/domainVerify.ts.
  allowActiveProbes?: boolean;
}

export async function runDiagnostics(
  targetUrl: string,
  authHeader?: string,
  opts: ScanOptions = {},
): Promise<DiagnosticResult> {
  const allowActiveProbes = !!opts.allowActiveProbes;
  let url = targetUrl.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }

  const parsedUrl = new URL(url);
  const host = parsedUrl.origin;
  const hostname = parsedUrl.hostname;

  // SSRF guard: refuse internal/reserved targets before issuing any request.
  await assertTargetIsScannable(parsedUrl);

  const result: DiagnosticResult = {
    url,
    scannedAt: new Date().toISOString(),
    responseStatus: 0,
    sslSecure: url.startsWith("https://"),
    headers: {},
    missingHeaders: [],
    techLeaked: [],
    probedPaths: [],
    cookieIssues: [],
    sastFindings: [],
    scaLibraries: [],
    easmPerimeter: {
      subdomains: [],
      ip: "", // resolved from real DNS below
      nameserver: "", // resolved from real DNS below
      protocol: url.startsWith("https://") ? "HTTPS" : "HTTP",
    },
    dastInputs: [],
    redTeamFindings: [],
    activeProbesSkipped: !allowActiveProbes,
  };

  const headers: Record<string, string> = {
    "User-Agent":
      "Seclayer-Security-Scanner/2.0 (seclayer.io; scanner@seclayer.io)",
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  };
  // Authenticated scanning: the user-supplied credential is applied to EVERY
  // request path (root fetch, probes, crawl, and templates) so auth-gated
  // surface is actually reached.
  const authHeaders = parseAuthHeader(authHeader);
  Object.assign(headers, authHeaders);

  // Wrapper that injects the auth + scanner identity into crawler/template
  // requests, which otherwise only carry their own minimal headers.
  const authedFetch = (u: string, init: RequestInit) =>
    safeFetch(u, {
      ...init,
      headers: {
        "User-Agent": headers["User-Agent"],
        ...authHeaders,
        ...((init.headers as Record<string, string>) || {}),
      },
    });

  let rootHtml = ""; // root document HTML, reused to seed the crawler

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

    // Analyze Security Headers
    const securityHeaders = {
      "content-security-policy":
        "Content-Security-Policy (CSP) regulates resources the browser is allowed to load.",
      "strict-transport-security":
        "Strict-Transport-Security (HSTS) enforces HTTPS connections.",
      "x-frame-options":
        "X-Frame-Options prevents clickjacking framing attacks.",
      "x-content-type-options":
        "X-Content-Type-Options prevents sniffing-based payload executions.",
      "referrer-policy":
        "Referrer-Policy restricts referrer information sent to other sites.",
    };

    for (const [header, desc] of Object.entries(securityHeaders)) {
      if (!result.headers[header]) {
        result.missingHeaders.push(header);
      }
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

    // --- 2. SAST SCAN ENGINE (high-precision secret signatures only) ---
    // Only patterns that are essentially never legitimately client-side are
    // reported with high confidence. Identifiers that are frequently public by
    // design (e.g. Firebase/Maps browser keys) are reported low/medium so they
    // do not become false positives.
    if (htmlText) {
      const patterns = [
        {
          name: "Stripe Secret Key",
          regex: /sk_live_[0-9a-zA-Z]{24,}/,
          severity: "critical" as Severity,
          confidence: "high" as const,
          note: "A Stripe live secret key grants full API access and must never appear client-side.",
        },
        {
          name: "GitHub OAuth Access Token",
          regex: /gho_[a-zA-Z0-9]{36}/,
          severity: "critical" as Severity,
          confidence: "high" as const,
          note: "A GitHub OAuth token grants repository access and must never be shipped to browsers.",
        },
        {
          name: "Private Key Block",
          regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
          severity: "critical" as Severity,
          confidence: "high" as const,
          note: "A PEM private key block was served to the client; the corresponding key must be rotated.",
        },
        {
          name: "AWS Access Key ID",
          regex: /AKIA[0-9A-Z]{16}/,
          severity: "high" as Severity,
          confidence: "medium" as const,
          note: "An AWS access key id is exposed. Confirm the matching secret is not also leaked and rotate it.",
        },
        {
          name: "Google API Key",
          regex: /AIzaSy[A-Za-z0-9_\-]{33}/,
          severity: "low" as Severity,
          confidence: "low" as const,
          note: "Google browser API keys are often intentionally public; verify it is restricted by HTTP referrer/API and not a server key.",
        },
      ];

      patterns.forEach((p) => {
        if (p.regex.test(htmlText)) {
          result.sastFindings.push({
            file: "Client-served HTML/JavaScript",
            issue: `Exposed Credential Signature (${p.name})`,
            severity: p.severity,
            confidence: p.confidence,
            type: "hardcoded_secrets",
            description: `A string matching the ${p.name} format was detected in the client-served response. ${p.note}`,
            fix: `Remove the credential from client code, rotate it immediately, and proxy any required third-party calls through an authenticated backend that holds the secret server-side.`,
          });
        }
      });
    }

    // --- 3. SCA ANALYSIS ENGINE (vulnerable library footprints in markup) ---
    // A library is only flagged when its version regex actually matches a known
    // vulnerable range in the served markup. The reported version is the one
    // captured from the page, and advisories are attributed per-library.
    if (htmlText) {
      const libraries = [
        {
          name: "jQuery",
          match: /jquery[-.](1\.\d+\.\d+|2\.\d+\.\d+)/i,
          severity: "medium" as Severity,
          advisories: ["CVE-2020-11022", "CVE-2020-11023"],
          desc: "jQuery before 3.5.0 is affected by cross-site scripting via htmlPrefilter when passing untrusted HTML to DOM-manipulation methods.",
          fix: "Upgrade jQuery to >= 3.5.0.",
        },
        {
          name: "Bootstrap",
          match: /bootstrap[-./](3\.\d+\.\d+)/i,
          severity: "medium" as Severity,
          advisories: ["CVE-2019-8331"],
          desc: "Bootstrap 3.x is affected by XSS in data-template/tooltip/popover handling and no longer receives security fixes.",
          fix: "Upgrade Bootstrap to >= 4.3.1 (ideally 5.x).",
        },
        {
          name: "AngularJS",
          match: /angular[-.](1\.[0-8]\.\d+)/i,
          severity: "low" as Severity,
          advisories: ["EOL"],
          desc: "AngularJS (1.x) is past end-of-life and receives no further security patches.",
          fix: "Migrate off AngularJS to a maintained framework.",
        },
        {
          name: "Lodash",
          match: /lodash[@/-](4\.(?:[0-9]|1[0-6])\.\d+)\b/i,
          severity: "high" as Severity,
          advisories: ["CVE-2019-10744"],
          desc: "lodash before 4.17.12 is vulnerable to prototype pollution via defaultsDeep.",
          fix: "Upgrade lodash to >= 4.17.21.",
        },
      ];

      libraries.forEach((lib) => {
        const m = lib.match.exec(htmlText);
        if (m) {
          result.scaLibraries.push({
            name: lib.name,
            version: m[1],
            status: "vuln",
            advisories: lib.advisories,
            severity: lib.severity,
            description: lib.desc,
            fix: lib.fix,
          });
        }
      });
    }

    // --- 4. DAST INSECURE INPUTS ---
    // Black-box CSRF detection from static markup is unreliable: token-less
    // forms are routinely protected by framework SameSite cookies or header
    // tokens that are invisible to an unauthenticated crawl. To honour the
    // zero-false-positive goal we do not infer CSRF gaps from markup alone;
    // active state-changing CSRF testing requires an authenticated session and
    // is out of scope for the black-box pass.

    // --- 5. EASM PERIMETER (Subdomains, DNS and Real Host IP Lookup) ---
    // Perform active Domain audit map
    const commonSubdomains = [
      "www",
      "api",
      "dev",
      "staging",
      "admin",
      "vpn",
      "dashboard",
      "status",
      "mail",
      "remote",
      "blog",
      "webmail",
      "server",
      "ns1",
      "ns2",
      "smtp",
      "secure",
      "shop",
      "portal",
      "test",
      "cdn",
      "app",
      "m",
      "cloud",
      "qa",
      "support",
      "docs",
      "help",
      "login",
      "auth",
      "ftp",
      "pop",
      "imap",
    ];
    try {
      const ipRecords = await dns.resolve4(hostname).catch(() => []);
      if (ipRecords && ipRecords.length > 0) {
        result.easmPerimeter.ip = ipRecords[0];
      }

      // Resolve the authoritative nameserver(s) for real, when available.
      const nsRecords = await dns.resolveNs(hostname).catch(() => [] as string[]);
      if (nsRecords && nsRecords.length > 0) {
        result.easmPerimeter.nameserver = nsRecords[0];
      }

      // Check for Wildcard DNS to prevent false positive subdomain bloating
      let wildcardIp: string | null = null;
      try {
        const randomSub = crypto.randomBytes(6).toString("hex");
        const wildcardRecords = await dns.resolve4(`${randomSub}.${hostname}`);
        if (wildcardRecords && wildcardRecords.length > 0) {
          wildcardIp = wildcardRecords[0];
        }
      } catch (e) {
        // No wildcard DNS detected
      }

      const subdomainChecks = commonSubdomains.map(async (sub) => {
        const subUrl = `${sub}.${hostname}`;
        try {
          const records = await dns.resolve4(subUrl);

          // Filter out false positives caused by Wildcard DNS records
          if (wildcardIp && records.includes(wildcardIp)) {
            return {
              domain: subUrl,
              status: "inactive" as const,
              port: "0",
            };
          }

          return {
            domain: subUrl,
            status: "live" as const,
            port: sub.includes("vpn")
              ? "1194"
              : sub.includes("mail") || sub.includes("smtp")
                ? "25"
                : "443",
            ip: records[0],
          };
        } catch (err) {
          return {
            domain: subUrl,
            status: "inactive" as const,
            port: "0",
          };
        }
      });

      const subResults = await Promise.all(subdomainChecks);
      result.easmPerimeter.subdomains = subResults;
    } catch (e) {
      console.warn(
        "DNS resolution failed or not supported in this environment.",
        e,
      );
      // Fallback
      commonSubdomains.slice(0, 10).forEach((sub) => {
        result.easmPerimeter.subdomains.push({
          domain: `${sub}.${hostname}`,
          status: "inactive",
          port: "0",
        });
      });
    }

    // Sensitive Paths Probing. A path is only treated as "exposed" when the
    // response BODY actually matches the file's signature, not merely on a 200.
    // This eliminates the dominant false positive: single-page apps that serve
    // index.html (HTTP 200) for every unknown path including /.env.
    const sensitiveProbes: Array<{ path: string; matches: (body: string) => boolean }> = [
      { path: "/.env", matches: (b) => !looksLikeHtml(b) && /^[A-Z][A-Z0-9_]*\s*=/m.test(b) },
      { path: "/.git/config", matches: (b) => /\[core\]/i.test(b) || /repositoryformatversion/i.test(b) },
      { path: "/.git/HEAD", matches: (b) => /^ref:\s+refs\//m.test(b.trim()) },
      { path: "/phpinfo.php", matches: (b) => /<title>phpinfo\(\)/i.test(b) || /PHP Version\s*</i.test(b) },
      { path: "/.aws/credentials", matches: (b) => !looksLikeHtml(b) && /aws_access_key_id/i.test(b) },
      { path: "/config.json", matches: (b) => !looksLikeHtml(b) && /"(password|secret|api[_-]?key|private[_-]?key)"\s*:/i.test(b) },
    ];

    for (const probe of sensitiveProbes) {
      try {
        const probeController = new AbortController();
        const probeId = setTimeout(() => probeController.abort(), 2500);
        const probeRes = await safeFetch(`${host}${probe.path}`, {
          method: "GET",
          headers: { "User-Agent": "Seclayer-Security-Scanner/2.0 (seclayer.io)" },
          signal: probeController.signal,
        });
        const body = await probeRes.text().catch(() => "");
        clearTimeout(probeId);

        const exposed = probeRes.status === 200 && probe.matches(body);
        result.probedPaths.push({ path: probe.path, status: probeRes.status, exposed });
      } catch (err) {
        result.probedPaths.push({ path: probe.path, status: 0, exposed: false });
      }
    }
  } catch (err: any) {
    // A failure reaching the target means we cannot assess it. Surface this as
    // a failed scan rather than a misleading "clean" (no-findings) report.
    if (err?.name === "AbortError") {
      throw new Error(`Target ${url} did not respond within the timeout window.`);
    }
    throw new Error(`Unable to connect to ${url}: ${err?.message || "connection failed"}`);
  }

  // --- RED TEAM ACTIVE FUZZING PROBES ---
  // Gated behind verified domain ownership (allowActiveProbes) — these send
  // real exploit payloads (SQLi/XSS/cmd-injection/SSRF) at the target.
  const redTeamFindings: any[] = [];
  if (allowActiveProbes) {
  try {
    const fuzzHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. SQL Injection Active Probe
    try {
      const sqlCtl = new AbortController();
      const sqlId = setTimeout(() => sqlCtl.abort(), 4000);
      const sqlRes = await safeFetch(`${url}/?id=%27%20OR%201%3D1--`, {
        headers: fuzzHeaders,
        signal: sqlCtl.signal,
      });
      clearTimeout(sqlId);
      const sqlText = await sqlRes.text();
      // Match specific database error signatures only — never bare "syntax
      // error", which appears in unrelated content and causes false positives.
      const sqlErrorSig =
        /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;
      if (sqlErrorSig.test(sqlText)) {
        redTeamFindings.push({
          testName: "Active SQL Injection Probe",
          payload: "' OR 1=1--",
          severity: "critical",
          description:
            "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
          fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 2. Reflected XSS Active Probe
    try {
      const xssCtl = new AbortController();
      const xssId = setTimeout(() => xssCtl.abort(), 4000);
      const uniqueTrigger = `xss_probe_${crypto.randomBytes(4).toString("hex")}`;
      const xssRes = await safeFetch(
        `${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`,
        { headers: fuzzHeaders, signal: xssCtl.signal },
      );
      clearTimeout(xssId);
      const xssText = await xssRes.text();
      if (xssText.includes(`<script>${uniqueTrigger}</script>`)) {
        redTeamFindings.push({
          testName: "Active Reflected XSS Probe",
          payload: `<script>${uniqueTrigger}</script>`,
          severity: "high",
          description:
            "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
          fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 3. OS Command Injection Active Probe
    try {
      const cmdCtl = new AbortController();
      const cmdId = setTimeout(() => cmdCtl.abort(), 4000);
      const cmdRes = await safeFetch(`${url}/?ping=127.0.0.1%3B+id`, {
        headers: fuzzHeaders,
        signal: cmdCtl.signal,
      });
      clearTimeout(cmdId);
      const cmdText = await cmdRes.text();
      if (cmdText.includes("uid=") && cmdText.includes("gid=")) {
        redTeamFindings.push({
          testName: "Active OS Command Injection",
          payload: "; id",
          severity: "critical",
          description:
            "Active Red Team command injection fuzzing triggered a successful `id` evaluation on the backend, exposing sensitive host system access and execution permissions.",
          fix: "Avoid invoking underlying operating system commands entirely. If required, use strictly sanitized arguments array APIs, never shell-interpolated execution.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 4. SSRF Active Probe
    try {
      const ssrfCtl = new AbortController();
      const ssrfId = setTimeout(() => ssrfCtl.abort(), 4000);
      // Attempting to request localhost loopback or internal metadata
      const ssrfRes = await safeFetch(`${url}/?url=http://127.0.0.1:22`, {
        headers: fuzzHeaders,
        signal: ssrfCtl.signal,
      });
      clearTimeout(ssrfId);
      const ssrfText = await ssrfRes.text();
      if (
        ssrfText.includes("SSH-2.0-OpenSSH") ||
        ssrfText.includes("Protocol mismatch")
      ) {
        redTeamFindings.push({
          testName: "Active Server-Side Request Forgery (SSRF)",
          payload: "http://127.0.0.1:22",
          severity: "critical",
          description:
            "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
          fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }
  } catch (globalErr) {
    console.warn(
      "Red team active fuzzing encounted top-level error",
      globalErr,
    );
  }
  }

  result.redTeamFindings = redTeamFindings;

  // --- API SECURITY TESTING ACTIVE PROBES ---
  const apiSecFindings: any[] = [];
  if (allowActiveProbes) {
  try {
    const apiHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. GraphQL Introspection Probe
    try {
      const gqlCtl = new AbortController();
      const gqlId = setTimeout(() => gqlCtl.abort(), 4000);
      const reqRaw = `POST /graphql HTTP/1.1\nHost: ${hostname}\nContent-Type: application/json\n\n{"query":"{__schema{types{name}}}"}`;

      const gqlRes = await safeFetch(`${url}/graphql`, {
        method: "POST",
        headers: { ...apiHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{__schema{types{name}}}" }),
        signal: gqlCtl.signal,
      });
      clearTimeout(gqlId);
      const gqlText = await gqlRes.text();
      const resRaw = `HTTP/1.1 ${gqlRes.status} ${gqlRes.statusText}\n\n${gqlText.substring(0, 500)}...`;

      // Confirm a real introspection RESULT (data.__schema.types), not merely
      // the echoed query string or an error mentioning "__schema".
      let introspectionExposed = false;
      try {
        const parsed = JSON.parse(gqlText);
        introspectionExposed = Array.isArray(parsed?.data?.__schema?.types) && parsed.data.__schema.types.length > 0;
      } catch {
        introspectionExposed = false;
      }
      if (introspectionExposed) {
        apiSecFindings.push({
          testName: "GraphQL Schema Introspection Exposed",
          endpoint: "/graphql",
          severity: "high",
          description:
            "An active API endpoint probe discovered that GraphQL introspection is globally reachable. Attackers can effortlessly dump the entire undocumented internal schema definitions.",
          fix: "Disable introspection blocks in the production GraphQL backend. Shield API with explicit token authentication schemas.",
          rawRequest: reqRaw,
          rawResponse: resRaw,
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }

    // 2. Broken Object Level Authorization (BOLA) Probe
    try {
      const idorCtl = new AbortController();
      const idorId = setTimeout(() => idorCtl.abort(), 4000);
      const reqRawIdor = `GET /api/v1/users/admin HTTP/1.1\nHost: ${hostname}\nAccept: application/json`;

      const idorRes = await safeFetch(`${url}/api/v1/users/admin`, {
        headers: apiHeaders,
        signal: idorCtl.signal,
      });
      clearTimeout(idorId);
      const idorText = await idorRes.text();
      const idorCt = idorRes.headers.get("content-type") || "text/plain";
      const resRawIdor = `HTTP/1.1 ${idorRes.status} ${idorRes.statusText}\nContent-Type: ${idorCt}\n\n${idorText.substring(0, 500)}...`;

      // Only flag when a JSON user object is actually returned — a 200 HTML
      // page that happens to contain the word "email" is not a BOLA.
      let bolaConfirmed = false;
      if (idorRes.status === 200 && /application\/json/i.test(idorCt)) {
        try {
          const obj = JSON.parse(idorText);
          const candidate = obj?.user ?? obj?.data ?? obj;
          bolaConfirmed = !!candidate && typeof candidate === "object" &&
            ("email" in candidate || "role" in candidate || "username" in candidate);
        } catch {
          bolaConfirmed = false;
        }
      }
      if (bolaConfirmed) {
        apiSecFindings.push({
          testName: "Broken Object Level Authorization (BOLA)",
          endpoint: "/api/v1/users/admin",
          severity: "critical",
          description:
            "API testing successfully resolved protected user entities directly by probing enumerated resource IDs, overriding local tenant boundaries.",
          fix: "Enforce stringent object-level resource verification. Explicitly map authorization states against the retrieved user objects inside controller logic.",
          rawRequest: reqRawIdor,
          rawResponse: resRawIdor,
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }
  } catch (globalErr) {
    console.warn("API Security fuzzing encounted top-level error", globalErr);
  }
  }

  result.apiSecFindings = apiSecFindings;

  // --- CRAWL + DISCOVERED-PARAMETER FUZZING ---
  // Map the real attack surface (links, forms, JS-referenced endpoints) and aim
  // the injection probes at the parameters the application actually uses, rather
  // than only a few hardcoded names. Strictly bounded by page/request/time caps.
  try {
    if (rootHtml && result.responseStatus > 0) {
      const crawl = await crawlSite(url, authedFetch, {
        maxPages: 10,
        maxDepth: 2,
        budgetMs: 15000,
        seedHtml: rootHtml,
      });

      // Optional headless rendering: merge JS-rendered links and XHR/fetch
      // endpoints the static crawl cannot see (no-op unless explicitly enabled).
      let allTargets = crawl.targets;
      if (isRenderingEnabled()) {
        const rendered = await renderPage(url, { "User-Agent": headers["User-Agent"], ...authHeaders });
        if (rendered) {
          const renderedTargets = [
            ...targetsFromHtml(rendered.html, url),
            ...rendered.requestedUrls
              .map((u) => ({ url: u, method: "GET" as const, params: paramsOf(u), source: "script" as const }))
              .filter((t) => t.params.length > 0),
          ];
          allTargets = dedupeTargets([...crawl.targets, ...renderedTargets]);
        }
      }

      // Mapping (crawl) is always allowed — it's passive same-origin GETs.
      // Fuzzing the discovered parameters is an active exploit attempt, so it
      // is gated behind verified domain ownership like the other red-team probes.
      let fuzz = { findings: [] as any[], paramsTested: 0 };
      if (allowActiveProbes) {
        const getTargets = allTargets.filter((t) => t.method === "GET" && t.params.length > 0);
        fuzz = await fuzzDiscoveredTargets(getTargets, { ...headers, "Cache-Control": "no-cache" });
        result.redTeamFindings = [...(result.redTeamFindings || []), ...fuzz.findings];
      }

      result.crawl = {
        pagesVisited: crawl.pagesVisited,
        endpointsDiscovered: allTargets.length,
        paramsTested: fuzz.paramsTested,
        sampleEndpoints: allTargets.slice(0, 8).map((t) => {
          try {
            return new URL(t.url).pathname + (t.params.length ? `?${t.params.join("&")}` : "");
          } catch {
            return t.url;
          }
        }),
      };
    }
  } catch (crawlErr) {
    console.warn("Crawl/fuzz stage encountered an error", crawlErr);
  }

  // --- TEMPLATE-BASED DETECTIONS ---
  // Data-driven checks (exposed panels, config/backup files, actuators, etc.).
  // Each template confirms via a body signature, so SPA fallbacks aren't flagged.
  try {
    if (result.responseStatus > 0) {
      // Gate framework-specific templates by the detected tech profile so the
      // pack scales without running every stack's checks against every target.
      const techTags = detectTechTags(result.headers, rootHtml);
      const selected = selectTemplates(TEMPLATES, techTags);
      result.templateFindings = await runTemplates(host, authedFetch, selected, 6);
    }
  } catch (tplErr) {
    console.warn("Template detection stage encountered an error", tplErr);
  }

  return result;
}

// Active injection fuzzing of discovered GET parameters. Reuses the same SQLi
// error signatures and reflected-XSS token strategy as the root-level probes,
// but injects into real discovered parameters. Globally request-capped.
async function fuzzDiscoveredTargets(
  targets: InjectableTarget[],
  fuzzHeaders: Record<string, string>,
): Promise<{ findings: any[]; paramsTested: number }> {
  const MAX_REQUESTS = 24;
  const MAX_PARAMS_PER_TARGET = 3;
  const findings: any[] = [];
  const reported = new Set<string>(); // dedupe by testName+endpoint+param
  let budget = MAX_REQUESTS;
  let paramsTested = 0;

  const sqlErrorSig =
    /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;

  const buildUrl = (base: string, param: string, value: string): string => {
    const u = new URL(base);
    u.searchParams.set(param, value);
    return u.toString();
  };

  const probe = async (target: string): Promise<string> => {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 4000);
    try {
      const res = await safeFetch(target, { headers: fuzzHeaders, signal: ctl.signal });
      return await res.text();
    } finally {
      clearTimeout(id);
    }
  };

  for (const t of targets) {
    if (budget <= 0) break;
    let endpointPath = t.url;
    try {
      endpointPath = new URL(t.url).pathname;
    } catch {}

    for (const param of t.params.slice(0, MAX_PARAMS_PER_TARGET)) {
      if (budget <= 0) break;
      paramsTested++;

      // SQL injection: error-based signature on a discovered parameter.
      try {
        budget--;
        const text = await probe(buildUrl(t.url, param, "' OR 1=1-- -"));
        const key = `sqli:${endpointPath}:${param}`;
        if (sqlErrorSig.test(text) && !reported.has(key)) {
          reported.add(key);
          findings.push({
            testName: "SQL Injection (discovered parameter)",
            payload: `${param}=' OR 1=1-- -`,
            severity: "critical",
            description: `Injecting SQL metacharacters into the discovered parameter "${param}" on ${endpointPath} provoked a database error in the response, indicating an exploitable SQL injection.`,
            fix: "Use parameterized queries / prepared statements for this endpoint; never concatenate request input into SQL.",
          });
        }
      } catch { /* probe failed */ }

      if (budget <= 0) break;

      // Reflected XSS: unique token reflected unencoded.
      try {
        budget--;
        const token = `sx${crypto.randomBytes(4).toString("hex")}`;
        const payload = `<svg/onload=${token}>`;
        const text = await probe(buildUrl(t.url, param, payload));
        const key = `xss:${endpointPath}:${param}`;
        if (text.includes(payload) && !reported.has(key)) {
          reported.add(key);
          findings.push({
            testName: "Reflected XSS (discovered parameter)",
            payload: `${param}=${payload}`,
            severity: "high",
            description: `The discovered parameter "${param}" on ${endpointPath} reflects unencoded HTML/JavaScript into the response, confirming a reflected Cross-Site Scripting vulnerability.`,
            fix: "Apply context-aware output encoding for this parameter and deploy a restrictive Content-Security-Policy.",
          });
        }
      } catch { /* probe failed */ }
    }
  }

  return { findings, paramsTested };
}

// Convert diagnostics into structured Category Findings
export function compileStaticFindings(diag: DiagnosticResult): {
  score: number;
  severity: Severity;
  findings: Finding[];
} {
  const findings: Finding[] = [];

  // 0. Surface mapping summary (informational, zero score impact).
  if (diag.crawl && (diag.crawl.pagesVisited > 1 || diag.crawl.endpointsDiscovered > 0)) {
    const c = diag.crawl;
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Application Surface Mapped (${c.pagesVisited} pages, ${c.endpointsDiscovered} endpoints)`,
      description: `The crawler mapped ${c.pagesVisited} same-origin page(s) and discovered ${c.endpointsDiscovered} parameterized endpoint(s); ${c.paramsTested} parameter(s) were actively fuzzed.${c.sampleEndpoints.length ? ` Examples: ${c.sampleEndpoints.join(", ")}.` : ""}`,
      severity: "info",
      confidence: "high",
      fix: "No action required — this maps the tested attack surface for context.",
      category: "DAST",
    });
  }

  if (diag.activeProbesSkipped) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Active Exploit Probing Skipped (Unverified Target)",
      description: "SQL injection, XSS, command-injection, SSRF, GraphQL and BOLA exploit attempts were not run against this target because domain ownership has not been verified. Passive recon (headers, TLS, DNS, exposed files, tech/library detection, and surface mapping) still ran in full.",
      severity: "info",
      confidence: "high",
      fix: "Verify ownership of this domain (DNS TXT record or well-known file, from the dashboard) to unlock active exploit testing on future scans of this target.",
      category: "DAST",
    });
  }

  // 1. EASM (External Attack Surface Management) checks
  if (!diag.sslSecure) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Insecure Connection Protocol (HTTP)",
      description: `The target server at ${diag.url} is accessible over plaintext HTTP. All authentication tags, passwords, and sensitive cookies are transmitted in cleartext, enabling packet interception.`,
      severity: "high",
      confidence: "high",
      fix: "Deploy a valid SSL/TLS certificate and configure permanent rewrite rules on port 80 to redirect HTTP traffic securely to HTTPS.",
      category: "EASM",
    });
  }

  if (diag.techLeaked.length > 0) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Verbose Server Framework Signature Leaked",
      description: `The attack surface assessment detected visible framework signatures leaked in response headers: ${diag.techLeaked.join(", ")}. Automated bots use these patterns to locate vulnerable systems.`,
      severity: "low",
      confidence: "high",
      fix: "Disable verbose Server headers in nginx.conf or web.config and strip x-powered-by settings globally.",
      category: "EASM",
    });
  }

  // 2. IAST (Interactive Application Security / Defensive Rules) checks
  // Missing security headers are defense-in-depth GAPS, not confirmed
  // vulnerabilities — a black-box GET can also miss headers a site serves
  // conditionally (per-route, per-User-Agent). They are reported at medium
  // with medium confidence so a possibly-absent header never dominates a
  // report as "high" on an otherwise well-hardened target.
  if (diag.missingHeaders.includes("content-security-policy")) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Missing Content-Security-Policy (CSP)",
      description:
        "No Content-Security-Policy header was observed on the scanned response. CSP is a defense-in-depth control that constrains where scripts and other resources may load from, reducing the blast radius of any cross-site scripting (XSS) flaw. Its absence is not itself an exploitable vulnerability.",
      severity: "medium",
      confidence: "medium",
      fix: "Deploy restrictive CSP header directives like \"Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-origin.com\".",
      category: "IAST",
    });
  }

  if (diag.missingHeaders.includes("strict-transport-security")) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Missing Strict-Transport-Security (HSTS) Policy",
      description:
        "No HTTP Strict-Transport-Security (HSTS) header was observed on the scanned response. HSTS instructs browsers to only ever connect over HTTPS, mitigating protocol-downgrade and SSL-stripping attacks. Note that large sites sometimes serve this header only on specific routes, so confirm against a browser before treating it as absent.",
      severity: "medium",
      confidence: "medium",
      fix: 'Transmit the header: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" over all HTTPS targets.',
      category: "IAST",
    });
  }

  if (diag.missingHeaders.includes("x-frame-options")) {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: "Missing X-Frame-Options / Clickjacking Immunity",
      description:
        "No anti-framing instruction (X-Frame-Options or CSP frame-ancestors) was observed on the scanned response. Without it, an attacker can frame the page inside a transparent overlay to hijack clicks. Some sites rely on CSP frame-ancestors instead, so confirm before treating this as absent.",
      severity: "medium",
      confidence: "medium",
      fix: 'Enforce "X-Frame-Options: DENY" or deploy CSP "frame-ancestors \'none\'" instructions.',
      category: "IAST",
    });
  }

  diag.cookieIssues.forEach((issue) => {
    const isSecureIssue = /secure attribute/i.test(issue);
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: issue,
      description: isSecureIssue
        ? `${issue}. A cookie without the Secure attribute can be transmitted over an unencrypted connection, where a network attacker could intercept it. If this cookie carries session or authentication state, that exposes the session to hijacking.`
        : `${issue}. A cookie without HttpOnly is readable by client-side JavaScript, so a cross-site scripting flaw elsewhere on the site could exfiltrate it. If this cookie carries session or authentication state, that raises the impact of any XSS to full session theft.`,
      severity: "medium",
      confidence: "high",
      fix: isSecureIssue
        ? "Add the Secure attribute to this cookie so it is only ever sent over HTTPS."
        : "Add the HttpOnly attribute to this cookie unless it must be read by client-side JavaScript; if it must, keep the sensitive session token in a separate HttpOnly cookie.",
      category: "IAST",
    });
  });

  // 3. SAST (Static Code Security Analysis) checks
  diag.sastFindings.forEach((sf) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: sf.issue,
      description: sf.description,
      severity: sf.severity,
      confidence: sf.confidence,
      fix: sf.fix,
      category: "SAST",
    });
  });

  // 4. SCA (Software Composition Analysis) checks
  diag.scaLibraries.forEach((sca) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Outdated Library Vulnerability Detected (${sca.name})`,
      description: sca.description,
      severity: sca.severity,
      confidence: "medium",
      fix: sca.fix,
      category: "SCA",
    });
  });

  // 5. DAST (Dynamic Application Security Probes) checks
  diag.dastInputs.forEach((dast) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: dast.vulnerability,
      description: dast.description,
      severity: dast.severity,
      confidence: "medium",
      fix: dast.fix,
      category: "DAST",
    });
  });

  // Probed Paths exposures check
  const exposed = diag.probedPaths.filter((p) => p.exposed);
  exposed.forEach((exp) => {
    findings.push({
      id: "f_" + crypto.randomBytes(4).toString("hex"),
      title: `Exposed Critical Resource File (${exp.path})`,
      description: `Active Dynamic scanning discovered a public exposed configuration target at ${diag.url}${exp.path}. This file can be queried freely over the web, yielding secret metadata configurations.`,
      severity:
        exp.path.includes(".env") || exp.path.includes(".git")
          ? "critical"
          : "high",
      confidence: "high",
      fix: `Immediately strip dynamic routes to ${exp.path} inside server rewrite engines or configure .htaccess rules to return 403 blocks.`,
      category: "DAST",
    });
  });

  // Compile Red Team aggressive probing findings
  if (diag.redTeamFindings && diag.redTeamFindings.length > 0) {
    diag.redTeamFindings.forEach((rt) => {
      findings.push({
        id: "f_rt_" + crypto.randomBytes(4).toString("hex"),
        title: rt.testName,
        description: rt.description,
        severity: rt.severity,
        confidence: "high",
        fix: rt.fix,
        category: "RED_TEAM",
      });
    });
  }

  // Compile API Security Testing findings
  if (diag.apiSecFindings && diag.apiSecFindings.length > 0) {
    diag.apiSecFindings.forEach((api) => {
      findings.push({
        id: "f_api_" + crypto.randomBytes(4).toString("hex"),
        title: api.testName,
        description: api.description,
        severity: api.severity,
        confidence: "high",
        fix: api.fix,
        category: "API_SEC",
        endpoint: api.endpoint,
        rawRequest: api.rawRequest,
        rawResponse: api.rawResponse,
      });
    });
  }

  // Template engine findings (exposed panels, config/backup files, actuators).
  if (diag.templateFindings && diag.templateFindings.length > 0) {
    findings.push(...diag.templateFindings);
  }

  // Final dedupe by title so a check can never double-report the same issue.
  const seenTitles = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = f.title.toLowerCase();
    if (seenTitles.has(key)) return false;
    seenTitles.add(key);
    return true;
  });

  // Tag each finding with its OWASP Top 10 (2021) category, and give it a
  // baseline impact/agentPrompt. DeepSeek (when configured) writes sharper,
  // finding-specific versions of both; these are the guaranteed fallback so
  // every scan — with or without an AI key — ships an actionable "fix this
  // with your coding agent" prompt.
  for (const f of deduped) {
    if (!f.owasp) f.owasp = mapOwasp(f.category, f.title);
    if (!f.impact) f.impact = buildImpactFallback(f.severity);
    if (!f.agentPrompt) f.agentPrompt = buildAgentPrompt(f, diag.url);
  }

  // Score via the shared scoring module so the initial score and any later
  // recalculation (after suppression) always use identical weights.
  const { score, severity } = scoreFindings(deduped);
  return { score, severity, findings: deduped };
}

// The five defensive response headers the scanner tracks (see runDiagnostics).
const TRACKED_SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
];

// Distils the raw diagnostics into the compact, display-oriented evidence the
// report renders — real resolved IP, nameserver, live subdomains, per-path
// probe results, detected libraries, crawl coverage, and header state. This is
// what replaces the report's previously-hardcoded placeholder network data.
export function compileScanEvidence(diag: DiagnosticResult): ScanEvidence {
  const present = TRACKED_SECURITY_HEADERS.filter((h) => !diag.missingHeaders.includes(h));
  return {
    scannedAt: diag.scannedAt,
    responseStatus: diag.responseStatus,
    protocol: diag.easmPerimeter.protocol || (diag.sslSecure ? "HTTPS" : "HTTP"),
    resolvedIp: diag.easmPerimeter.ip || undefined,
    nameserver: diag.easmPerimeter.nameserver || undefined,
    serverHeader: diag.headers["server"] || undefined,
    presentSecurityHeaders: present,
    missingSecurityHeaders: [...diag.missingHeaders],
    liveSubdomains: diag.easmPerimeter.subdomains.filter((s) => s.status === "live").map((s) => s.domain),
    subdomainsChecked: diag.easmPerimeter.subdomains.length,
    probedPaths: diag.probedPaths.map((p) => ({ path: p.path, status: p.status, exposed: p.exposed })),
    detectedLibraries: diag.scaLibraries.map((l) => ({ name: l.name, version: l.version, vulnerable: l.status === "vuln" })),
    crawl: diag.crawl,
    activeProbesRun: !diag.activeProbesSkipped,
  };
}
