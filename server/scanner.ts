import { Finding, Severity, ExploitEvidence, BolaIdentity } from "../src/types.js";
import type { OobCollaborator } from "./oob.js";
import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf, InjectableTarget } from "./crawler.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { isLikelyPlaceholderSecret, xssReflectionExecutes } from "./fpFilters.js";
import { renderPage, isRenderingEnabled } from "./render.js";
import { safeFetch, assertTargetIsScannable } from "./ssrf.js";
import {
  looksLikeHtml, parseAuthHeader, renderRawRequest, renderRawResponse, windowAround,
  buildProbeEvidence, buildOobEvidence, extractIdentityMarker,
} from "./evidence.js";
import { fuzzDiscoveredTargets } from "./paramFuzzer.js";
import { bolaProbe } from "./bola.js";
import crypto from "crypto";
import * as dns from "dns/promises";

// Re-export the SSRF, evidence, and findings-compilation entry points so
// existing importers of scanner.js keep working after these moved to dedicated
// modules (./ssrf.js, ./evidence.js, ./findings.js).
export { isBlockedIp, firstBlockedAddress, safeDispatcher, guardedFetch, assertScanTargetSafe, safeFetch } from "./ssrf.js";
export { looksLikeHtml, parseAuthHeader, renderRawRequest, windowAround } from "./evidence.js";
export { compileStaticFindings, compileScanEvidence } from "./findings.js";
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
    evidence?: ExploitEvidence; // stored exploit receipt (promotes to PROVEN)
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
    evidence?: ExploitEvidence; // stored exploit receipt (promotes to PROVEN)
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

  // Two owned test identities that unlock a PROVEN cross-tenant BOLA/IDOR check
  // (docs/confirmed-evidence-spec.md §3.1a). Layered on top of allowActiveProbes —
  // ownership must still be verified. When absent, the two-identity probe is
  // simply skipped (the rest of the scan is unaffected).
  bolaIdentities?: [BolaIdentity, BolaIdentity];

  // Out-of-band collaborator used to PROVE blind vulnerabilities: the scanner
  // injects a unique callback URL and, if the target reaches back to it, emits a
  // PROVEN 'out-of-band' finding. Threaded in by the server only when a reachable
  // public base URL is configured; when absent, the OOB probe is simply skipped.
  oob?: OobCollaborator;

  // Optional scan id, forwarded to the collaborator so a recorded callback can be
  // attributed to this scan. Purely for the audit trail.
  scanId?: string;
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
        const m = p.regex.exec(htmlText);
        // Signature match is necessary but not sufficient: skip documented
        // example/placeholder credentials (e.g. AWS's AKIAIOSFODNN7EXAMPLE,
        // sk_live_0000…, YOUR_API_KEY) so they never surface as false positives.
        if (m && !isLikelyPlaceholderSecret(m[0])) {
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
      const sqlMatch = sqlErrorSig.exec(sqlText);
      if (sqlMatch) {
        // Receipt: the injected request plus the exact database-error text the
        // engine emitted — quoted verbatim so the proof can be seen, not asserted.
        const attackUrl = `${url}/?id=%27%20OR%201%3D1--`;
        redTeamFindings.push({
          testName: "Active SQL Injection Probe",
          payload: "' OR 1=1--",
          severity: "critical",
          description:
            "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
          fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
          evidence: buildProbeEvidence({
            method: "error-signature",
            attackUrl,
            requestHeaders: fuzzHeaders,
            res: sqlRes,
            body: sqlText,
            matchIndex: sqlMatch.index,
            quote: sqlMatch[0],
            why: "This is a raw database-engine error, emitted only when our injected quote breaks the SQL query's syntax. A benign value does not produce it — so request input is reaching the database unescaped.",
            demonstration:
              'We injected the SQL boundary payload "\' OR 1=1--" into the "id" parameter and the server responded with a raw database error. That error is proof the input reaches the SQL engine unescaped — the hallmark of an exploitable injection.',
          }),
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
      const marker = `<script>${uniqueTrigger}</script>`;
      const markerIdx = xssText.indexOf(marker);
      // Reflection alone is not XSS: require an HTML response the browser will
      // parse AND a context where the marker actually executes (not a JSON echo,
      // an HTML comment, a <textarea>/<title>, etc.). This gate removes the
      // dominant reflected-XSS false positive.
      if (markerIdx !== -1 && xssReflectionExecutes(xssRes.headers.get("content-type"), xssText, markerIdx)) {
        // Receipt: the request that carried the payload and the response that
        // reflected it back verbatim (windowed so the marker survives truncation).
        const attackUrl = `${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`;
        redTeamFindings.push({
          testName: "Active Reflected XSS Probe",
          payload: marker,
          severity: "high",
          description:
            "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
          fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
          evidence: buildProbeEvidence({
            method: "reflection",
            attackUrl,
            requestHeaders: fuzzHeaders,
            res: xssRes,
            body: xssText,
            matchIndex: markerIdx,
            quote: marker,
            why: "The unique probe marker was echoed back verbatim and unescaped inside the HTML body, so a browser parses it as a live <script> element rather than text.",
            demonstration:
              `We submitted the unique marker ${marker} in the "q" query parameter, and the server reflected it back into the page unescaped. Because it is returned as live HTML — not text — an attacker-supplied script placed here would execute in a visitor's browser.`,
          }),
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 3. OS Command Injection Active Probe.
    // Oracle-first: inject an arithmetic expression with random operands and look
    // for the COMPUTED SUM in the response. The literal payload never contains the
    // sum, so its appearance can only mean the backend evaluated our injected
    // command — a proof that can't be a coincidental page string. We fall back to
    // the classic `id` output signature only if the arithmetic oracle doesn't land.
    const cmdFix =
      "Avoid invoking underlying operating system commands entirely. If required, use strictly sanitized arguments array APIs, never shell-interpolated execution.";
    const cmdDesc =
      "Active Red Team command-injection fuzzing evaluated an injected shell command on the backend, confirming arbitrary OS command execution.";
    try {
      const a = 100000 + crypto.randomInt(899999); // 6-digit operands so the sum
      const b = 100000 + crypto.randomInt(899999); // is a distinctive, unlikely string
      const sum = String(a + b);
      const oracleUrl = `${url}/?ping=127.0.0.1%3B+expr+${a}+%2B+${b}`;
      const oCtl = new AbortController();
      const oId = setTimeout(() => oCtl.abort(), 4000);
      const oracleRes = await safeFetch(oracleUrl, { headers: fuzzHeaders, signal: oCtl.signal });
      clearTimeout(oId);
      const oracleText = await oracleRes.text();
      const sumIdx = oracleText.indexOf(sum);

      if (sumIdx !== -1) {
        redTeamFindings.push({
          testName: "Active OS Command Injection",
          payload: `; expr ${a} + ${b}`,
          severity: "critical",
          description: cmdDesc,
          fix: cmdFix,
          evidence: buildProbeEvidence({
            method: "oracle",
            attackUrl: oracleUrl,
            requestHeaders: fuzzHeaders,
            res: oracleRes,
            body: oracleText,
            matchIndex: sumIdx,
            quote: sum,
            why: `We injected "expr ${a} + ${b}"; the server returned ${sum}, the exact arithmetic result. The literal payload never contains that number, so the backend must have executed our injected command to produce it.`,
            demonstration: `We injected the shell command "expr ${a} + ${b}" into the "ping" parameter, and the server responded with ${sum} — the computed sum. The only way that number appears is if the server ran our command, proving arbitrary OS command execution.`,
          }),
        });
      } else {
        // Fallback: classic `id` output signature (uid=…gid=…).
        const idUrl = `${url}/?ping=127.0.0.1%3B+id`;
        const iCtl = new AbortController();
        const iId = setTimeout(() => iCtl.abort(), 4000);
        const idRes = await safeFetch(idUrl, { headers: fuzzHeaders, signal: iCtl.signal });
        clearTimeout(iId);
        const idText = await idRes.text();
        const idMatch = /uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)/.exec(idText);
        if (idMatch) {
          redTeamFindings.push({
            testName: "Active OS Command Injection",
            payload: "; id",
            severity: "critical",
            description: cmdDesc,
            fix: cmdFix,
            evidence: buildProbeEvidence({
              method: "oracle",
              attackUrl: idUrl,
              requestHeaders: fuzzHeaders,
              res: idRes,
              body: idText,
              matchIndex: idMatch.index,
              quote: idMatch[0],
              why: "This is the output of the Unix `id` command (the current user's uid/gid), returned only because the backend executed our injected `; id`. It is not static page content.",
              demonstration: `We injected "; id" into the "ping" parameter and the server returned "${idMatch[0]}" — the live output of the id command. That output only appears if the server executed our injected command.`,
            }),
          });
        }
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
      // The signal is internal-only content the public target could not otherwise
      // return: an SSH banner from the loopback interface. Quote the exact banner so
      // the proof is the leaked internal data itself, not merely a boolean.
      // (A true out-of-band callback oracle is the pending upgrade — spec §7 #4.)
      const ssrfMatch = /SSH-2\.0-\S+|Protocol mismatch\.?/.exec(ssrfText);
      const ssrfUrl = `${url}/?url=http://127.0.0.1:22`;
      if (ssrfMatch) {
        redTeamFindings.push({
          testName: "Active Server-Side Request Forgery (SSRF)",
          payload: "http://127.0.0.1:22",
          severity: "critical",
          description:
            "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
          fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
          evidence: buildProbeEvidence({
            method: "oracle",
            attackUrl: ssrfUrl,
            requestHeaders: fuzzHeaders,
            res: ssrfRes,
            body: ssrfText,
            matchIndex: ssrfMatch.index,
            quote: ssrfMatch[0],
            why: "This is an SSH service banner from 127.0.0.1 — the target's own loopback interface, unreachable from the public internet. Its presence in the response means the server fetched an attacker-chosen internal address on our behalf.",
            demonstration: `We asked the app to fetch "http://127.0.0.1:22" (its own internal loopback), and the response came back carrying "${ssrfMatch[0]}" — an internal SSH banner a public visitor can never reach. That proves the server can be steered to make requests to internal systems.`,
          }),
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 5. Out-of-band SSRF probe (blind). Reflection only catches SSRF that echoes
    // internal content back inline; this catches the blind case by injecting a
    // unique collaborator URL and watching for the target to call it. A recorded
    // callback is the proof — see server/oob.ts and buildOobEvidence.
    if (opts.oob) {
      try {
        const probe = opts.oob.issue(opts.scanId);
        const oobAttackUrl = `${url}/?url=${encodeURIComponent(probe.url)}`;
        const oobCtl = new AbortController();
        const oobId = setTimeout(() => oobCtl.abort(), 4000);
        try {
          // Fire the trigger: ask the target to fetch our collaborator URL.
          await safeFetch(oobAttackUrl, { headers: fuzzHeaders, signal: oobCtl.signal });
        } catch {
          /* the target may not respond to us directly — the callback is the proof */
        } finally {
          clearTimeout(oobId);
        }
        // Wait a bounded window for the target to reach our collaborator.
        const event = await opts.oob.poll(probe.token, 8000);
        if (event) {
          redTeamFindings.push({
            testName: "Blind Server-Side Request Forgery (out-of-band)",
            payload: probe.url,
            severity: "critical",
            description:
              "The target fetched a unique Seclayer collaborator URL supplied in the \"url\" parameter, reaching our out-of-band listener from its own infrastructure. This proves the server makes attacker-controlled outbound requests even though nothing is reflected in its response — a blind SSRF that can be aimed at internal services or cloud metadata.",
            fix: "Do not fetch user-supplied URLs directly. Enforce an allow-list of permitted hosts, resolve and validate the destination IP (blocking loopback/link-local/RFC1918/metadata ranges), and disable redirects to internal addresses.",
            evidence: buildOobEvidence({
              attackUrl: oobAttackUrl,
              requestHeaders: fuzzHeaders,
              callbackUrl: probe.url,
              token: probe.token,
              event,
              why: "This is our collaborator's record of the target calling the unique, unguessable URL we injected. Only a server that fetched our payload URL could produce this callback — a public visitor cannot forge it.",
              demonstration: `We put a one-time Seclayer URL in the "url" parameter, and moments later the target itself connected to that URL from ${event.sourceIp}. That callback — carrying our unique token — proves the server made a request we controlled, without leaking anything in its own response.`,
            }),
          });
        }
      } catch (e) {
        /* Ignore OOB probe errors */
      }
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
      const gqlBody = JSON.stringify({ query: "{__schema{types{name}}}" });

      const gqlRes = await safeFetch(`${url}/graphql`, {
        method: "POST",
        headers: { ...apiHeaders, "Content-Type": "application/json" },
        body: gqlBody,
        signal: gqlCtl.signal,
      });
      clearTimeout(gqlId);
      const gqlText = await gqlRes.text();

      // Confirm a real introspection RESULT (data.__schema.types), not merely
      // the echoed query string or an error mentioning "__schema".
      let typeCount = 0;
      try {
        const parsed = JSON.parse(gqlText);
        if (Array.isArray(parsed?.data?.__schema?.types)) typeCount = parsed.data.__schema.types.length;
      } catch {
        typeCount = 0;
      }
      if (typeCount > 0) {
        // Receipt: the introspection query and the schema dump it returned. The
        // returned schema IS the evidence — quote the "__schema" result marker.
        const quote = '"__schema"';
        const schemaIdx = gqlText.indexOf(quote);
        const requestText = renderRawRequest(
          "POST",
          `${url}/graphql`,
          { ...apiHeaders, "Content-Type": "application/json" },
          gqlBody,
        );
        const responseText = renderRawResponse(gqlRes, windowAround(gqlText, Math.max(0, schemaIdx), quote.length, 2000));
        apiSecFindings.push({
          testName: "GraphQL Schema Introspection Exposed",
          endpoint: "/graphql",
          // Disclosure, not exploitation — the schema is the evidence. Kept at
          // `high`, never `critical` (spec §3.6 / open decision #3).
          severity: "high",
          description:
            "An active API endpoint probe discovered that GraphQL introspection is globally reachable. Attackers can effortlessly dump the entire undocumented internal schema definitions.",
          fix: "Disable introspection blocks in the production GraphQL backend. Shield API with explicit token authentication schemas.",
          evidence: {
            method: "introspection",
            attack: { request: requestText, response: responseText },
            signal: {
              quote,
              offsetInResponse: responseText.indexOf(quote),
              why: `The endpoint answered a standard introspection query with a full schema result (data.__schema.types — ${typeCount} types), so the entire internal API schema is publicly dumpable.`,
            },
            demonstration: `We sent a standard GraphQL introspection query to /graphql and the server returned its full schema — ${typeCount} types — with no authentication required. Anyone can map your entire API surface, including undocumented fields.`,
            reproduction: `curl -s -X POST "${url}/graphql" -H "Content-Type: application/json" --data '${gqlBody}'`,
            capturedAt: new Date().toISOString(),
          },
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }

    // 2. Exposed user-object endpoint probe (fixed-path guess). This is a
    // single-request heuristic: it does NOT prove a cross-tenant authorization
    // break — that is the separate two-identity BOLA probe below. So it is titled
    // honestly ("Exposed User Object Endpoint"), never "BOLA", which also keeps it
    // from colliding with the PROVEN BOLA finding during title-dedup.
    try {
      const idorCtl = new AbortController();
      const idorId = setTimeout(() => idorCtl.abort(), 4000);
      const idorUrl = `${url}/api/v1/users/admin`;
      const idorRes = await safeFetch(idorUrl, { headers: apiHeaders, signal: idorCtl.signal });
      clearTimeout(idorId);
      const idorText = await idorRes.text();
      const idorCt = idorRes.headers.get("content-type") || "text/plain";

      // Only flag when a JSON user object is actually returned — a 200 HTML page
      // that happens to contain the word "email" is not an exposed record. Quote a
      // real identifying value (or the key name) so the receipt shows the leak.
      let marker = "";
      if (idorRes.status === 200 && /application\/json/i.test(idorCt)) {
        try {
          const obj = JSON.parse(idorText);
          const candidate = obj?.user ?? obj?.data ?? obj;
          if (candidate && typeof candidate === "object") {
            for (const k of ["email", "username", "role"]) {
              const v = (candidate as any)[k];
              if (typeof v === "string" && v) { marker = v; break; }
            }
            if (!marker) {
              for (const k of ["email", "username", "role"]) {
                if (k in candidate) { marker = `"${k}"`; break; }
              }
            }
          }
        } catch { marker = ""; }
      }
      if (marker && idorText.includes(marker)) {
        apiSecFindings.push({
          testName: "Exposed User Object Endpoint",
          endpoint: "/api/v1/users/admin",
          severity: "critical",
          description:
            "A request to /api/v1/users/admin returned a JSON user/admin record directly. Protected user objects should not be served from a guessable path.",
          fix: "Require authentication and object-level authorization on user endpoints; do not expose admin/user records at predictable paths.",
          evidence: buildProbeEvidence({
            method: "oracle",
            attackUrl: idorUrl,
            requestHeaders: apiHeaders,
            res: idorRes,
            body: idorText,
            matchIndex: idorText.indexOf(marker),
            quote: marker,
            why: "The endpoint returned a JSON user record carrying this identifying field, proving the user/admin object is served directly at this path.",
            demonstration: `We requested /api/v1/users/admin and the server returned a user record containing ${marker}. A protected user object is reachable directly at this path.`,
          }),
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }

    // 3. Two-identity BOLA / IDOR — proves (or disproves) a cross-tenant read when
    // the caller supplied two owned test identities. Uses a clean, auth-free base
    // for the control request so "unauthenticated" really means no credentials.
    if (opts.bolaIdentities && opts.bolaIdentities.length === 2) {
      try {
        const bolaBase = {
          "User-Agent": headers["User-Agent"] || "Seclayer-Security-Scanner/2.0",
          "Cache-Control": "no-cache",
        };
        const bolaResults = await bolaProbe(host, opts.bolaIdentities, bolaBase);
        if (bolaResults) apiSecFindings.push(...bolaResults);
      } catch (e) {
        /* best-effort */
      }
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
