import { Finding, Severity, ExploitEvidence, BolaIdentity } from "../src/types.js";
import type { OobCollaborator } from "./oob.js";
import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf, InjectableTarget } from "./crawler.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { renderPage, isRenderingEnabled } from "./render.js";
import { safeFetch, assertTargetIsScannable } from "./ssrf.js";
import { parseAuthHeader } from "./evidence.js";
import { fuzzDiscoveredTargets } from "./paramFuzzer.js";
import { runRedTeamProbes } from "./redTeamProbes.js";
import { runApiSecProbes } from "./apiProbes.js";
import { runPassiveScan } from "./passiveScan.js";

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

  // Passive recon of the root document: headers, cookies, SAST secrets, SCA
  // libraries, EASM perimeter, and sensitive paths. Returns the root HTML to
  // seed the crawler. Throws on an unreachable target. See server/passiveScan.ts.
  const rootHtml = await runPassiveScan(url, host, hostname, headers, result);

  // RED TEAM active fuzzing (SQLi/XSS/cmd-injection/SSRF, incl. blind OOB).
  // Gated behind verified domain ownership. See server/redTeamProbes.ts.
  result.redTeamFindings = allowActiveProbes
    ? await runRedTeamProbes(url, headers, { oob: opts.oob, scanId: opts.scanId })
    : [];

  // API SECURITY active probes (GraphQL introspection, exposed user object,
  // two-identity BOLA). Gated behind ownership. See server/apiProbes.ts.
  result.apiSecFindings = allowActiveProbes
    ? await runApiSecProbes(url, host, headers, { bolaIdentities: opts.bolaIdentities })
    : [];

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
