import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf, InjectableTarget } from "./crawler.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { renderPage, isRenderingEnabled } from "./render.js";
import { safeFetch, assertTargetIsScannable } from "./ssrf.js";
import { parseAuthHeader } from "./evidence.js";
import { fuzzDiscoveredTargets } from "./paramFuzzer.js";
import { probeStoredXss } from "./storedXss.js";
import { runRedTeamProbes } from "./redTeamProbes.js";
import { runAggressiveProbes } from "./aggressiveProbes.js";
import { runApiSecProbes } from "./apiProbes.js";
import { probeJwtAuth } from "./jwtProbe.js";
import { runPassiveScan } from "./passiveScan.js";
import type { DiagnosticResult, ScanOptions } from "./scanTypes.js";

// Re-export the SSRF, evidence, and findings-compilation entry points so
// existing importers of scanner.js keep working after these moved to dedicated
// modules (./ssrf.js, ./evidence.js, ./findings.js).
export { isBlockedIp, firstBlockedAddress, safeDispatcher, guardedFetch, assertScanTargetSafe, safeFetch } from "./ssrf.js";
export { looksLikeHtml, parseAuthHeader, renderRawRequest, windowAround } from "./evidence.js";
export { compileStaticFindings, compileScanEvidence } from "./findings.js";
export type { DiagnosticResult, ScanOptions } from "./scanTypes.js";
export async function runDiagnostics(
  targetUrl: string,
  authHeader?: string,
  opts: ScanOptions = {},
): Promise<DiagnosticResult> {
  const allowActiveProbes = !!opts.allowActiveProbes;
  // The aggressive tier is more invasive, so it requires BOTH the active-probe
  // gate (verified ownership) AND an explicit per-scan opt-in.
  const allowAggressiveProbes = allowActiveProbes && !!opts.allowAggressiveProbes;
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

  // JWT auth-weakness probe (signature-not-verified). Only fires when the scan
  // carries a Bearer JWT and the endpoint enforces auth; read-only. Gated on
  // ownership; appended to the red-team findings for the shared receipt pipeline.
  if (allowActiveProbes) {
    try {
      const jwtFinding = await probeJwtAuth(url, headers);
      if (jwtFinding) result.redTeamFindings = [...(result.redTeamFindings || []), jwtFinding];
    } catch (e) {
      console.warn("JWT auth probe encountered an error", e);
    }
  }

  // AGGRESSIVE tier (opt-in, more invasive): SSTI, LFI/path-traversal, open
  // redirect, CRLF, CORS, out-of-band XXE, NoSQL injection. Non-destructive and
  // signature/OOB-proven. Appended to the red-team findings so they share the
  // RED_TEAM category, PROVEN-receipt scoring, and the report/fix-prompt pipeline.
  if (allowAggressiveProbes) {
    const aggressive = await runAggressiveProbes(url, headers, { oob: opts.oob, scanId: opts.scanId });
    result.redTeamFindings = [...(result.redTeamFindings || []), ...aggressive];
  }

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
        // Fuzz both GET query parameters and POST form fields the crawler mapped.
        // The fuzzer sends each payload with the target's own method (query string
        // for GET, form-encoded body for POST), so discovered forms are no longer
        // mapped-but-skipped.
        const fuzzTargets = allTargets.filter((t) => t.params.length > 0);
        fuzz = await fuzzDiscoveredTargets(fuzzTargets, { ...headers, "Cache-Control": "no-cache" }, { aggressive: allowAggressiveProbes });
        result.redTeamFindings = [...(result.redTeamFindings || []), ...fuzz.findings];
      }

      // Stored/persistent XSS over discovered POST forms. Aggressive tier: it
      // submits a persisting marker (mutates state), so it requires the same
      // explicit opt-in as the other invasive probes. Proves the two-step flow —
      // POST the marker, then see it on a separate GET.
      if (allowAggressiveProbes) {
        const formTargets = allTargets.filter((t) => t.method === "POST" && t.params.length > 0);
        const stored = await probeStoredXss(formTargets, { ...headers, "Cache-Control": "no-cache" });
        result.redTeamFindings = [...(result.redTeamFindings || []), ...stored];
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
