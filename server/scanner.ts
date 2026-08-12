import { crawlSite, targetsFromHtml, dedupeTargets, paramsOf, InjectableTarget } from "./crawler.js";
import { discoverAndParseApi } from "./openapi.js";
import { runTemplates, selectTemplates } from "./templateEngine.js";
import { TEMPLATES } from "./templates.js";
import { detectTechTags } from "./techprofile.js";
import { renderPage, isRenderingEnabled } from "./render.js";
import { safeFetch, assertTargetIsScannable } from "./ssrf.js";
import { parseAuthHeader } from "./evidence.js";
import { fuzzDiscoveredTargets, type FuzzCapture } from "./paramFuzzer.js";
import { weakTokenFindings } from "./weakTokenScan.js";
import { buildGuessedTargets } from "./paramMiner.js";
import { probeStoredXss } from "./storedXss.js";
import { findLoginTarget, probeWeakSessionToken } from "./redTeam/weakSessionToken.js";
import { runRedTeamProbes } from "./redTeamProbes.js";
import { runAggressiveProbes } from "./aggressiveProbes.js";
import { runApiSecProbes, exposedUserListInCapture, exposedCredentialListInCapture } from "./apiProbes.js";
import { probeJwtAuth, extractJwtSecretCandidates } from "./jwtProbe.js";
import { probeI18nAuthBypass } from "./i18nProbe.js";
import { extractUrlKeyPairs, probeCredentialUrlPairs } from "./credentialChainProbe.js";
import { probeEdgeFunctionAuth } from "./edgeFunctionProbe.js";
import { probePrototypePollution } from "./prototypePollutionProbe.js";
import { probePriceManipulation } from "./priceManipulationProbe.js";
import { probeWebhookSignatureBypass } from "./webhookSignatureProbe.js";
import { probeAuthRateLimit } from "./authRateLimitProbe.js";
import { probeDomXss } from "./domXss.js";
import { runPassiveScan, cookieFlagIssues } from "./passiveScan.js";
import { analyzeSecrets, analyzeDataDumpExposure } from "./staticAnalysis.js";
import { buildScanCoverage } from "./coverage.js";
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
  // Live progress sink for the real-time ticker (no-op when nobody's watching).
  const emit = opts.emit;
  // How many tech-gated templates were actually selected to run (for coverage).
  let templatesRun = 0;
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
      "Seclayer-Security-Scanner/2.0 (seclayerio.ai; scanner@seclayerio.ai)",
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
  emit?.("system", "Target validated. Passive recon: headers, TLS, secrets, libraries, perimeter & sensitive paths…");
  const rootHtml = await runPassiveScan(url, host, hostname, headers, result, emit);

  // RED TEAM active fuzzing (SQLi/XSS/cmd-injection/SSRF, incl. blind OOB).
  // Gated behind verified domain ownership. See server/redTeamProbes.ts.
  if (allowActiveProbes) emit?.("system", "Active red-team probes — firing real exploit payloads at the target…");
  result.redTeamFindings = allowActiveProbes
    ? await runRedTeamProbes(url, headers, { oob: opts.oob, scanId: opts.scanId, emit })
    : [];

  // API SECURITY active probes (GraphQL introspection, exposed user object,
  // two-identity BOLA). Gated behind ownership. See server/apiProbes.ts.
  if (allowActiveProbes) emit?.("system", "API security probes — GraphQL introspection, exposed objects, BOLA/IDOR…");
  result.apiSecFindings = allowActiveProbes
    ? await runApiSecProbes(url, host, headers, { bolaIdentities: opts.bolaIdentities })
    : [];
  if (allowActiveProbes && emit) {
    for (const f of result.apiSecFindings || []) {
      emit("result", `✓ CONFIRMED: ${f.testName} [${f.severity.toUpperCase()}] — ${f.endpoint}`);
    }
  }

  // JWT auth-weakness probe runs AFTER the crawl below (it can use a signing
  // secret the crawl discovers in a leaked file, e.g. a served .env) — see
  // the crawl.captures loop.
  if (allowActiveProbes) {
    // DOM-based XSS (headless-browser execution proof). No-ops unless
    // ENABLE_BROWSER_RENDERING is set; non-mutating, so gated on ownership only.
    try {
      const domFinding = await probeDomXss(url, headers);
      if (domFinding) result.redTeamFindings = [...(result.redTeamFindings || []), domFinding];
    } catch (e) {
      console.warn("DOM-XSS probe encountered an error", e);
    }
  }

  // AGGRESSIVE tier (opt-in, more invasive): SSTI, LFI/path-traversal, open
  // redirect, CRLF, CORS, out-of-band XXE, NoSQL injection. Non-destructive and
  // signature/OOB-proven. Appended to the red-team findings so they share the
  // RED_TEAM category, PROVEN-receipt scoring, and the report/fix-prompt pipeline.
  if (allowAggressiveProbes) {
    emit?.("system", "Aggressive tier — SSTI, LFI, XXE, CORS, CRLF, open-redirect, NoSQL, host-header…");
    const aggressive = await runAggressiveProbes(url, headers, { oob: opts.oob, scanId: opts.scanId, emit });
    result.redTeamFindings = [...(result.redTeamFindings || []), ...aggressive];
  }

  // --- CRAWL + DISCOVERED-PARAMETER FUZZING ---
  // Map the real attack surface (links, forms, JS-referenced endpoints) and aim
  // the injection probes at the parameters the application actually uses, rather
  // than only a few hardcoded names. Strictly bounded by page/request/time caps.
  try {
    if (rootHtml && result.responseStatus > 0) {
      emit?.("system", "Crawling to map the attack surface (links, forms, JS-referenced endpoints)…");
      const crawl = await crawlSite(url, authedFetch, {
        maxPages: 10,
        maxDepth: 2,
        budgetMs: 15000,
        seedHtml: rootHtml,
      });

      // Extend secret-signature + cookie-flag analysis beyond the root
      // document to every page the crawler actually visited, HTML or not —
      // e.g. a JSON API endpoint (like /api/settings) that hardcodes secrets
      // in its response, or a cookie set by a page other than the root.
      // Deduped so the same secret/cookie found via multiple pages isn't
      // repeated in the report.
      const seenSecretKeys = new Set(result.sastFindings.map((f) => `${f.issue}|${f.file}`));
      const isHttpsTarget = url.startsWith("https://");
      for (const capture of crawl.captures) {
        for (const sf of analyzeSecrets(capture.text, capture.url)) {
          const key = `${sf.issue}|${sf.file}`;
          if (seenSecretKeys.has(key)) continue;
          seenSecretKeys.add(key);
          result.sastFindings.push(sf);
        }
        for (const df of analyzeDataDumpExposure(capture.text, capture.url)) {
          const key = `${df.issue}|${df.file}`;
          if (seenSecretKeys.has(key)) continue;
          seenSecretKeys.add(key);
          result.sastFindings.push(df);
        }
        for (const issue of cookieFlagIssues(capture.setCookie, isHttpsTarget, result.cookieIssues.length)) {
          if (!result.cookieIssues.includes(issue)) result.cookieIssues.push(issue);
        }
        // Passive — no new request, just inspecting what the crawler already
        // fetched — so this runs unconditionally like the checks above, not
        // gated behind allowActiveProbes (unlike the fixed-path exposed-
        // user-object probe in apiProbes.ts, which makes its own requests).
        for (const capFinding of [
          exposedUserListInCapture(capture.text, capture.url),
          exposedCredentialListInCapture(capture.text, capture.url),
        ]) {
          if (!capFinding) continue;
          const key = `${capFinding.testName}|${capFinding.endpoint}`;
          if (!(result.apiSecFindings || []).some((f) => `${f.testName}|${f.endpoint}` === key)) {
            result.apiSecFindings = [...(result.apiSecFindings || []), capFinding];
          }
        }
      }

      // Every response body this scan has actually seen the text of, for the
      // two content-correlation checks below — NOT just crawl.captures,
      // which only covers pages the crawler itself fetched while following
      // links. The root document is SEEDED into the crawler (never
      // "fetched" by it, so it's absent from captures) and a sensitive-path
      // hit like /.env is fetched by server/perimeter.ts entirely separately
      // from the crawl. Missing either source means missing exactly the
      // cases these checks exist for (a key declared on the homepage itself;
      // a secret leaked via sensitive-path probing rather than a crawled
      // link) — confirmed by a real miss against the Tier 3 fixture before
      // this was added.
      const allScannedText = [
        rootHtml,
        ...crawl.captures.map((c) => c.text),
        ...result.probedPaths.map((p) => p.body).filter((b): b is string => !!b),
      ];

      // Cross-origin credential chaining: a client-side key paired with the
      // URL it's for (both disclosed in the SAME served content) is tested
      // against that OTHER origin — the only probe in this codebase that
      // ever calls back to somewhere other than the scanned target. The
      // target origin is one the scanned app's own content named, not a
      // guess, and reuses safeFetch's existing SSRF gate unchanged. Gated
      // behind ownership like the other active probes.
      if (allowActiveProbes) {
        const urlKeyPairs = allScannedText.flatMap((t) => extractUrlKeyPairs(t));
        if (urlKeyPairs.length) {
          try {
            const chainFinding = await probeCredentialUrlPairs(urlKeyPairs);
            if (chainFinding) result.apiSecFindings = [...(result.apiSecFindings || []), chainFinding];
          } catch (e) {
            console.warn("Credential-chain probe encountered an error", e);
          }
        }
      }

      // Edge Function auth-bypass: extract any Edge/serverless function URL the
      // scanned app's own content references (a .../functions/v1/<name> ref or a
      // functions.invoke('<name>') call + a discovered base URL) and prove it
      // accepts a forged token where no token is denied. Read-only (GET), like
      // the JWT probe; the function origin is one the app named, not a guess.
      if (allowActiveProbes) {
        try {
          const edgeFinding = await probeEdgeFunctionAuth(allScannedText, headers);
          if (edgeFinding) result.redTeamFindings = [...(result.redTeamFindings || []), edgeFinding];
        } catch (e) {
          console.warn("Edge Function auth probe encountered an error", e);
        }
      }

      // JWT auth-weakness probe. Delayed until after the crawl above so it
      // can also try re-signing with any JWT signing secret the crawl found
      // leaked in a served file (e.g. .env) — a validly-signed forged token
      // is a materially stronger proof than the alg:none/tampered-signature
      // forgeries alone (see extractJwtSecretCandidates in jwtProbe.ts).
      if (allowActiveProbes) {
        const secretCandidates = [
          ...new Set(allScannedText.flatMap((t) => extractJwtSecretCandidates(t))),
        ];
        try {
          const jwtFinding = await probeJwtAuth(
            url,
            headers,
            secretCandidates,
            crawl.captures.map((c) => c.url),
          );
          if (jwtFinding) result.redTeamFindings = [...(result.redTeamFindings || []), jwtFinding];
        } catch (e) {
          console.warn("JWT auth probe encountered an error", e);
        }
      }

      // Locale-route auth bypass: unlike the checks above this makes NEW
      // requests (a locale-swapped sibling of each discovered /en//es/ path),
      // so it's gated behind verified ownership like the other active probes,
      // even though it's read-only. Every URL the crawl fetched at all (not
      // just ones that became "pages") is a candidate, since a 401/403 JSON
      // response never becomes a page but is exactly the gated half of the
      // differential this needs.
      if (allowActiveProbes) {
        try {
          const i18nFinding = await probeI18nAuthBypass(
            url,
            crawl.captures.map((c) => c.url),
            { ...headers, "Cache-Control": "no-cache" },
          );
          if (i18nFinding) result.redTeamFindings = [...(result.redTeamFindings || []), i18nFinding];
        } catch (e) {
          console.warn("i18n auth-bypass probe encountered an error", e);
        }
      }

      // Server-side prototype pollution (AGGRESSIVE tier). Needs discovered POST
      // endpoints, so it runs here (after the crawl) rather than in the root-only
      // aggressive orchestrator above. It POSTs a benign body then the "json
      // spaces" gadget and proves pollution via a response-formatting flip — the
      // one probe that leaves a transient (cosmetic, self-healing) trace, so it's
      // gated behind the aggressive+ownership tier and reverts the gadget on a hit.
      if (allowAggressiveProbes) {
        const postUrls = [
          ...new Set(crawl.targets.filter((t) => t.method === "POST").map((t) => t.url)),
        ];
        try {
          const ppFinding = await probePrototypePollution(url, postUrls, { ...headers, "Cache-Control": "no-cache" });
          if (ppFinding) result.redTeamFindings = [...(result.redTeamFindings || []), ppFinding];
        } catch (e) {
          console.warn("prototype-pollution probe encountered an error", e);
        }

        // Business-logic price tampering (client-controlled price honored). Sends
        // only line items — no payment instrument, no confirmation — so it can
        // elicit at most a quote/total, never a real charge. Same aggressive+owned
        // gate + discovered-POST-target set as the prototype-pollution probe.
        try {
          const priceFinding = await probePriceManipulation(url, postUrls, { ...headers, "Cache-Control": "no-cache" });
          if (priceFinding) result.redTeamFindings = [...(result.redTeamFindings || []), priceFinding];
        } catch (e) {
          console.warn("price-manipulation probe encountered an error", e);
        }

        // Webhook signature-verification bypass. Sends only a zero-amount
        // FAILURE event for a nonexistent entity, so acceptance processes nothing
        // of value — proving the (conditional) signature skip without a real
        // payment side effect. Same aggressive+owned gate + discovered-POST set.
        try {
          const webhookFinding = await probeWebhookSignatureBypass(url, postUrls, { ...headers, "Cache-Control": "no-cache" });
          if (webhookFinding) result.redTeamFindings = [...(result.redTeamFindings || []), webhookFinding];
        } catch (e) {
          console.warn("webhook-signature probe encountered an error", e);
        }

        // Missing rate-limit on OTP/2FA verification. Observational (absence of a
        // control) → reported at MEDIUM confidence, never PROVEN. A small bounded
        // burst of wrong codes; bails the instant any throttle signal appears.
        try {
          const rlFinding = await probeAuthRateLimit(url, postUrls, { ...headers, "Cache-Control": "no-cache" });
          if (rlFinding) result.redTeamFindings = [...(result.redTeamFindings || []), rlFinding];
        } catch (e) {
          console.warn("auth-rate-limit probe encountered an error", e);
        }
      }

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

      // Weak-session-token probe: only runs when the caller explicitly supplied
      // real login credentials for a target they own (never guessed) — logs in
      // ONCE against a discovered login-shaped form and tries to reproduce the
      // resulting token from common weak (seed, algorithm) recipes. Aggressive
      // tier, same trust bar as the other credentialed/mutating probes below.
      // Deliberately runs BEFORE discovered-parameter fuzzing: fuzzing hits
      // every discovered form (including this same login form) with many
      // payloads, which can exhaust a target's own login rate limiter before
      // this probe's one legitimate login gets a turn — so it goes first.
      if (allowAggressiveProbes && opts.loginCredentials) {
        const loginTarget = findLoginTarget(allTargets);
        if (loginTarget) {
          emit?.("system", `Testing session token strength via ${loginTarget.url}…`);
          try {
            const weakToken = await probeWeakSessionToken(loginTarget, opts.loginCredentials, { ...headers, "Cache-Control": "no-cache" });
            if (weakToken) result.redTeamFindings = [...(result.redTeamFindings || []), weakToken];
          } catch (e) {
            console.warn("Weak session-token probe encountered an error", e);
          }
        }
      }

      // Mapping (crawl) is always allowed — it's passive same-origin GETs.
      // Fuzzing the discovered parameters is an active exploit attempt, so it
      // is gated behind verified domain ownership like the other red-team probes.
      let fuzz = { findings: [] as any[], paramsTested: 0, captures: [] as FuzzCapture[] };
      if (allowActiveProbes) {
        // Fuzz both GET query parameters and POST form fields the crawler mapped.
        // The fuzzer sends each payload with the target's own method (query string
        // for GET, form-encoded body for POST), so discovered forms are no longer
        // mapped-but-skipped.
        const discovered = allTargets.filter((t) => t.params.length > 0);

        // Parameter MINING: on the root and any crawled pages that linked no
        // parameters, guess common injectable names and keep the ones the app
        // reflects (plus a small always-test set), so injection probing reaches a
        // surface even on SPAs / JSON APIs that link or form nothing — the case
        // where the crawl otherwise yields zero fuzzable parameters. See
        // server/paramMiner.ts.
        const pathOf = (u: string) => { try { const p = new URL(u); return p.origin + p.pathname; } catch { return u; } };
        const paramPaths = new Set(discovered.map((t) => pathOf(t.url)));
        const mineBases = [url, ...crawl.pages].filter((p) => !paramPaths.has(pathOf(p)));
        emit?.("system", "Parameter mining: guessing common injectable parameter names on paths that linked none…");
        const guessed = await buildGuessedTargets(mineBases, { ...headers, "Cache-Control": "no-cache" });
        if (guessed.length) {
          const total = guessed.reduce((n, g) => n + g.params.length, 0);
          emit?.("recon", `Parameter mining: ${guessed.length} path(s), ${total} candidate parameter(s) to fuzz.`);
        }

        // API-first testing: discover an OpenAPI/Swagger spec and fuzz every
        // DECLARED operation's parameters — the full API surface, not just what
        // the crawl referenced. GET operations (reads) run here under active
        // probing; POST operations (which can create state) are held to the
        // aggressive opt-in, the same non-destructive line the rest of the fuzzer
        // draws. Same-origin only, via the SSRF-guarded authedFetch.
        let apiTargets: InjectableTarget[] = [];
        try {
          const api = await discoverAndParseApi(url, authedFetch, {
            explicitUrl: opts.apiSchemaUrl,
            includePost: allowAggressiveProbes,
          });
          if (api) {
            apiTargets = api.targets;
            let specPath = api.specUrl;
            try { specPath = new URL(api.specUrl).pathname; } catch { /* keep full */ }
            emit?.("recon", `API schema: ${api.format} at ${specPath} — ${api.operationCount} declared operation(s) queued for fuzzing.`);
          }
        } catch (e) {
          console.warn("API-schema discovery encountered an error", e);
        }

        // Fuzz discovered + mined + schema-declared parameters. Add a JSON-body
        // twin for API-looking endpoints so injection is exercised over
        // application/json, not only form-encoded bodies (many APIs accept only JSON).
        let fuzzTargets = dedupeTargets([...discovered, ...guessed, ...apiTargets]);
        const apiRe = /\/(api|graphql|rest|v\d)(\/|$)/i;
        const jsonTwins = fuzzTargets
          .filter((t) => apiRe.test(pathOf(t.url)))
          .map((t) => ({ url: t.url, method: "POST" as const, params: t.params, source: "script" as const, contentType: "json" as const }));
        fuzzTargets = [...fuzzTargets, ...jsonTwins];

        if (fuzzTargets.length) emit?.("system", `Fuzzing ${fuzzTargets.length} parameterized endpoint(s) (discovered + mined) with injection payloads…`);
        fuzz = await fuzzDiscoveredTargets(fuzzTargets, { ...headers, "Cache-Control": "no-cache" }, { aggressive: allowAggressiveProbes, emit });
        result.redTeamFindings = [...(result.redTeamFindings || []), ...fuzz.findings];

        // Fuzzing is the only pass that ever POSTs to these endpoints, so it's
        // the only place a JSON response like a password-reset token is ever
        // seen — scan every response it captured for weak/low-entropy security
        // tokens the app put in its own body (see weakTokenScan.ts).
        for (const capture of fuzz.captures) {
          for (const wf of weakTokenFindings(capture.text, capture.url)) {
            const key = `${wf.issue}|${wf.file}`;
            if (seenSecretKeys.has(key)) continue;
            seenSecretKeys.add(key);
            result.sastFindings.push(wf);
          }
        }
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
      emit?.("recon", `Surface mapped: ${crawl.pagesVisited} page(s), ${allTargets.length} endpoint(s), ${fuzz.paramsTested} parameter(s) fuzzed.`);
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
      templatesRun = selected.length;
      result.templateFindings = await runTemplates(host, authedFetch, selected, 6);
    }
  } catch (tplErr) {
    console.warn("Template detection stage encountered an error", tplErr);
  }

  // Full-transparency coverage record: exactly which check groups ran against
  // this target and how many discrete checks each fired.
  result.coverage = buildScanCoverage({
    activeProbesRun: allowActiveProbes,
    aggressiveProbesRun: allowAggressiveProbes,
    subdomainsChecked: result.easmPerimeter.subdomains.length,
    pathsProbed: result.probedPaths.length,
    templatesRun,
    crawlPages: result.crawl?.pagesVisited ?? 0,
    paramsFuzzed: result.crawl?.paramsTested ?? 0,
    domXssRun: allowActiveProbes && isRenderingEnabled(),
  });

  return result;
}
