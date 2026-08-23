// Diagnostics → findings compilation. Turns the raw DiagnosticResult produced by
// runDiagnostics into the scored, deduped, OWASP-tagged Finding[] the report
// renders, and distils the compact ScanEvidence panel. Kept separate from the
// probe pipeline so the "what did we find" transform can evolve (and be tested)
// independently of "how did we probe".
//
// compileStaticFindings is an ordered pipeline of small per-category builders.
// Order matters: the final dedupe-by-title keeps the FIRST occurrence, so the
// concatenation order below is the precedence order.
import type { DiagnosticResult } from "./scanner.js";
import { Finding, Severity, ScanEvidence } from "../src/types.js";
import { scoreFindings } from "./scoring.js";
import { classifyCookie } from "./cookieClassify.js";
import { mapOwasp } from "./owasp.js";
import { buildAgentPrompt, buildImpactFallback } from "./agentPrompt.js";
import crypto from "crypto";

// Every finding carries a random id; red-team/API findings namespace theirs.
function fid(prefix = "f_"): string {
  return prefix + crypto.randomBytes(4).toString("hex");
}

// Transparency: a plain-English statement of HOW a finding was confirmed, so a
// reader can weigh the basis behind the verdict. Prefers the strongest evidence
// available (a replayable exploit receipt), then falls back to the detection
// method for the finding's category. Applied as a guaranteed default in the
// compile loop; a specific builder may set its own note to override this.
function verificationNote(f: Finding): string {
  if (f.evidence) {
    return "Confirmed by active exploitation — a request/response receipt was captured and is replayable (see evidence).";
  }
  if (f.severity === "info") {
    return "Informational scan-coverage context — not a detected vulnerability.";
  }
  switch (f.category) {
    case "SAST":
      return "Signature match in the client-served markup, screened against known placeholder/example credentials.";
    case "SCA":
      return "Version identified in a script/link resource the page loads, matched to a known-vulnerable range.";
    case "IAST":
      return "Observed directly from the response headers and cookie attributes on the scanned URL.";
    case "EASM":
      return "Observed from the target's response headers and TLS state.";
    case "DAST":
      return "Confirmed by fetching the path and matching the file's signature in the response body — not a status code alone.";
    case "RED_TEAM":
    case "API_SEC":
      return "Detected by an active exploit probe against the target.";
    default:
      return "Derived from the scan diagnostics.";
  }
}

// 0. Surface mapping + skipped-probe notices (informational, zero score impact).
function buildSurfaceFindings(diag: DiagnosticResult): Finding[] {
  const findings: Finding[] = [];
  if (diag.crawl && (diag.crawl.pagesVisited > 1 || diag.crawl.endpointsDiscovered > 0)) {
    const c = diag.crawl;
    findings.push({
      id: fid(),
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
      id: fid(),
      title: "Active Exploit Probing Skipped (Unverified Target)",
      description: "SQL injection, XSS, command-injection, SSRF, GraphQL and BOLA exploit attempts were not run against this target because domain ownership has not been verified. Passive recon (headers, TLS, DNS, exposed files, tech/library detection, and surface mapping) still ran in full.",
      severity: "info",
      confidence: "high",
      fix: "Verify ownership of this domain (DNS TXT record or well-known file, from the dashboard) to unlock active exploit testing on future scans of this target.",
      category: "DAST",
    });
  }
  return findings;
}

// 1. EASM (External Attack Surface Management): transport + framework signature.
function buildEasmFindings(diag: DiagnosticResult): Finding[] {
  const findings: Finding[] = [];
  if (!diag.sslSecure) {
    findings.push({
      id: fid(),
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
      id: fid(),
      // A Server / X-Powered-By banner is fingerprinting, not a weakness: nearly
      // every site discloses one, so scoring it as a LOW weakness fired on almost
      // every scan for no real risk. Reported as informational context (zero
      // score impact) — surfaced for hardening, never treated as a vulnerability.
      title: "Verbose Server Framework Signature Leaked",
      description: `The attack surface assessment detected visible framework signatures leaked in response headers: ${diag.techLeaked.join(", ")}. This is a fingerprinting/hardening note, not an exploitable weakness — automated bots use these patterns to locate systems, but the banner itself grants no access.`,
      severity: "info",
      confidence: "high",
      fix: "Optional hardening: suppress the Server / X-Powered-By response headers at the web server or reverse proxy so the stack isn't advertised.",
      category: "EASM",
    });
  }
  return findings;
}

// 2. IAST (defensive response headers). Missing security headers are
// defense-in-depth GAPS, not confirmed vulnerabilities — a black-box GET can
// also miss headers a site serves conditionally (per-route, per-User-Agent).
// Reported at medium/medium so a possibly-absent header never dominates a report
// as "high" on an otherwise well-hardened target.
function buildHeaderFindings(diag: DiagnosticResult): Finding[] {
  const findings: Finding[] = [];
  if (diag.missingHeaders.includes("content-security-policy")) {
    findings.push({
      id: fid(),
      title: "Missing Content-Security-Policy (CSP)",
      description:
        "No Content-Security-Policy header was observed on the scanned response. CSP is a defense-in-depth control that constrains where scripts and other resources may load from, reducing the blast radius of any cross-site scripting (XSS) flaw. Its absence is not itself an exploitable vulnerability.",
      severity: "medium",
      confidence: "medium",
      fix: "Deploy restrictive CSP header directives like \"Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-origin.com\".",
      category: "IAST",
    });
  }

  // HSTS is only meaningful over HTTPS. On a plaintext-HTTP target the absence of
  // HSTS is both redundant with the "Insecure Connection Protocol (HTTP)" finding
  // above and not independently actionable (you fix it by adding TLS, not the
  // header), so flagging it here would be double-counted noise.
  if (diag.sslSecure && diag.missingHeaders.includes("strict-transport-security")) {
    findings.push({
      id: fid(),
      title: "Missing Strict-Transport-Security (HSTS) Policy",
      description:
        "No HTTP Strict-Transport-Security (HSTS) header was observed on the scanned response. HSTS instructs browsers to only ever connect over HTTPS, mitigating protocol-downgrade and SSL-stripping attacks. Note that large sites sometimes serve this header only on specific routes, so confirm against a browser before treating it as absent.",
      severity: "medium",
      confidence: "medium",
      fix: 'Transmit the header: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" over all HTTPS targets.',
      category: "IAST",
    });
  }

  // CSP frame-ancestors is the modern replacement for X-Frame-Options. When it
  // is present, the page IS protected against framing, so flagging a missing
  // X-Frame-Options header would be a false positive — and would directly
  // contradict this finding's own text ("X-Frame-Options or CSP frame-ancestors").
  // Only report clickjacking exposure when NEITHER control is in place.
  const cspHasFrameAncestors = /frame-ancestors/i.test(diag.headers["content-security-policy"] || "");
  if (diag.missingHeaders.includes("x-frame-options") && !cspHasFrameAncestors) {
    findings.push({
      id: fid(),
      title: "Missing X-Frame-Options / Clickjacking Immunity",
      description:
        "No anti-framing instruction (X-Frame-Options or CSP frame-ancestors) was observed on the scanned response. Without it, an attacker can frame the page inside a transparent overlay to hijack clicks. Some sites rely on CSP frame-ancestors instead, so confirm before treating this as absent.",
      severity: "medium",
      confidence: "medium",
      fix: 'Enforce "X-Frame-Options: DENY" or deploy CSP "frame-ancestors \'none\'" instructions.',
      category: "IAST",
    });
  }
  return findings;
}

// 2b. Cookie hardening (IAST). Secure/HttpOnly attribute gaps, scored by what the
// cookie actually is (see cookieClassify.ts). A missing flag only carries real
// session-hijack risk on a session/auth cookie. On third-party analytics cookies
// and non-secret UX preference cookies the same "gap" is a false positive: they
// MUST be JS-readable, hold no secret, and (for analytics) are set by an embedded
// SDK, not this app. Flagging all of them at "medium" was inflating the score and
// firing FP noise — e.g. six locale/analytics cookies dragging an otherwise-clean
// site to the score floor. Genuine session cookies (and anything we can't
// confidently classify as non-session) still report at medium so nothing real is
// under-reported.
function buildCookieFindings(diag: DiagnosticResult): Finding[] {
  const findings: Finding[] = [];
  for (const issue of diag.cookieIssues) {
    const isSecureIssue = /secure attribute/i.test(issue);
    const name = issue.match(/"([^"]+)"/)?.[1] || "cookie";
    const cls = classifyCookie(name);

    // ZERO-FALSE-POSITIVE policy. A missing HttpOnly/Secure flag is only a real
    // risk on a cookie that could carry session/auth state. Third-party analytics
    // cookies and non-secret UX preference cookies (locale/currency/country/theme)
    // MUST be readable by client-side JavaScript, hold no secret, and are often
    // set by an embedded SDK rather than this app — the "gap" is a false positive.
    // We therefore DON'T EMIT a finding for them at all (previously they were shown
    // as low/suppressed, which still surfaced noise the user had to triage). Every
    // cookie we can't confidently classify as non-session ("session" or "unknown")
    // is still reported, so a genuine session-cookie gap is never missed.
    if (cls === "analytics" || cls === "preference") continue;

    // Confidence reflects how sure we are it's a real RISK, not just that the flag
    // is absent: a session-named cookie is high; an unclassifiable one is medium
    // (which damps its score impact) since we can't confirm it carries session
    // state — but we still report it rather than risk under-reporting a real one.
    const confidence: Finding["confidence"] = cls === "unknown" ? "medium" : "high";

    findings.push({
      id: fid(),
      title: issue,
      description: isSecureIssue
        ? `${issue}. A cookie without the Secure attribute can be transmitted over an unencrypted connection, where a network attacker could intercept it. If this cookie carries session or authentication state, that exposes the session to hijacking.`
        : `${issue}. A cookie without HttpOnly is readable by client-side JavaScript, so a cross-site scripting flaw elsewhere on the site could exfiltrate it. If this cookie carries session or authentication state, that raises the impact of any XSS to full session theft.`,
      severity: "medium",
      confidence,
      fix: isSecureIssue
        ? "Add the Secure attribute to this cookie so it is only ever sent over HTTPS."
        : "Add the HttpOnly attribute to this cookie unless it must be read by client-side JavaScript; if it must, keep the sensitive session token in a separate HttpOnly cookie.",
      category: "IAST",
    });
  }
  return findings;
}

// 3. SAST (static code security analysis) findings. `sf.file` is a URL for
// findings from a specific crawled page/endpoint (vs. the historical
// "Client-served HTML/JavaScript" label for the root document) — surfaced as
// `endpoint` so a reader can tell WHERE it leaked, not just that it did.
function buildSastFindings(diag: DiagnosticResult): Finding[] {
  return diag.sastFindings.map((sf) => ({
    id: fid(),
    title: sf.issue,
    description: sf.description,
    severity: sf.severity,
    confidence: sf.confidence,
    fix: sf.fix,
    category: "SAST",
    endpoint: /^https?:\/\//i.test(sf.file) ? sf.file : undefined,
  }));
}

// 4. SCA (software composition analysis) findings.
function buildScaFindings(diag: DiagnosticResult): Finding[] {
  return diag.scaLibraries.map((sca) => ({
    id: fid(),
    title: `Outdated Library Vulnerability Detected (${sca.name})`,
    description: sca.description,
    severity: sca.severity,
    confidence: "medium",
    fix: sca.fix,
    category: "SCA",
  }));
}

// 5. Exposed critical resource files discovered by dynamic path probing. A probe
// may carry its own `meta` (accurate title/severity/fix — e.g. supply-chain
// lockfiles are a LOW dependency-tree disclosure); otherwise the generic
// secret/VCS-file mapping (critical for .env/.git, else high) applies.
function buildExposedPathFindings(diag: DiagnosticResult): Finding[] {
  return diag.probedPaths
    .filter((p) => p.exposed)
    .map((exp) => {
      if (exp.meta) {
        return {
          id: fid(),
          title: exp.meta.title,
          description: exp.meta.description,
          severity: exp.meta.severity,
          confidence: "high" as const,
          fix: exp.meta.fix,
          category: "DAST" as const,
        };
      }
      return {
        id: fid(),
        title: `Exposed Critical Resource File (${exp.path})`,
        description: `Active Dynamic scanning discovered a public exposed configuration target at ${diag.url}${exp.path}. This file can be queried freely over the web, yielding secret metadata configurations.`,
        severity: (exp.path.includes(".env") || exp.path.includes(".git") ? "critical" : "high") as Severity,
        confidence: "high" as const,
        fix: `Immediately strip dynamic routes to ${exp.path} inside server rewrite engines or configure .htaccess rules to return 403 blocks.`,
        category: "DAST" as const,
      };
    });
}

// 6. Red-team active-fuzzing findings (each carries a PROVEN exploit receipt).
function buildRedTeamFindings(diag: DiagnosticResult): Finding[] {
  return (diag.redTeamFindings ?? []).map((rt) => ({
    id: fid("f_rt_"),
    title: rt.testName,
    description: rt.description,
    severity: rt.severity,
    confidence: rt.confidence ?? "high", // most probes prove it; an observational one can declare "medium"
    fix: rt.fix,
    category: "RED_TEAM",
    evidence: rt.evidence, // exploit receipt, when the probe captured one
  }));
}

// 7. API security testing findings.
function buildApiSecFindings(diag: DiagnosticResult): Finding[] {
  return (diag.apiSecFindings ?? []).map((api) => ({
    id: fid("f_api_"),
    title: api.testName,
    description: api.description,
    severity: api.severity,
    confidence: "high",
    fix: api.fix,
    category: "API_SEC",
    endpoint: api.endpoint,
    evidence: api.evidence, // exploit receipt, when the probe captured one
  }));
}

// Convert diagnostics into structured Category Findings
export function compileStaticFindings(diag: DiagnosticResult): {
  score: number;
  severity: Severity;
  findings: Finding[];
} {
  // Assembled in precedence order (first occurrence of a title wins the dedupe).
  const findings: Finding[] = [
    ...buildSurfaceFindings(diag),
    ...buildEasmFindings(diag),
    ...buildHeaderFindings(diag),
    ...buildCookieFindings(diag),
    ...buildSastFindings(diag),
    ...buildScaFindings(diag),
    ...buildExposedPathFindings(diag),
    ...buildRedTeamFindings(diag),
    ...buildApiSecFindings(diag),
    // Template engine findings (exposed panels, config/backup files, actuators).
    ...(diag.templateFindings ?? []),
  ];

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
    if (!f.verification) f.verification = verificationNote(f);
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

// Advisory (informational) headers: their absence is NOT treated as a defensive
// gap because the browser default is already safe — Referrer-Policy defaults to
// strict-origin-when-cross-origin. They're still shown as present/absent in the
// evidence panel for completeness, but they never become a scored finding and are
// excluded from the "essential headers missing" narrative. Same reasoning that
// omits SameSite from cookie flagging: no score impact, no false-positive noise.
export const ADVISORY_SECURITY_HEADERS = ["referrer-policy"];

// Splits observed-missing headers into the essential gaps (worth surfacing as
// defensive weaknesses) and the advisory ones (informational only).
export function splitMissingHeaders(missing: string[]): { essential: string[]; advisory: string[] } {
  const advisory = missing.filter((h) => ADVISORY_SECURITY_HEADERS.includes(h));
  const essential = missing.filter((h) => !ADVISORY_SECURITY_HEADERS.includes(h));
  return { essential, advisory };
}

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
    coverage: diag.coverage,
  };
}
