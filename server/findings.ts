// Diagnostics → findings compilation. Turns the raw DiagnosticResult produced by
// runDiagnostics into the scored, deduped, OWASP-tagged Finding[] the report
// renders, and distils the compact ScanEvidence panel. Kept separate from the
// probe pipeline so the "what did we find" transform can evolve (and be tested)
// independently of "how did we probe".
import type { DiagnosticResult } from "./scanner.js";
import { Finding, Severity, ScanEvidence } from "../src/types.js";
import { scoreFindings } from "./scoring.js";
import { mapOwasp } from "./owasp.js";
import { buildAgentPrompt, buildImpactFallback } from "./agentPrompt.js";
import crypto from "crypto";

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
        evidence: rt.evidence, // exploit receipt, when the probe captured one
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
        evidence: api.evidence, // exploit receipt, when the probe captured one
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
