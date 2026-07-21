// Builds the deep-report prompt handed to deepseek-v4-pro. Isolated from the
// call/parse orchestration so the (long, carefully-worded) instruction text —
// false-positive filtering rules, the strict JSON schema, the active-probe
// gating language — can be read and tuned on its own.
import { Finding, Severity } from "../src/types.js";

export function buildReportPrompt(
  url: string,
  diagnostics: any,
  staticCompiled: { score: number; severity: Severity; findings: Finding[] },
): string {
  const findingsSummaryText = staticCompiled.findings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description} (Fix: ${f.fix})`).join("\n");
  const techContext = diagnostics.techLeaked?.length ? diagnostics.techLeaked.join(", ") : "no framework/server signature leaked";
  const activeProbesSkipped = !!diagnostics.activeProbesSkipped;
  // Summarize the sensitive-path probe outcomes so the model treats a
  // locked-down path (403/404) as a PASS, not a finding.
  const lockedDownPaths = (diagnostics.probedPaths || []).filter((p: any) => !p.exposed).map((p: any) => p.path);
  const exposedPaths = (diagnostics.probedPaths || []).filter((p: any) => p.exposed).map((p: any) => p.path);

  return `You are Seclayer's automated penetration testing AI, reviewing a completed black-box scan
before it ships to a developer as their audit report. Think through the evidence carefully — this
report is what the developer's team will act on directly, including handing pieces of it straight
to an AI coding agent (Cursor, Claude Code, Windsurf) to implement the fixes.

Analyze the following black-box scanner diagnostics for target web url: "${url}" and the compiled issues listed below.
Generate a structured penetration testing report output in JSON format.

DIAGNOSTIC DATA:
Response Status Code: ${diagnostics.responseStatus}
SSL Encryption Active: ${diagnostics.sslSecure}
Missing Essential Defensive Security Headers (observed absent on the scanned response; may be served conditionally elsewhere): ${diagnostics.missingHeaders.join(", ") || "none"}
Technology Framework Signature Leaks: ${techContext}
Sensitive paths that are LOCKED DOWN (403/404 — these are PASSES, not issues): ${lockedDownPaths.join(", ") || "none"}
Sensitive paths CONFIRMED EXPOSED (real findings): ${exposedPaths.join(", ") || "none"}
Cookie Configuration Flags: ${JSON.stringify(diagnostics.cookieIssues)}
Active Exploitation Testing (SQLi / XSS / command-injection / SSRF / GraphQL / BOLA): ${activeProbesSkipped ? "NOT PERFORMED — domain ownership was not verified, so ONLY passive recon ran. No active exploit probe fired against this target." : "performed against the target"}

DETECTED ISSUES:
${findingsSummaryText}

FALSE POSITIVE FILTERING (CRITICAL):
- Aggressively filter out noise, theoretical vulnerabilities, and duplicate findings.
- Sensitive paths that returned 403/404 (e.g. /.env, /.git/config, /admin) are PASSES — the target is correctly locked down. NEVER report them as findings; they are positive signals of good hygiene, not issues.
- Missing security headers (CSP, HSTS, X-Frame-Options) are defense-in-depth GAPS, not exploitable vulnerabilities on their own. Rate them "medium" at most, and "low" (or omit) when the rest of the surface is well-hardened. NEVER rate a missing header "high" or "critical". Large, well-run sites also sometimes serve these headers only on certain routes, so do not over-state confidence that they are truly absent.
- Consolidate multiple similar issues into a single actionable finding.
- Do NOT hallucinate vulnerabilities that are not supported by the DIAGNOSTIC DATA or DETECTED ISSUES.
${activeProbesSkipped ? '- ACTIVE EXPLOITATION DID NOT RUN. You MUST NOT emit any finding in the "RED_TEAM" category, MUST NOT claim any injection/XSS/SSRF/command-injection/BOLA/GraphQL vulnerability was found or tested, and MUST NOT present these pillars as having results. It is correct and expected that active probing was skipped for an unverified domain — describe it as a scan-coverage note (info severity, DAST category) at most, not a vulnerability.' : "- Only report active-exploitation findings that the probes actually confirmed via a real signature match."}

Please return a JSON object containing exactly these keys:
1. "aiSummary": A direct, plain-English, professional executive summary paragraph (3-5 sentences) summarizing overall posture, potential risks, and urgency level. Speak with the authority of an active principal cybersecurity assessor. Do NOT use fake placeholders like "example.com", you MUST explicitly mention the target url "${url}" in your summary. Do NOT use markdown links.
2. "adjustedScore": An integer safety score from 0 to 100 based on the severity of the findings (e.g. critical items lower score near 10-30, high items live around 40-60, clean sites get 90+).
3. "executiveBreakdown": A detailed, multi-part breakdown for a developer/engineering-lead audience — this is the DEEP report, not a repeat of "aiSummary". Object with exactly these fields:
   - "overview": 2-4 sentences of context on what was tested and the overall posture story (not identical wording to "aiSummary").
   - "riskAreas": an array of 3-6 objects, each { "area": short theme name (e.g. "Injection & Input Validation", "Transport & Perimeter Security", "Attack Surface Exposure", "Dependency Hygiene"), "detail": 1-2 sentences on what was actually found in that theme for "${url}" and why it matters }. Group the DETECTED ISSUES into these themes yourself — don't just restate each finding 1:1.
   - "businessImpact": 2-3 sentences framing the real-world consequence in business terms (data exposure, downtime, reputational/compliance risk, financial cost) if the current issues go unaddressed.
   - "priorityActions": an array of 3-6 short, ranked, imperative action items (most urgent first) a team should do this week — concrete engineering tasks, not vague advice.
4. "findings": An array corresponding to the detected issues, rewritten with clearer titles/descriptions of how an attacker would exploit the issue. Each item MUST have exactly these fields:
   - "title": short, specific vulnerability name.
   - "description": how an attacker would actually exploit this against "${url}".
   - "severity": one of "info", "low", "medium", "high", "critical".
   - "category": strictly one of "DAST", "SAST", "IAST", "SCA", "EASM", "RED_TEAM".
   - "fix": exactly how a developer would remediate this — concrete, and tailored to the detected stack (${techContext}) where that narrows it down.
   - "impact": one plain-English sentence on the real-world consequence if this is exploited (data/access/business impact) — do not just restate the description.
   - "agentPrompt": a ready-to-paste, numbered instruction block a developer could hand directly to their own AI coding agent (Cursor, Claude Code, etc.) to locate this exact issue in their codebase and fix it. Reference the detected stack (${techContext}) if it narrows down where to look, name the vulnerable pattern to search for, the concrete secure replacement, and a verification step. Write it as a clean, self-contained engineering instruction — do not mention Seclayer, "the scan", or this report inside the prompt text itself.
   Replace any generic placeholder domains (like example.com) with the real target "${url}".

Ensure the returned output is strictly valid JSON compliant with the required structure.`;
}
