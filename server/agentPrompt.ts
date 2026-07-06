import { Finding, Severity } from "../src/types.js";

// Builds the "hand this to your AI coding agent" prompt for a finding. Shared
// by the static compiler (server/scanner.ts, used whenever DeepSeek is not
// configured or a given finding doesn't come back with its own prompt) and
// the DeepSeek report generator (server/deepseek.ts, which asks the model to
// write a sharper one but falls back to this if it omits it). Deliberately
// generic/agent-actionable — the scanner is black-box and never sees the
// user's actual source, so the prompt describes what to search for and how
// to verify the fix rather than naming a specific file.
export function buildAgentPrompt(
  finding: Pick<Finding, "title" | "description" | "fix" | "category" | "owasp"> & { endpoint?: string },
  targetUrl: string,
): string {
  const lines = [
    `Fix this security finding from a Seclayer scan of ${targetUrl}: "${finding.title}"`,
    "",
    `Category: ${finding.category}${finding.owasp ? ` (OWASP ${finding.owasp})` : ""}`,
  ];
  if (finding.endpoint) lines.push(`Affected endpoint: ${finding.endpoint}`);
  lines.push(
    "",
    "What was found:",
    finding.description,
    "",
    "Do the following:",
    "1. Search the codebase for the code path handling this behavior/endpoint.",
    "2. Confirm the finding actually applies here (rule out a false positive).",
    `3. Apply this fix: ${finding.fix}`,
    "4. Add or update a regression test that would catch this issue if it reappears.",
    "5. Re-run the affected request (or re-run the Seclayer scan) to confirm it's resolved.",
  );
  return lines.join("\n");
}

// Local (non-AI) fallback for the plain-English "if exploited, then..." line.
// DeepSeek is asked to write a sharper, finding-specific version of this.
const IMPACT_BY_SEVERITY: Record<Severity, string> = {
  critical: "If exploited, this typically leads to full compromise: data exfiltration, account takeover, or remote code execution.",
  high: "If exploited, this can expose sensitive data or grant an attacker unauthorized access or control.",
  medium: "If exploited, this weakens the site's defenses and can be chained with other issues to greater effect.",
  low: "Low direct risk on its own, but it removes a defensive layer and is worth closing.",
  info: "Informational — no direct exploit risk, included for completeness.",
};

export function buildImpactFallback(severity: Severity): string {
  return IMPACT_BY_SEVERITY[severity] ?? IMPACT_BY_SEVERITY.info;
}
