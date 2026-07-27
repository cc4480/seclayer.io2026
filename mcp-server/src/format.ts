import type { Finding, ScanListSuccess, ScanReport, Severity } from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

function formatFinding(finding: Finding, index: number): string {
  const lines: string[] = [];
  lines.push(`### ${index + 1}. ${finding.title}  [${finding.severity.toUpperCase()}${finding.confidence ? ` · confidence: ${finding.confidence}` : ""}]`);

  const metaParts: string[] = [`Category: ${finding.category}`];
  if (finding.owasp) metaParts.push(`OWASP: ${finding.owasp}`);
  lines.push(metaParts.join("  ·  "));
  if (finding.endpoint) lines.push(`Endpoint: ${finding.endpoint}`);
  if (finding.evidence) lines.push(`_Proven — replayable exploit evidence captured._`);

  lines.push("");
  lines.push(finding.description);

  if (finding.impact) {
    lines.push("");
    lines.push(`**Impact:** ${finding.impact}`);
  }

  lines.push("");
  lines.push(`**Fix:** ${finding.fix}`);

  if (finding.agentPrompt) {
    lines.push("");
    lines.push("**Suggested agent prompt:**");
    lines.push(finding.agentPrompt);
  }

  return lines.join("\n");
}

// Pure — turns the backend's JSON report into a single Markdown text block.
// This IS the tool's result content: the product's whole pitch is that a
// finding's fix + agentPrompt is directly actionable by whatever coding agent
// receives this text next, so the report is rendered in full rather than
// summarized or left as raw JSON. Accepts either a freshly-run scan or a
// retrieved historical report (same shape) — the credit line shows only for a
// fresh scan, the date line only for a retrieved one.
export function formatScanReport(data: ScanReport): string {
  const lines: string[] = [];
  lines.push(`# Seclayer Security Scan — ${data.targetUrl}`);
  lines.push("");
  lines.push(`Posture score: ${data.postureScore}/100`);
  lines.push(`Severity: ${data.vulnerabilityLevel.toUpperCase()}`);
  if (data.creditsRemaining !== undefined) lines.push(`Credits remaining: ${data.creditsRemaining}`);
  if (data.completedAt) lines.push(`Scanned: ${data.completedAt}`);
  lines.push("");

  lines.push("## Summary");
  lines.push(data.analysisSummary);
  lines.push("");

  const eb = data.executiveBreakdown;
  if (eb) {
    lines.push("## Executive breakdown");
    lines.push(eb.overview);
    lines.push("");
    lines.push(`**Business impact:** ${eb.businessImpact}`);

    if (eb.riskAreas?.length) {
      lines.push("");
      lines.push("**Risk areas:**");
      for (const area of eb.riskAreas) lines.push(`- ${area.area}: ${area.detail}`);
    }

    if (eb.priorityActions?.length) {
      lines.push("");
      lines.push("**Priority actions:**");
      eb.priorityActions.forEach((action, i) => lines.push(`${i + 1}. ${action}`));
    }
    lines.push("");
  }

  const findings = data.securityFindings || [];
  lines.push(`## Findings (${findings.length})`);
  lines.push("");
  if (findings.length === 0) {
    lines.push("No findings were reported for this target.");
  } else {
    const sorted = sortBySeverity(findings);
    lines.push(sorted.map((f, i) => formatFinding(f, i)).join("\n\n---\n\n"));
  }

  return lines.join("\n");
}

// Pure — renders the compact scan-history list as a Markdown table an agent can
// scan to find the id of a report to fetch in full. Newest first (as returned).
export function formatScanList(data: ScanListSuccess): string {
  const scans = data.scans || [];
  if (scans.length === 0) {
    return "No scans found for this API key yet. Run one with the seclayer_scan tool.";
  }
  const lines: string[] = [];
  lines.push(`# Seclayer scan history (${scans.length})`);
  lines.push("");
  lines.push("| Scan ID | Target | Status | Score | Severity | Completed |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const s of scans) {
    const score = s.score == null ? "—" : `${s.score}/100`;
    const sev = s.severity ? s.severity.toUpperCase() : "—";
    lines.push(`| \`${s.id}\` | ${s.url} | ${s.status} | ${score} | ${sev} | ${s.completedAt || "—"} |`);
  }
  lines.push("");
  lines.push("Fetch any completed scan's full report with the seclayer_get_report tool, passing its Scan ID.");
  return lines.join("\n");
}
