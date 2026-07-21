// Deterministic, always-available report fallbacks. Every AI-authored field
// (summary, executive breakdown) degrades to one of these when DeepSeek isn't
// configured, the call fails, or — per-field, via sanitizeBreakdown — the model
// omits a piece. This is what keeps the product fully functional with no AI key:
// degraded polish, never degraded function.
import { Finding, Severity, ExecutiveBreakdown } from "../src/types.js";

type ScoredFindings = { score: number; severity: Severity; findings: Finding[] };

export function compileLocalSummary(url: string, sc: ScoredFindings): string {
  if (sc.severity === "critical" || sc.severity === "high") {
    return `Seclayer security scan for ${url} has identified several severe security perimeters leaks. Multiple high or critical level configuration issues have been detected, presenting actionable vectors for unauthorized access, data exposure, or client hijacking. Remediation of dotfile policies and deploying standard script isolation wrappers should be handled as an urgent engineering requirement to protect customer resources.`;
  }
  if (sc.severity === "medium") {
    return `Seclayer security assessment for ${url} indicates moderate vulnerability flags are present. Key defensive layers (including SSL redirection pipelines, XSS protection boundaries, or secure session cookie directives) are absent or require strict consolidation. While not presenting an immediate server compromise, hardening these perimeter checkpoints aligns with standard production guidelines.`;
  }
  return `Seclayer verification scanner reports that ${url} displays strong basic defensive hygiene. No critical system exposures or active data leaks were detected. To reach industry-leading status, minor improvements should be introduced to satisfy full HSTS preload targets and deploy advanced content routing headers.`;
}

// Deterministic executive breakdown built from the real compiled findings —
// used when DeepSeek isn't configured, the call fails, or (per-field, via
// sanitizeBreakdown) when the model omits a piece.
export function compileLocalBreakdown(url: string, sc: ScoredFindings): ExecutiveBreakdown {
  const active = sc.findings.filter((f) => !f.isFalsePositive);
  const byCategory = new Map<string, Finding[]>();
  for (const f of active) {
    const list = byCategory.get(f.category) || [];
    list.push(f);
    byCategory.set(f.category, list);
  }
  const categoryLabels: Record<string, string> = {
    SAST: "Static Code & Secrets Exposure", DAST: "Dynamic Exploit Surface", IAST: "Defensive Header & Session Policy",
    SCA: "Dependency Hygiene", EASM: "External Attack Surface", RED_TEAM: "Active Exploit Probes", API_SEC: "API Security",
  };
  const riskAreas = Array.from(byCategory.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 6)
    .map(([category, findings]) => ({
      area: categoryLabels[category] || category,
      detail: `${findings.length} finding(s), including "${findings[0].title}".`,
    }));

  const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const priorityActions = [...active]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity])
    .slice(0, 6)
    .map((f) => f.fix || f.title);

  return {
    overview: `Automated black-box assessment of ${url}: ${active.length} active finding(s) across ${byCategory.size} area(s), posture score ${sc.score}/100 (${sc.severity}).`,
    riskAreas: riskAreas.length > 0 ? riskAreas : [{ area: "General Hygiene", detail: "No active findings — baseline defensive posture looks clean." }],
    businessImpact: sc.severity === "critical" || sc.severity === "high"
      ? "Unaddressed, these issues create a realistic path to data exposure, account compromise, or service disruption — with attendant customer-trust and compliance fallout."
      : sc.severity === "medium"
        ? "Current gaps are unlikely to cause an immediate breach on their own but weaken defense-in-depth and could compound with future issues."
        : "No material business risk identified from this pass; continued monitoring is still recommended as the app evolves.",
    priorityActions: priorityActions.length > 0 ? priorityActions : ["No action required — no active findings this scan."],
  };
}

const MAX_RISK_AREAS = 6;
const MAX_PRIORITY_ACTIONS = 6;

// Defensively merges the model's executiveBreakdown with the local deterministic
// one, field by field — the model's JSON is free-form input and any field can be
// missing, wrong-shaped, or empty.
export function sanitizeBreakdown(raw: any, url: string, sc: ScoredFindings): ExecutiveBreakdown {
  const fallback = compileLocalBreakdown(url, sc);
  if (!raw || typeof raw !== "object") return fallback;

  const overview = typeof raw.overview === "string" && raw.overview.trim() ? raw.overview.trim() : fallback.overview;

  const riskAreas = Array.isArray(raw.riskAreas)
    ? raw.riskAreas
        .filter((r: any) => r && typeof r.area === "string" && r.area.trim() && typeof r.detail === "string" && r.detail.trim())
        .slice(0, MAX_RISK_AREAS)
        .map((r: any) => ({ area: r.area.trim(), detail: r.detail.trim() }))
    : [];

  const businessImpact = typeof raw.businessImpact === "string" && raw.businessImpact.trim()
    ? raw.businessImpact.trim()
    : fallback.businessImpact;

  const priorityActions = Array.isArray(raw.priorityActions)
    ? raw.priorityActions.map((a: unknown) => String(a).trim()).filter(Boolean).slice(0, MAX_PRIORITY_ACTIONS)
    : [];

  return {
    overview,
    riskAreas: riskAreas.length > 0 ? riskAreas : fallback.riskAreas,
    businessImpact,
    priorityActions: priorityActions.length > 0 ? priorityActions : fallback.priorityActions,
  };
}
