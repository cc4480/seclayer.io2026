import { Finding, Severity } from "../src/types.js";

// Single source of truth for posture scoring, shared by the scanner (initial
// score) and the suppression read-model (recalculated score). Keeping one set
// of weights here prevents the initial and recalculated scores from drifting.
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 35,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
};

// The worst possible site still reports a small non-zero score so the UI gauge
// renders sensibly; mirrors the previous floor used across the codebase.
export const SCORE_FLOOR = 10;

function normalizeSeverity(sev: string | undefined): Severity {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s;
  }
  return "info";
}

// Computes a 0-100 posture score and the highest active severity from a set of
// findings. Suppressed (false-positive) findings are excluded from both.
export function scoreFindings(findings: Finding[]): { score: number; severity: Severity } {
  const active = (findings || []).filter((f) => !f.isFalsePositive);

  let score = 100;
  for (const f of active) {
    score -= SEVERITY_WEIGHTS[normalizeSeverity(f.severity)];
  }
  score = Math.max(SCORE_FLOOR, Math.min(100, score));

  let severity: Severity = "info";
  if (active.some((f) => normalizeSeverity(f.severity) === "critical")) severity = "critical";
  else if (active.some((f) => normalizeSeverity(f.severity) === "high")) severity = "high";
  else if (active.some((f) => normalizeSeverity(f.severity) === "medium")) severity = "medium";
  else if (active.some((f) => normalizeSeverity(f.severity) === "low")) severity = "low";

  return { score, severity };
}
