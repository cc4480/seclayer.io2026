import { Finding, Severity } from "../src/types.js";

// SINGLE SOURCE OF TRUTH for posture scoring and risk labelling.
//
// Every consumer that needs a score, a grade, a posture rating, per-severity
// counts, or a risk label MUST derive it from this module — the scanner (initial
// score), the suppression read-model (recalculated score), AND the client report
// UI (executive score, pillar cards, warning banner, PDF export). Nothing may
// compute or label risk on its own; that independent labelling is exactly what
// let the executive score, the pillar counts, and the warning banner drift into
// contradicting each other for the same findings.
//
// This file is intentionally isomorphic: it imports only shared types, so both
// the Node server and the browser bundle import it unchanged.

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 35,
  high: 25,
  medium: 15,
  low: 5,
  // Informational findings still nudge the score below a perfect 100 so a scan
  // with any real findings can never present as a flawless "100/100 — no issues"
  // result next to a list of findings. The nudge is deliberately small so a
  // hardened site covered only in info notes still grades an A.
  info: 2,
};

// The worst possible site still reports a small non-zero score so the UI gauge
// renders sensibly; mirrors the previous floor used across the codebase.
export const SCORE_FLOOR = 10;

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function normalizeSeverity(sev: string | undefined): Severity {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s;
  }
  return "info";
}

// A finding is PROVEN when it carries a valid, replayable exploit receipt: an
// evidence bundle whose `signal.quote` actually appears verbatim in the stored
// `attack.response`. That substring check is the whole guarantee — we can never
// claim proof of a byte we didn't capture. PROVEN is the top truth-tier; the word
// only appears when the user can see the receipt.
export function isProven(finding: Pick<Finding, "evidence">): boolean {
  const ev = finding.evidence;
  if (!ev || !ev.attack || typeof ev.attack.response !== "string") return false;
  const quote = ev.signal?.quote;
  if (!quote) return false;
  return ev.attack.response.includes(quote);
}

// A finding is "Confirmed" when the engine is confident it is real: either it
// carries a PROVEN exploit receipt, or it was recorded as high-confidence (a
// probe-confirmed exploit, an observed cookie flag, an exposed file matched by
// body signature, etc.). Everything lower is heuristic and shown as DETECTED /
// "Needs Verification". Missing confidence is treated as confirmed so legacy
// findings keep their existing presentation. (Adding the PROVEN path is purely
// additive — it never demotes a finding that was already Confirmed.)
export function isConfirmed(finding: Pick<Finding, "confidence" | "evidence">): boolean {
  return isProven(finding) || finding.confidence === undefined || finding.confidence === "high";
}

// Letter grade derived from the numeric score. One mapping, used everywhere a
// grade is shown, so the letter can never disagree with the number beside it.
export type Grade = "A" | "B" | "C" | "D" | "F";
export function gradeForScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

// The one human risk label used by the executive score, the pillar cards, the
// per-module header and the PDF — keyed off severity, not off ad-hoc score
// thresholds, so a label can never contradict the posture rating.
export type RiskLabel = "SECURE" | "INFO" | "LOW RISK" | "MODERATE" | "HIGH RISK" | "CRITICAL";
export function riskLabelForSeverity(sev: Severity | null): RiskLabel {
  switch (sev) {
    case "critical": return "CRITICAL";
    case "high": return "HIGH RISK";
    case "medium": return "MODERATE";
    case "low": return "LOW RISK";
    case "info": return "INFO";
    default: return "SECURE";
  }
}

// Highest active (non-suppressed) severity across a set of findings, or null
// when there is nothing actionable.
export function highestSeverity(findings: Finding[]): Severity | null {
  const active = (findings || []).filter((f) => !f.isFalsePositive);
  let idx = -1;
  for (const f of active) {
    idx = Math.max(idx, SEVERITY_ORDER.indexOf(normalizeSeverity(f.severity)));
  }
  return idx >= 0 ? SEVERITY_ORDER[idx] : null;
}

export interface SecurityPosture {
  score: number;                  // 0-100
  grade: Grade;                   // letter grade for `score`
  severity: Severity;             // highest active severity ("info" when none)
  postureRating: RiskLabel;       // human label for `severity`
  findingsBySeverity: Record<Severity, number>; // active counts per severity
  activeCount: number;            // total non-suppressed findings
  confirmedCount: number;         // active findings that are probe-confirmed
  needsVerificationCount: number; // active heuristic findings
}

// THE derivation. Given a findings array, returns every risk figure the product
// displays, computed once and consistently. Suppressed (false-positive)
// findings are excluded from every figure.
export function deriveSecurityPosture(findings: Finding[]): SecurityPosture {
  const active = (findings || []).filter((f) => !f.isFalsePositive);

  let score = 100;
  const findingsBySeverity: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  let confirmedCount = 0;
  for (const f of active) {
    const sev = normalizeSeverity(f.severity);
    score -= SEVERITY_WEIGHTS[sev];
    findingsBySeverity[sev] += 1;
    if (isConfirmed(f)) confirmedCount += 1;
  }
  score = Math.round(Math.max(SCORE_FLOOR, Math.min(100, score)));

  const top = highestSeverity(active);

  return {
    score,
    grade: gradeForScore(score),
    severity: top ?? "info",
    postureRating: riskLabelForSeverity(top),
    findingsBySeverity,
    activeCount: active.length,
    confirmedCount,
    needsVerificationCount: active.length - confirmedCount,
  };
}

// Back-compat shim for the server callers that only need { score, severity }.
// Delegates to the single derivation so there is exactly one implementation.
export function scoreFindings(findings: Finding[]): { score: number; severity: Severity } {
  const p = deriveSecurityPosture(findings);
  return { score: p.score, severity: p.severity };
}

// Severity-proportionate warning banner. Returns null when there is nothing to
// warn about; for an INFO/LOW worst case it returns a calm "notice" (never a red
// "fix immediately" alarm). The message is DERIVED from the actual highest
// severity finding — never a fixed catastrophic string.
export type BannerLevel = "critical" | "warning" | "notice";
export interface PostureBanner {
  level: BannerLevel;
  title: string;
  message: string;
}
export function bannerForPosture(findings: Finding[]): PostureBanner | null {
  const active = (findings || []).filter((f) => !f.isFalsePositive);
  const top = highestSeverity(active);
  if (!top) return null;

  const n = active.length;
  const noun = n === 1 ? "finding" : "findings";
  // The single most severe finding drives the wording so the banner describes
  // the real worst case (e.g. a missing header) instead of "arbitrary code
  // execution" boilerplate. Prefer a confirmed finding over a heuristic one.
  const worst = active
    .filter((f) => normalizeSeverity(f.severity) === top)
    .sort((a, b) => (isConfirmed(b) ? 1 : 0) - (isConfirmed(a) ? 1 : 0))[0];
  const worstTitle = worst?.title ? `"${worst.title}"` : "the highest-severity issue";

  switch (top) {
    case "critical":
      return {
        level: "critical",
        title: "Critical Risk — Immediate Action Required",
        message: `${n} ${noun} detected, including a critical issue (${worstTitle}). A critical finding can allow full compromise of the target. Remediate immediately.`,
      };
    case "high":
      return {
        level: "critical",
        title: "High Risk — Prompt Remediation Needed",
        message: `${n} ${noun} detected. The most severe is a high-severity issue (${worstTitle}) that should be fixed promptly before it can be chained into a larger attack.`,
      };
    case "medium":
      return {
        level: "warning",
        title: "Moderate Hardening Gaps",
        message: `${n} ${noun} detected. The most significant is a medium-severity issue (${worstTitle}) — a defense-in-depth gap worth scheduling for remediation, not an emergency.`,
      };
    // INFO / LOW: proportionate, non-alarming notice — no red "fix immediately"
    // banner (Bug 2: alarming language is gated behind real severity).
    default:
      return {
        level: "notice",
        title: "Informational Findings",
        message: `${n} low-impact ${noun} noted (worst severity: ${top.toUpperCase()}). These are informational or minor hardening suggestions, not confirmed exploitable vulnerabilities.`,
      };
  }
}
