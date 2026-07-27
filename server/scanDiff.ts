import { Finding, Severity } from "../src/types.js";

// Pure, isomorphic scan-to-scan diff — "what changed since last time". Kept
// separate from notify.ts (which decides whether to ALERT) so the report UI can
// show the full picture (new / fixed / still-present) without any alerting
// policy baked in. Imports only shared types, so both the Node server and the
// browser bundle use it unchanged, exactly like scoring.ts.

// Stable cross-scan identity for a finding: title + category + endpoint is
// stable across re-scans; the per-scan random `id` is not. Matches notify.ts's
// signature() so "the same issue as last time" is never miscounted as new.
function signature(f: Finding): string {
  return `${f.category}|${f.title}|${f.endpoint || ""}`.toLowerCase();
}

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// A finding whose severity changed between scans (same identity, different level).
export interface SeverityChange {
  finding: Finding;          // the current-scan version
  from: Severity;
  to: Severity;
  worsened: boolean;         // true when severity increased
}

export interface ScanDiff {
  isBaseline: boolean;       // no comparable previous scan — nothing to diff against
  newFindings: Finding[];    // present now, absent before
  fixedFindings: Finding[];  // present before, absent now (likely remediated)
  persisting: Finding[];     // present in both scans
  severityChanges: SeverityChange[];
  scoreDelta?: number;       // current − previous score (negative = worse)
}

function active(findings?: Finding[]): Finding[] {
  return (findings || []).filter((f) => !f.isFalsePositive);
}

// Diffs a current finding set against a previous one. Suppressed (false-positive)
// findings are excluded from every bucket, matching how the score is derived.
export function diffFindings(
  current?: Finding[],
  previous?: Finding[],
  scores?: { current?: number; previous?: number },
): ScanDiff {
  const isBaseline = previous === undefined;
  // No prior scan → there's nothing to diff against. Return an empty baseline
  // rather than reporting every current finding as "new" relative to nothing.
  if (isBaseline) {
    return { isBaseline: true, newFindings: [], fixedFindings: [], persisting: [], severityChanges: [] };
  }
  const cur = active(current);
  const prev = active(previous);

  const prevBySig = new Map(prev.map((f) => [signature(f), f]));
  const curSigs = new Set(cur.map(signature));

  const newFindings: Finding[] = [];
  const persisting: Finding[] = [];
  const severityChanges: SeverityChange[] = [];

  for (const f of cur) {
    const before = prevBySig.get(signature(f));
    if (!before) {
      newFindings.push(f);
      continue;
    }
    persisting.push(f);
    if (before.severity !== f.severity) {
      severityChanges.push({
        finding: f,
        from: before.severity,
        to: f.severity,
        worsened: SEVERITY_RANK[f.severity] > SEVERITY_RANK[before.severity],
      });
    }
  }

  const fixedFindings = prev.filter((f) => !curSigs.has(signature(f)));

  const scoreDelta =
    scores && typeof scores.current === "number" && typeof scores.previous === "number"
      ? scores.current - scores.previous
      : undefined;

  return { isBaseline, newFindings, fixedFindings, persisting, severityChanges, scoreDelta };
}
