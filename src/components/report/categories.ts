// Shared category metadata + per-pillar risk helpers for the report views.
// Every risk label comes from the same shared scoring module the server uses, so
// the tabs, pillar grid, and module headers can never disagree.
import { Code, Globe, Zap, Package, Grid, Server, Terminal } from 'lucide-react';
import { Finding } from '../../types.js';
import { riskLabelForSeverity, highestSeverity, type RiskLabel } from '../../../server/scoring.js';

export type SecCategory = 'SAST' | 'DAST' | 'IAST' | 'SCA' | 'EASM' | 'RED_TEAM' | 'API_SEC';

export const categoryTabLabels = [
  { key: 'SAST' as const, label: 'SAST', icon: Code, term: 'Static Analysis' },
  { key: 'DAST' as const, label: 'DAST', icon: Globe, term: 'Dynamic Audit' },
  { key: 'IAST' as const, label: 'IAST', icon: Zap, term: 'Interactive Policies' },
  { key: 'SCA' as const, label: 'SCA', icon: Package, term: 'Composition Review' },
  { key: 'EASM' as const, label: 'EASM', icon: Grid, term: 'Attack Surface' },
  { key: 'API_SEC' as const, label: 'API SEC', icon: Server, term: 'API Security Testing' },
  { key: 'RED_TEAM' as const, label: 'RED TEAM', icon: Terminal, term: 'Red Team Active Probes' },
];

// Colour keyed off SEVERITY (not ad-hoc score thresholds) so a colour can never
// contradict the posture rating. Shared by the executive score card and pillars.
export function severityColorClass(label: RiskLabel): string {
  if (label === 'CRITICAL' || label === 'HIGH RISK') return 'text-red-400 border-red-500/20 bg-red-500/5';
  if (label === 'MODERATE') return 'text-amber-400 border-amber-500/20 bg-amber-500/5';
  if (label === 'LOW RISK') return 'text-blue-400 border-blue-500/20 bg-blue-500/5';
  if (label === 'INFO') return 'text-zinc-300 border-zinc-500/20 bg-zinc-500/5';
  return 'text-[#22c55e] border-[#22c55e]/25 bg-[#22c55e]/5'; // SECURE
}

export function getCategoryCount(findings: Finding[], cat: SecCategory): number {
  return findings.filter((f) => f.category === cat && !f.isFalsePositive).length;
}

// Per-pillar label, derived from the SAME shared severity model as everything
// else — an info-only category reads "INFO", never "LOW RISK".
export function getCategorySeverity(findings: Finding[], cat: SecCategory): RiskLabel {
  const catFindings = findings.filter((f) => f.category === cat);
  return riskLabelForSeverity(highestSeverity(catFindings));
}

export function getCategoryColor(findings: Finding[], cat: SecCategory): string {
  return severityColorClass(getCategorySeverity(findings, cat));
}
