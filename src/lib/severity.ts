import type { Severity } from '../types.js';
import type { RiskLabel, Grade } from '../../server/scoring.js';

// SINGLE SOURCE OF TRUTH for how severity/grade LOOK, mirroring scoring.ts as the
// single source of truth for what they MEAN. Every chip, pillar, badge, gauge and
// bar reads from here so a colour can never drift between two components.
//
// Severity colours are a *status* palette (reserved, semantic) — each is always
// shown next to its text label, never colour-alone.

export interface SeverityToken {
  label: string;   // human label
  text: string;    // tailwind text colour
  border: string;  // tailwind border colour
  bg: string;      // tailwind background tint
  chip: string;    // combined chip classes (bg + border + text)
  hex: string;     // raw colour for SVG/canvas marks
}

export const SEVERITY_TOKENS: Record<Severity, SeverityToken> = {
  critical: { label: 'Critical', text: 'text-red-400',   border: 'border-red-500/25',   bg: 'bg-red-500/10',   chip: 'bg-red-500/10 border border-red-500/25 text-red-400',    hex: '#f87171' },
  high:     { label: 'High',     text: 'text-rose-400',  border: 'border-rose-500/25',  bg: 'bg-rose-500/10',  chip: 'bg-rose-500/10 border border-rose-500/25 text-rose-400',  hex: '#fb7185' },
  medium:   { label: 'Medium',   text: 'text-amber-400', border: 'border-amber-500/25', bg: 'bg-amber-500/10', chip: 'bg-amber-500/10 border border-amber-500/25 text-amber-400', hex: '#fbbf24' },
  low:      { label: 'Low',      text: 'text-blue-400',  border: 'border-blue-500/25',  bg: 'bg-blue-500/10',  chip: 'bg-blue-500/10 border border-blue-500/25 text-blue-400',   hex: '#60a5fa' },
  info:     { label: 'Info',     text: 'text-zinc-300',  border: 'border-zinc-500/25',  bg: 'bg-zinc-500/10',  chip: 'bg-zinc-500/10 border border-zinc-500/25 text-zinc-300',   hex: '#a1a1aa' },
};

// Green "all clear" token for the SECURE state (a pillar/category with nothing).
export const SECURE_TOKEN = {
  label: 'Secure', text: 'text-[#22c55e]', border: 'border-[#22c55e]/25', bg: 'bg-[#22c55e]/5',
  chip: 'bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e]', hex: '#22c55e',
};

// Severity order for stacking a distribution bar (worst first, left-to-right).
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// The risk LABEL (from scoring.riskLabelForSeverity) → its visual token. Keeps
// pillar cards / tab badges keyed off the same colours as the severity chips.
export function tokenForRiskLabel(label: RiskLabel): SeverityToken | typeof SECURE_TOKEN {
  switch (label) {
    case 'CRITICAL': return SEVERITY_TOKENS.critical;
    case 'HIGH RISK': return SEVERITY_TOKENS.high;
    case 'MODERATE': return SEVERITY_TOKENS.medium;
    case 'LOW RISK': return SEVERITY_TOKENS.low;
    case 'INFO': return SEVERITY_TOKENS.info;
    default: return SECURE_TOKEN; // SECURE
  }
}

// The 0-100 SCORE gauge is a magnitude→status meter, coloured by GRADE band so
// the arc colour always agrees with the grade letter printed inside it. (Distinct
// from severity chips: this answers "how good is the score", not "how bad is the
// worst finding".)
export const GRADE_ACCENT: Record<Grade, { hex: string; text: string; label: string }> = {
  A: { hex: '#22c55e', text: 'text-[#22c55e]', label: 'Excellent' },
  B: { hex: '#84cc16', text: 'text-lime-400',  label: 'Good' },
  C: { hex: '#fbbf24', text: 'text-amber-400', label: 'Fair' },
  D: { hex: '#fb923c', text: 'text-orange-400', label: 'Poor' },
  F: { hex: '#ef4444', text: 'text-red-400',   label: 'Critical' },
};
