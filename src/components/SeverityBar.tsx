import React from 'react';
import type { Severity } from '../types.js';
import { SEVERITY_TOKENS, SEVERITY_ORDER } from '../lib/severity.js';

interface SeverityBarProps {
  counts: Partial<Record<Severity, number>>;
  className?: string;
}

// A thin stacked distribution bar: one segment per present severity, widths
// proportional to count, worst-first. Each segment carries a title tooltip so
// identity is never colour-alone. Renders a recessive track when there is
// nothing to show, so every pillar card keeps a consistent baseline.
export default function SeverityBar({ counts, className = '' }: SeverityBarProps) {
  const present = SEVERITY_ORDER
    .map((sev) => ({ sev, n: counts[sev] || 0 }))
    .filter((s) => s.n > 0);
  const total = present.reduce((a, s) => a + s.n, 0);

  if (total === 0) {
    return <div className={`h-1.5 rounded-full bg-[#22c55e]/15 ${className}`} title="No findings" />;
  }

  return (
    <div className={`flex gap-[2px] h-1.5 ${className}`}>
      {present.map(({ sev, n }) => {
        const t = SEVERITY_TOKENS[sev];
        return (
          <div
            key={sev}
            className="rounded-full first:rounded-l-full last:rounded-r-full min-w-[3px]"
            style={{ flexGrow: n, flexBasis: 0, backgroundColor: t.hex }}
            title={`${n} ${t.label}`}
          />
        );
      })}
    </div>
  );
}
