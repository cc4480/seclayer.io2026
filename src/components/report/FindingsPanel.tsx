import React from 'react';
import { Shield, Check, CheckCircle2, AlertTriangle, Eye, Zap } from 'lucide-react';
import { Finding } from '../../types.js';
import { isConfirmed, isProven } from '../../../server/scoring.js';
import { categoryTabLabels, getCategorySeverity, type SecCategory } from './categories.js';
import FindingCard, { FindingCardProps } from './FindingCard.js';

// The per-module (non-overview) findings view: module header, empty state, and
// the confidence-grouped list of finding cards (Proven → Confirmed → Needs
// Verification → Suppressed).
type Props = {
  findings: Finding[];
  activeTab: SecCategory;
} & Omit<FindingCardProps, 'finding'>;

export default function FindingsPanel({ findings, activeTab, ...cardProps }: Props) {
  const meta = categoryTabLabels.find(c => c.key === activeTab);
  const moduleFindings = findings.filter(f => f.category === activeTab);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Module title cards */}
      <div className="flex items-center justify-between border-b border-[#27272a] pb-4">
        <div>
          <h4 className="text-white text-sm font-bold font-mono tracking-tight uppercase flex items-center space-x-2">
            {React.createElement(meta?.icon || Shield, { className: 'w-5 h-5 text-[#22c55e]' })}
            <span>{meta?.label} Module Findings</span>
          </h4>
          <span className="text-[10px] font-mono text-[#52525b] uppercase mt-1 block">
            {meta?.term}
          </span>
        </div>
        <span className="text-[10px] font-mono text-zinc-400 block uppercase font-extrabold bg-[#18181b] border border-[#27272a] px-2.5 py-1">
          Risk Assessment: {getCategorySeverity(findings, activeTab)}
        </span>
      </div>

      {/* Filtered list of findings */}
      {moduleFindings.length === 0 ? (
        <div className="text-center py-16 bg-black/40 rounded border border-dashed border-[#27272a] flex flex-col items-center">
          <CheckCircle2 className="w-10 h-10 text-[#22c55e] mb-3" />
          <span className="text-xs text-white font-bold font-mono uppercase block">Zero Vulnerabilities Outstanding</span>
          <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-md">
            Your current configurations satisfy standard defensive criteria in {meta?.term}.
          </p>
          <div className="mt-5 grid grid-cols-2 gap-3 max-w-sm w-full font-mono text-[9px] text-[#52525b] text-left">
            <div className="flex items-center space-x-1">
              <Check className="w-3 h-3 text-[#22c55e]" />
              <span>Hardening complete</span>
            </div>
            <div className="flex items-center space-x-1">
              <Check className="w-3 h-3 text-[#22c55e]" />
              <span>Continuous evaluation active</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {(() => {
            // Confirmed vs. Needs-Verification split: probe-confirmed findings
            // first, then heuristic ones, then suppressed — each group introduced
            // by a header so the confidence level is legible at a glance. PROVEN
            // sits above CONFIRMED (a valid replayable receipt is the top tier).
            const groupOf = (f: Finding): 'proven' | 'confirmed' | 'needs' | 'suppressed' =>
              f.isFalsePositive ? 'suppressed' : isProven(f) ? 'proven' : isConfirmed(f) ? 'confirmed' : 'needs';
            const rank = { proven: 0, confirmed: 1, needs: 2, suppressed: 3 };
            const ordered = [...moduleFindings].sort((a, b) => rank[groupOf(a)] - rank[groupOf(b)]);
            let lastGroup = '';
            return ordered.map(finding => {
              const group = groupOf(finding);
              const showGroupHeader = group !== lastGroup;
              lastGroup = group;
              return (
                <React.Fragment key={finding.id}>
                  {showGroupHeader && (
                    <div className="flex flex-wrap items-center gap-2 pt-3 first:pt-0">
                      {group === 'proven' ? (
                        <><Zap className="w-3.5 h-3.5 text-[#22c55e] shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-[#22c55e]">Proven</span></>
                      ) : group === 'confirmed' ? (
                        <><CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e] shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-[#22c55e]">Confirmed</span></>
                      ) : group === 'needs' ? (
                        <><AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-amber-400">Needs Verification</span></>
                      ) : (
                        <><Eye className="w-3.5 h-3.5 text-zinc-500 shrink-0" /><span className="text-[10px] font-mono uppercase tracking-wider font-bold text-zinc-500">Suppressed (False Positive)</span></>
                      )}
                      <span className="text-[9px] font-mono text-[#52525b]">
                        {group === 'proven'
                          ? 'Demonstrated live — replayable exploit receipt attached'
                          : group === 'confirmed'
                          ? 'Engine-verified — high confidence'
                          : group === 'needs'
                          ? 'Heuristic / pattern match — verify before acting'
                          : 'Excluded from the posture score'}
                      </span>
                    </div>
                  )}
                  <FindingCard finding={finding} {...cardProps} />
                </React.Fragment>
              );
            });
          })()}
        </div>
      )}
    </div>
  );
}
