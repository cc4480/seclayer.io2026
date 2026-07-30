import { useState } from 'react';
import { ListChecks, ChevronDown, Lock } from 'lucide-react';
import { Scan } from '../../types.js';

// Full-transparency panel: exactly which check groups ran against this target and
// how many discrete checks each fired — recorded from the real scan, not a
// marketing figure. Gated groups (ownership-required / aggressive opt-in) are
// shown with their would-run count and the reason they were held back, so the
// report is honest about both what ran and what's available.
export default function ScanCoveragePanel({ scan }: { scan: Scan }) {
  const [open, setOpen] = useState(false);
  const coverage = scan.evidence?.coverage;
  if (!coverage) return null;

  const ran = coverage.items.filter((i) => i.ran);
  const skipped = coverage.items.filter((i) => !i.ran);

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-5 py-3.5 cursor-pointer hover:bg-black/30 transition-colors"
        aria-expanded={open}
      >
        <div className="flex items-center space-x-2">
          <ListChecks className="w-4 h-4 text-[#22c55e]" />
          <span className="text-[11px] font-mono text-white uppercase tracking-wider font-bold">Scan Coverage</span>
          <span className="text-[10px] font-mono text-[#71717a]">
            {coverage.totalChecks} checks run · {ran.length}/{coverage.items.length} groups
          </span>
        </div>
        <ChevronDown className={`w-4 h-4 text-[#52525b] transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="px-5 pb-5 pt-1 space-y-4 animate-fade-in">
          <div>
            <p className="text-[9px] font-mono uppercase tracking-wider text-[#22c55e] mb-2">Ran ({ran.length})</p>
            <ul className="space-y-1.5">
              {ran.map((i) => (
                <li key={i.label} className="flex items-start gap-2 text-[11px] font-mono">
                  <span className="text-[#22c55e] shrink-0">✓</span>
                  <span className="text-[#52525b] tabular-nums w-8 shrink-0 text-right">{i.checks}</span>
                  <span className="text-[#52525b] uppercase text-[9px] w-16 shrink-0 pt-0.5">{i.category}</span>
                  <span className="text-zinc-300">{i.label}</span>
                </li>
              ))}
            </ul>
          </div>

          {skipped.length > 0 && (
            <div>
              <p className="text-[9px] font-mono uppercase tracking-wider text-[#71717a] mb-2 flex items-center gap-1">
                <Lock className="w-3 h-3" /> Not run ({skipped.length}) — available, gated
              </p>
              <ul className="space-y-1.5">
                {skipped.map((i) => (
                  <li key={i.label} className="flex items-start gap-2 text-[11px] font-mono opacity-70">
                    <span className="text-[#52525b] shrink-0">○</span>
                    <span className="text-[#52525b] tabular-nums w-8 shrink-0 text-right">{i.checks}</span>
                    <span className="text-[#52525b] uppercase text-[9px] w-16 shrink-0 pt-0.5">{i.category}</span>
                    <span className="text-[#71717a]">
                      {i.label}
                      {i.note && <span className="text-[#52525b] italic"> — {i.note}</span>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
