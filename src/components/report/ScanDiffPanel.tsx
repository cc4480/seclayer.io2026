import { ArrowUpRight, ArrowDownRight, Minus, CheckCircle2, AlertOctagon } from 'lucide-react';
import { Scan, Finding } from '../../types.js';
import { diffFindings } from '../../../server/scanDiff.js';
import { SEVERITY_TOKENS } from '../../lib/severity.js';

// "What changed since the last scan" — a compact, at-a-glance delta between this
// scan and the previous completed scan of the same target. Renders nothing when
// there's no prior scan (baseline) or literally nothing changed, so it never adds
// noise. Uses the shared, isomorphic diffFindings so it can't disagree with the
// server's own regression logic.
export default function ScanDiffPanel({ scan, previousScan }: { scan: Scan; previousScan: Scan }) {
  const diff = diffFindings(scan.findings, previousScan.findings, {
    current: scan.score,
    previous: previousScan.score,
  });

  const nothingChanged =
    diff.newFindings.length === 0 && diff.fixedFindings.length === 0 && diff.severityChanges.length === 0;
  if (diff.isBaseline || nothingChanged) return null;

  const delta = diff.scoreDelta ?? 0;
  const deltaTone = delta > 0 ? 'text-[#22c55e]' : delta < 0 ? 'text-[#f87171]' : 'text-zinc-500';
  const DeltaIcon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : Minus;

  const sevChip = (f: Finding) => SEVERITY_TOKENS[f.severity]?.text || 'text-zinc-400';

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-white text-xs font-bold font-mono uppercase tracking-wider">What changed since last scan</h3>
        <span className={`flex items-center gap-1 font-mono text-xs font-bold ${deltaTone}`}>
          <DeltaIcon className="w-3.5 h-3.5" />
          {delta > 0 ? '+' : ''}{delta} score
        </span>
      </div>

      <div className="grid grid-cols-3 gap-3 font-mono text-center">
        <div className="bg-black/40 border border-[#27272a] rounded p-2.5">
          <span className="block text-lg font-black text-[#f87171]">{diff.newFindings.length}</span>
          <span className="text-[9px] uppercase tracking-wider text-zinc-500">New</span>
        </div>
        <div className="bg-black/40 border border-[#27272a] rounded p-2.5">
          <span className="block text-lg font-black text-[#22c55e]">{diff.fixedFindings.length}</span>
          <span className="text-[9px] uppercase tracking-wider text-zinc-500">Resolved</span>
        </div>
        <div className="bg-black/40 border border-[#27272a] rounded p-2.5">
          <span className="block text-lg font-black text-amber-400">{diff.severityChanges.filter((c) => c.worsened).length}</span>
          <span className="text-[9px] uppercase tracking-wider text-zinc-500">Worsened</span>
        </div>
      </div>

      {diff.newFindings.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#f87171] font-bold flex items-center gap-1.5">
            <AlertOctagon className="w-3.5 h-3.5" /> New findings
          </span>
          {diff.newFindings.slice(0, 8).map((f) => (
            <div key={f.id} className="text-[11px] font-mono text-zinc-300 flex items-center gap-2">
              <span className={`uppercase text-[9px] font-bold ${sevChip(f)}`}>{f.severity}</span>
              <span>{f.title}</span>
            </div>
          ))}
        </div>
      )}

      {diff.fixedFindings.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#22c55e] font-bold flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" /> Resolved since last scan
          </span>
          {diff.fixedFindings.slice(0, 8).map((f) => (
            <div key={f.id} className="text-[11px] font-mono text-zinc-400 flex items-center gap-2 line-through">
              <span className="uppercase text-[9px] font-bold text-zinc-600">{f.severity}</span>
              <span>{f.title}</span>
            </div>
          ))}
        </div>
      )}

      {diff.severityChanges.filter((c) => c.worsened).length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-bold">Severity increased</span>
          {diff.severityChanges.filter((c) => c.worsened).slice(0, 6).map((c) => (
            <div key={c.finding.id} className="text-[11px] font-mono text-zinc-300 flex items-center gap-2">
              <span>{c.finding.title}</span>
              <span className="text-zinc-500">{c.from.toUpperCase()} → <span className="text-amber-400 font-bold">{c.to.toUpperCase()}</span></span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
