import { useState } from 'react';
import { AlertTriangle, ShieldCheck } from 'lucide-react';

// False-positive / risk-exclusion rules tab: lists active suppression rules and
// lets the operator revoke them (which restores the finding to future scores).
export default function ExclusionsTab({ suppressRules, fetchSuppressRules }: { suppressRules: any[]; fetchSuppressRules: () => void }) {
  const [isDeletingRule, setIsDeletingRule] = useState<string | null>(null);

  const revoke = async (id: string) => {
    setIsDeletingRule(id);
    try {
      const delRes = await fetch(`/api/suppressions/${id}`, { method: 'DELETE' });
      if (delRes.ok) fetchSuppressRules();
    } catch (err) {
      console.error('Failed to revoke suppression:', err);
    } finally {
      setIsDeletingRule(null);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="bg-amber-500/5 border border-amber-500/10 rounded p-4 flex items-start space-x-3.5">
        <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-white font-mono text-xs uppercase font-bold">Rule-based Exclusion Ledger & False Positive Controls</h4>
          <p className="text-[11px] font-mono text-[#a1a1aa] leading-relaxed">
            Security managers can override individual vulnerabilities by declaring them "False Positives" or "Exempt Risks". When an exclusion rule is defined, future testing sequences on that URL automatically filter out matching threats, recalculating the Posture Score to reflect verified, accepted, or compensated risks.
          </p>
        </div>
      </div>

      {suppressRules.length === 0 ? (
        <div className="text-center py-16 bg-black rounded border border-dashed border-[#27272a] flex flex-col items-center">
          <ShieldCheck className="w-10 h-10 text-zinc-600 mb-3" />
          <span className="text-xs text-white uppercase font-bold font-mono">No Active Exclusion Rules</span>
          <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-sm">
            All vulnerability findings are currently factored into core security scores. To suppress an issue, open its security report details and trigger "Mark False Positive".
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {suppressRules.map((rule) => (
            <div key={rule.id} className="bg-black/80 border border-[#27272a]/95 rounded p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:border-zinc-750 transition-colors">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[9px] font-mono uppercase bg-zinc-900 border border-zinc-700/60 text-zinc-400 px-2 py-0.5 rounded">
                    Target Host Exclusion
                  </span>
                  <span className="text-[11px] text-[#22c55e] font-mono font-bold select-all">{rule.targetUrl}</span>
                </div>
                <h5 className="text-white text-xs font-mono font-bold leading-snug">{rule.findingTitle}</h5>
                <p className="text-zinc-500 text-[11px] font-mono leading-relaxed">
                  <strong className="text-zinc-400">Security Justification:</strong> {rule.reason || 'No justification provided'}
                </p>
                <span className="text-[9px] text-[#52525b] font-mono block">
                  Established: {new Date(rule.createdAt).toLocaleString()} • Exclusion ID: {rule.id}
                </span>
              </div>

              <button
                onClick={() => revoke(rule.id)}
                disabled={isDeletingRule === rule.id}
                className="self-start sm:self-center px-3 py-1.5 bg-red-950/20 hover:bg-red-950/50 border border-red-900/40 text-[#f87171] hover:text-red-300 rounded text-[10px] font-mono uppercase tracking-wider transition-colors shrink-0 cursor-pointer"
              >
                {isDeletingRule === rule.id ? 'Revoking...' : 'Revoke Exclusion'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
