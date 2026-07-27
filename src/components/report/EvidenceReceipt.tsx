import type { Dispatch, SetStateAction } from 'react';
import { Zap, Terminal, ChevronDown, ChevronUp, Copy } from 'lucide-react';
import { Finding } from '../../types.js';

// The proof-by-demonstration block that earns a finding its PROVEN badge: a
// plain-English demonstration, the highlighted signal quoted verbatim from the
// response, and a collapsible raw attack request/response + replay command.
interface Props {
  finding: Finding;
  expandedApiRows: Record<string, boolean>;
  setExpandedApiRows: Dispatch<SetStateAction<Record<string, boolean>>>;
  handleCopyCode: (id: string, text: string) => void;
}

export default function EvidenceReceipt({ finding, expandedApiRows, setExpandedApiRows, handleCopyCode }: Props) {
  const ev = finding.evidence!;
  const resp = ev.attack.response;
  const q = ev.signal?.quote ?? '';
  const qi = q ? resp.indexOf(q) : -1;
  const isOob = ev.method === 'out-of-band';
  const methodLabel = ({
    reflection: 'Reflection', 'error-signature': 'Error signature',
    oracle: 'Oracle', differential: 'Differential',
    introspection: 'Introspection', 'out-of-band': 'Out-of-band callback',
  } as Record<string, string>)[ev.method] || ev.method;

  return (
    <div className="mb-4 p-4 rounded border border-[#22c55e]/25 bg-[#22c55e]/[0.04]">
      <div className="flex items-center gap-1.5 mb-2">
        <Zap className="w-3 h-3 text-[#22c55e] shrink-0" />
        <span className="text-[9px] font-mono uppercase tracking-wider font-bold text-[#22c55e]">Exploit Receipt — Proven Live</span>
        <span className="ml-auto text-[8px] font-mono uppercase tracking-wider font-bold text-[#22c55e]/80 border border-[#22c55e]/30 rounded px-1.5 py-0.5">{methodLabel}</span>
      </div>
      <p className="text-[13px] font-sans leading-relaxed text-zinc-200">{ev.demonstration}</p>

      {qi !== -1 && (
        <div className="mt-3">
          <span className="text-[#52525b] font-mono text-[9px] uppercase tracking-wider">Proof — captured verbatim in the response</span>
          <div className="mt-1 p-2.5 rounded bg-black border border-zinc-800 overflow-x-auto scrollbar-thin">
            <code className="text-[10px] font-mono whitespace-pre-wrap break-all leading-relaxed">
              <span className="text-zinc-600">{resp.slice(Math.max(0, qi - 90), qi)}</span>
              <span className="bg-[#22c55e]/20 text-[#22c55e] rounded px-0.5 font-bold">{q}</span>
              <span className="text-zinc-600">{resp.slice(qi + q.length, qi + q.length + 90)}</span>
            </code>
          </div>
          {ev.signal?.why && <p className="mt-1.5 text-[11px] font-sans text-zinc-400 leading-relaxed">{ev.signal.why}</p>}
        </div>
      )}

      <div className="mt-3">
        <button
          onClick={() => setExpandedApiRows(p => ({ ...p, [`ev-${finding.id}`]: !p[`ev-${finding.id}`] }))}
          aria-expanded={!!expandedApiRows[`ev-${finding.id}`]}
          className="w-full flex items-center justify-between p-2.5 rounded bg-black/40 hover:bg-black border border-zinc-800/80 transition-colors cursor-pointer group"
        >
          <span className="flex items-center gap-2 text-[10px] font-mono text-zinc-400 group-hover:text-[#22c55e] transition-colors uppercase tracking-wider font-bold">
            <Terminal className="w-3.5 h-3.5 shrink-0" aria-hidden="true" /> Raw attack exchange & replay
          </span>
          {expandedApiRows[`ev-${finding.id}`] ? <ChevronUp className="w-4 h-4 text-zinc-500" aria-hidden="true" /> : <ChevronDown className="w-4 h-4 text-zinc-500" aria-hidden="true" />}
        </button>
        {expandedApiRows[`ev-${finding.id}`] && (
          <div className="mt-2 space-y-2 animate-fade-in">
            {ev.reproduction && (
              <div className="p-2.5 bg-black border border-zinc-800 rounded flex items-center justify-between gap-2 overflow-x-auto">
                <code className="text-[10px] font-mono whitespace-pre text-zinc-300 break-all">{ev.reproduction}</code>
                <button onClick={() => handleCopyCode(`repro-${finding.id}`, ev.reproduction)} aria-label="Copy reproduction command" className="text-zinc-500 hover:text-white cursor-pointer shrink-0"><Copy className="w-3 h-3" aria-hidden="true"/></button>
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-amber-500/80 flex items-center justify-between">
                  <span>Attack Request</span>
                  <button onClick={() => handleCopyCode(`evreq-${finding.id}`, ev.attack.request)} aria-label="Copy attack request" className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3" aria-hidden="true"/></button>
                </div>
                <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                  <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{ev.attack.request}</code>
                </div>
              </div>
              <div className="p-3 bg-black border border-zinc-800 rounded relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full bg-zinc-900/80 p-1.5 border-b border-zinc-800 text-[9px] uppercase tracking-wider font-mono text-red-400/80 flex items-center justify-between">
                  <span>{isOob ? 'Out-of-Band Callback' : 'Attack Response'}</span>
                  <button onClick={() => handleCopyCode(`evres-${finding.id}`, ev.attack.response)} aria-label={isOob ? 'Copy out-of-band callback' : 'Copy attack response'} className="text-zinc-500 hover:text-white cursor-pointer"><Copy className="w-3 h-3" aria-hidden="true"/></button>
                </div>
                <div className="pt-6 overflow-x-auto max-h-64 scrollbar-thin">
                  <code className="text-[10px] font-mono whitespace-pre text-zinc-400 break-all">{ev.attack.response}</code>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
