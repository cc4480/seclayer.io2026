import { useState } from 'react';
import { Radar, Globe, RefreshCw, ChevronDown, AlertTriangle, Info } from 'lucide-react';
import { useNmap } from '../../hooks/useNmap.js';
import { NmapScan } from '../../types.js';

const STATUS_STYLE: Record<string, string> = {
  complete: 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30',
  scanning: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
  queued: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
  failed: 'bg-[#f87171]/10 text-[#f87171] border-[#f87171]/30',
  canceled: 'bg-[#52525b]/15 text-[#a1a1aa] border-[#52525b]/40',
};

function ResultsView({ scan }: { scan: NmapScan }) {
  const result = scan.result;
  if (!result) return null;
  const openPorts = result.ports.filter((p) => p.state === 'open');

  return (
    <div className="mt-4 pt-4 border-t border-[#27272a] space-y-5">
      <div>
        <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] mb-2">
          Open Ports &amp; Services ({openPorts.length})
        </h4>
        {openPorts.length === 0 ? (
          <p className="text-[11px] font-mono text-[#a1a1aa]">No open ports found.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-[11px] font-mono">
              <thead>
                <tr className="text-[#52525b] uppercase text-[9px] tracking-wider border-b border-[#27272a]">
                  <th className="py-1.5 pr-4">Port</th>
                  <th className="py-1.5 pr-4">Proto</th>
                  <th className="py-1.5 pr-4">Service</th>
                  <th className="py-1.5 pr-4">Product / Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#27272a]/40">
                {openPorts.map((p) => (
                  <tr key={`${p.protocol}-${p.port}`}>
                    <td className="py-1.5 pr-4 text-white font-bold">{p.port}</td>
                    <td className="py-1.5 pr-4 text-[#a1a1aa]">{p.protocol}</td>
                    <td className="py-1.5 pr-4 text-[#a1a1aa]">{p.service || '—'}</td>
                    <td className="py-1.5 pr-4 text-[#a1a1aa]">
                      {[p.product, p.version].filter(Boolean).join(' ') || '—'}
                      {p.extraInfo ? <span className="text-[#52525b]"> ({p.extraInfo})</span> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {result.osMatches.length > 0 && (
        <div>
          <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] mb-2">OS Detection</h4>
          <p className="text-[11px] font-mono text-[#a1a1aa]">
            Best-guess fingerprint: <span className="text-white font-bold">{result.osMatches[0].name}</span>{' '}
            <span className="text-[#52525b]">({result.osMatches[0].accuracy}% confidence)</span>
          </p>
        </div>
      )}

      <div>
        <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] mb-2">
          Vulnerability Script Findings ({result.vulnFindings.length})
        </h4>
        {result.vulnFindings.length === 0 ? (
          <p className="text-[11px] font-mono text-[#a1a1aa]">No NSE vulnerability-script hits.</p>
        ) : (
          <div className="space-y-2">
            <p className="text-[10px] font-mono text-[#a1a1aa] flex items-start gap-1.5">
              <Info className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
              Nmap NSE vulnerability scripts match on service banners and version strings — they indicate a
              likely issue, not a confirmed, exploited proof. Every hit below is marked <span className="text-amber-400 font-bold">DETECTED</span>, never PROVEN. Verify manually, or run a targeted AppSec active probe for PROVEN evidence.
            </p>
            {result.vulnFindings.map((f, i) => (
              <div key={`${f.scriptId}-${i}`} className="p-3 bg-black border border-[#27272a] rounded">
                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                  <span className="bg-amber-500/10 text-amber-400 border border-amber-500/35 text-[9px] font-mono uppercase rounded px-1.5 py-0.5 font-bold">Detected</span>
                  <span className="text-white text-[11px] font-mono font-bold">{f.scriptId}</span>
                  {f.port != null && <span className="text-[#52525b] text-[10px] font-mono">port {f.port}</span>}
                </div>
                <pre className="text-[10px] font-mono text-[#a1a1aa] whitespace-pre-wrap break-words">{f.output}</pre>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-[9px] font-mono text-[#52525b]">
        Scanned {result.resolvedIp} with nmap {result.nmapVersion} in {Math.round(result.durationMs / 1000)}s
        · {result.scanArgs.join(' ')}
      </p>
    </div>
  );
}

// Network Reconnaissance history — a fully independent tab: its own data
// (nmapScans), its own per-row actions, results shown inline (Dashboard-local
// expand state) rather than routed through the AppSec report/currentView
// machinery. Mirrors MonitoringTab's per-row busy-state pattern.
export default function NetworkReconTab({ nm }: { nm: ReturnType<typeof useNmap> }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (nm.nmapScans.length === 0) {
    return (
      <div className="space-y-4 animate-fade-in text-xs font-mono">
        <div className="text-center py-12 bg-black rounded border border-dashed border-[#27272a]">
          <Radar className="w-8 h-8 text-[#52525b] mx-auto mb-3" />
          <span className="text-xs text-[#52525b] font-mono block mb-2">No network reconnaissance scans yet</span>
          <p className="text-[11px] text-[#52525b] max-w-sm mx-auto font-mono">
            Run one from the Network Reconnaissance card above — results appear here.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3 animate-fade-in text-xs font-mono">
      {nm.nmapScans.map((scan) => {
        const busy = nm.busyScanId === scan.id;
        const inFlight = scan.status === 'queued' || scan.status === 'scanning';
        const expanded = expandedId === scan.id;
        return (
          <div key={scan.id} className="p-4 bg-black border border-[#27272a] rounded">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <Globe className="w-4 h-4 text-[#52525b]" />
                  <span className="text-white font-bold uppercase text-xs">{scan.url}</span>
                  <span className={`text-[9px] px-2 py-0.5 rounded border uppercase ${STATUS_STYLE[scan.status] || STATUS_STYLE.canceled}`}>
                    {scan.status}
                  </span>
                </div>
                <div className="text-[#a1a1aa] text-[10px] flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span>Launched: {new Date(scan.createdAt).toLocaleString()}</span>
                  {scan.completedAt && (
                    <>
                      <span>&bull;</span>
                      <span>Finished: {new Date(scan.completedAt).toLocaleString()}</span>
                    </>
                  )}
                  {scan.result && (
                    <>
                      <span>&bull;</span>
                      <span>{scan.result.ports.filter((p) => p.state === 'open').length} open port(s), {scan.result.vulnFindings.length} DETECTED</span>
                    </>
                  )}
                </div>
                {scan.status === 'failed' && scan.error && (
                  <div className="text-[#f87171] text-[10px] flex items-start gap-1.5">
                    <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                    <span>{scan.error}</span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {inFlight && (
                  <button
                    onClick={() => nm.cancelScan(scan.id)}
                    disabled={busy}
                    className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:bg-[#f87171] hover:text-white text-[#f87171] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer disabled:opacity-40 flex items-center gap-1.5"
                  >
                    {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}Cancel
                  </button>
                )}
                {scan.status === 'complete' && (
                  <button
                    onClick={() => setExpandedId(expanded ? null : scan.id)}
                    className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#22c55e]/40 hover:text-[#22c55e] text-[#a1a1aa] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer flex items-center gap-1.5"
                  >
                    <ChevronDown className={`w-3 h-3 transition-transform ${expanded ? 'rotate-180' : ''}`} />
                    {expanded ? 'Hide Results' : 'View Results'}
                  </button>
                )}
              </div>
            </div>
            {expanded && scan.status === 'complete' && <ResultsView scan={scan} />}
          </div>
        );
      })}
    </div>
  );
}
