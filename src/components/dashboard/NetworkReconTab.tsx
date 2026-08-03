import { useState } from 'react';
import { Radar, Globe, RefreshCw, ChevronDown, AlertTriangle, Info, Download } from 'lucide-react';
import { useNmap } from '../../hooks/useNmap.js';
import { NmapScan, NmapVulnFinding, NmapScriptOutcome } from '../../types.js';

// Client-side only — scan.rawXml is nmap's own unmodified -oX output, already
// sent to the client on every scan fetch (see src/types.ts's NmapScan). This
// just gives it somewhere to go: independently verifiable proof the scan
// actually ran, not just Seclayer's own rendering of it.
function downloadRawXml(scan: NmapScan) {
  if (!scan.rawXml) return;
  const blob = new Blob([scan.rawXml], { type: 'application/xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `nmap-${scan.id}.xml`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const STATUS_STYLE: Record<string, string> = {
  complete: 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30',
  scanning: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
  queued: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
  failed: 'bg-[#f87171]/10 text-[#f87171] border-[#f87171]/30',
  canceled: 'bg-[#52525b]/15 text-[#a1a1aa] border-[#52525b]/40',
};

// A script ran for every entry here — only 'finding' means it actually hit
// something (see server/nmap/classify.ts). Missing outcome (older, pre-fix
// persisted scans) falls back to 'finding' rather than silently hiding it —
// never under-report, worst case a stale row still shows the old label.
const OUTCOME_BADGE: Record<NmapScriptOutcome, { label: string; className: string }> = {
  finding: { label: 'Detected', className: 'bg-amber-500/10 text-amber-400 border-amber-500/35' },
  negative: { label: 'Clean', className: 'bg-[#22c55e]/10 text-[#22c55e] border-[#22c55e]/30' },
  error: { label: 'Script Error', className: 'bg-[#52525b]/15 text-[#a1a1aa] border-[#52525b]/40' },
  inconclusive: { label: 'Inconclusive', className: 'bg-[#52525b]/15 text-[#a1a1aa] border-[#52525b]/40' },
};

function outcomeOf(f: NmapVulnFinding): NmapScriptOutcome {
  return f.outcome ?? 'finding';
}

// `key` is declared (but unused in the body) only because this repo has no
// @types/react installed, so TS doesn't auto-strip JSX's special `key` prop
// the way it would with real React types — see the two call sites below.
function ScriptResultRow({ f }: { f: NmapVulnFinding; key?: string }) {
  const badge = OUTCOME_BADGE[outcomeOf(f)];
  return (
    <div className="p-3 bg-black border border-[#27272a] rounded">
      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
        <span className={`${badge.className} border text-[9px] font-mono uppercase rounded px-1.5 py-0.5 font-bold`}>{badge.label}</span>
        <span className="text-white text-[11px] font-mono font-bold">{f.scriptId}</span>
        {f.port != null && <span className="text-[#52525b] text-[10px] font-mono">port {f.port}</span>}
      </div>
      <pre className="text-[10px] font-mono text-[#a1a1aa] whitespace-pre-wrap break-words">{f.output}</pre>
    </div>
  );
}

function ResultsView({ scan }: { scan: NmapScan }) {
  const [showAllScripts, setShowAllScripts] = useState(false);
  const result = scan.result;
  if (!result) return null;
  const openPorts = result.ports.filter((p) => p.state === 'open');
  const findings = result.vulnFindings.filter((f) => outcomeOf(f) === 'finding');
  const otherScripts = result.vulnFindings.filter((f) => outcomeOf(f) !== 'finding');
  const errored = otherScripts.filter((f) => outcomeOf(f) === 'error').length;

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
          NSE Vulnerability Scripts ({result.vulnFindings.length} run{errored > 0 ? `, ${errored} errored` : ''})
        </h4>
        {result.vulnFindings.length === 0 ? (
          <p className="text-[11px] font-mono text-[#a1a1aa]">No NSE vulnerability scripts ran (no open ports matched).</p>
        ) : findings.length === 0 ? (
          <p className="text-[11px] font-mono text-[#22c55e] flex items-start gap-1.5">
            <Info className="w-3 h-3 shrink-0 mt-0.5" />
            {result.vulnFindings.length} script(s) ran against open ports/host — none flagged a signal.
          </p>
        ) : (
          <div className="space-y-2 mb-3">
            <p className="text-[10px] font-mono text-[#a1a1aa] flex items-start gap-1.5">
              <Info className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
              Nmap NSE vulnerability scripts match on service banners and version strings — they indicate a
              likely issue, not a confirmed, exploited proof. Every hit below is marked <span className="text-amber-400 font-bold">DETECTED</span>, never PROVEN. Verify manually, or run a targeted AppSec active probe for PROVEN evidence.
            </p>
            {findings.map((f, i) => <ScriptResultRow key={`${f.scriptId}-${i}`} f={f} />)}
          </div>
        )}
        {otherScripts.length > 0 && (
          <div>
            <button
              type="button"
              onClick={() => setShowAllScripts((v) => !v)}
              className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-[#52525b] hover:text-white transition-all cursor-pointer"
            >
              <ChevronDown className={`w-3 h-3 transition-transform ${showAllScripts ? 'rotate-180' : ''}`} />
              {showAllScripts ? 'Hide' : 'Show'} {otherScripts.length} clean / inconclusive / errored script result(s)
            </button>
            {errored > 0 && (
              <p className="text-[10px] font-mono text-[#a1a1aa] flex items-start gap-1.5 mt-2">
                <Info className="w-3 h-3 text-[#52525b] shrink-0 mt-0.5" />
                {errored} script{errored === 1 ? '' : 's'} failed to get a clean read rather than reporting a real
                signal — this scan still completed successfully. It's common against a target sitting behind a
                reverse proxy / PaaS edge (Replit, Vercel, Heroku, Cloudflare, etc.): the script expects to talk
                directly to the origin server and gets an unexpected response shape from the edge layer instead, so
                it errors or times out rather than producing a false result. A bare, unproxied host typically shows
                zero script errors.
              </p>
            )}
            {showAllScripts && (
              <div className="space-y-2 mt-2">
                {otherScripts.map((f, i) => <ScriptResultRow key={`${f.scriptId}-${i}`} f={f} />)}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex items-start justify-between gap-3 flex-wrap">
        <p className="text-[9px] font-mono text-[#52525b]">
          Scanned {result.resolvedIp} with nmap {result.nmapVersion} in {Math.round(result.durationMs / 1000)}s
          · {result.scanArgs.join(' ')}
        </p>
        {scan.rawXml && (
          <button
            type="button"
            onClick={() => downloadRawXml(scan)}
            className="flex items-center gap-1.5 px-2 py-1 rounded bg-black border border-[#27272a] hover:border-[#22c55e]/40 hover:text-[#22c55e] text-[#a1a1aa] text-[9px] font-mono uppercase tracking-wide transition-all cursor-pointer shrink-0"
            title="Download nmap's unmodified -oX output — independent proof of exactly what ran and what it returned"
          >
            <Download className="w-3 h-3" />
            <span>Download raw nmap XML</span>
          </button>
        )}
      </div>
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
                      <span>{scan.result.ports.filter((p) => p.state === 'open').length} open port(s), {scan.result.vulnFindings.filter((f) => outcomeOf(f) === 'finding').length} DETECTED</span>
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
