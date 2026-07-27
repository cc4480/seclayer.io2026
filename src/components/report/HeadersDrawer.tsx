import { Terminal, ChevronDown, ChevronUp } from 'lucide-react';
import { Scan, Finding } from '../../types.js';

// Collapsible raw-diagnostics drawer: the exact evidence captured during the
// scan — resolved network data, per-path probe results, observed header state,
// and active-probe outcomes. All real output from this run.
interface Props {
  scan: Scan;
  findings: Finding[];
  showRaw: boolean;
  setShowRaw: (v: boolean) => void;
}

export default function HeadersDrawer({ scan, findings, showRaw, setShowRaw }: Props) {
  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <button
        onClick={() => setShowRaw(!showRaw)}
        aria-expanded={showRaw}
        className="w-full flex items-center justify-between text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider cursor-pointer"
      >
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-[#22c55e]" aria-hidden="true" />
          <span>Diagnostic Raw Headers & Outputs</span>
        </div>
        {showRaw ? <ChevronUp className="w-4 h-4" aria-hidden="true" /> : <ChevronDown className="w-4 h-4" aria-hidden="true" />}
      </button>

      {showRaw && (
        <div className="mt-5 space-y-4 pt-4 border-t border-[#27272a] animate-fade-in">
          <p className="text-[#52525b] text-[11px] leading-relaxed font-mono">
            The exact evidence captured during this scan of {scan.url} — resolved network data, per-path probe results, and observed header state. Everything below is real output from this run.
          </p>

          {!scan.evidence ? (
            <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-500 border border-[#27272a]">
              Raw diagnostic evidence was not captured for this scan (it predates evidence logging). Re-run the scan to populate it.
            </div>
          ) : (
            <div className="bg-black p-4 rounded font-mono text-[10px] text-zinc-400 space-y-2 border border-[#27272a] max-h-96 overflow-y-auto">
              <span className="text-[#52525b] text-[9px] uppercase font-bold block mb-1">Captured scan trace</span>
              <p className="text-zinc-200">GET / HTTP/1.1</p>
              <p className="text-zinc-200">Host: {scan.url.replace(/https?:\/\//i, '').replace(/\/.*$/, '')}</p>
              <p className="text-[#52525b]">User-Agent: Seclayer-Security-Scanner/2.0 (seclayer.io)</p>
              <p className="text-zinc-300">→ HTTP {scan.evidence.responseStatus} over {scan.evidence.protocol}</p>

              <p className="text-[#22c55e] font-bold mt-3">[EASM — DNS &amp; PERIMETER]</p>
              <p className="text-zinc-400">Resolved IP: {scan.evidence.resolvedIp || '(not resolved)'}</p>
              <p className="text-zinc-400">Authoritative nameserver: {scan.evidence.nameserver || '(not disclosed)'}</p>
              <p className="text-zinc-400">Subdomains probed: {scan.evidence.subdomainsChecked} · live: {scan.evidence.liveSubdomains.length}</p>
              {scan.evidence.liveSubdomains.slice(0, 8).map((d, i) => (
                <p key={i} className="text-amber-400">  ↳ {d}</p>
              ))}

              <p className="text-[#22c55e] font-bold mt-3">[DAST — SENSITIVE PATH PROBES]</p>
              {scan.evidence.probedPaths.map((p, i) => (
                <p key={i} className="text-zinc-200">
                  Path: <span className={p.exposed ? 'text-red-400' : 'text-amber-400'}>{p.path}</span> — HTTP {p.status} <span className={p.exposed ? 'text-red-400' : 'text-[#22c55e]'}>({p.exposed ? 'EXPOSED' : 'locked down'})</span>
                </p>
              ))}

              <p className="text-[#22c55e] font-bold mt-4">[HTTP RESPONSE]</p>
              <p className="text-zinc-300">Server: {scan.evidence.serverHeader || '(suppressed)'}</p>
              <p className="text-zinc-300">Scanned at: {new Date(scan.evidence.scannedAt).toUTCString()}</p>

              <p className="text-[#22c55e] font-bold mt-4">[IAST — DEFENSIVE HEADERS]</p>
              {['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy'].map((h) => {
                const present = scan.evidence!.presentSecurityHeaders.includes(h);
                return (
                  <p key={h} className="text-zinc-450">{h}: <span className={present ? 'text-[#22c55e]' : 'text-amber-400'}>{present ? 'PRESENT' : 'ABSENT'}</span></p>
                );
              })}

              <p className="text-red-500 font-bold mt-4">[RED TEAM — ACTIVE EXPLOIT PROBES]</p>
              {!scan.evidence.activeProbesRun ? (
                <p className="text-zinc-400">Skipped — domain ownership not verified (passive recon only).</p>
              ) : findings.filter(f => f.category === 'RED_TEAM' || f.category === 'API_SEC').length > 0 ? (
                findings.filter(f => f.category === 'RED_TEAM' || f.category === 'API_SEC').map((f, i) => (
                  <p key={i} className="text-red-300">{`✗ ${f.title} — ${f.severity.toUpperCase()} confirmed`}</p>
                ))
              ) : (
                <p className="text-[#22c55e]">Active probes ran — no exploitable injection/SSRF/API signatures confirmed.</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
