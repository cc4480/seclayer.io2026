import { Scan } from '../../types.js';

// The two-column diagnostic evidence grid (EASM network/perimeter + DAST dynamic
// coverage), resolved from the actual scan rather than placeholder values.
export default function EvidencePanels({ scan }: { scan: Scan }) {
  if (!scan.evidence) return null;
  const ev = scan.evidence;
  const exposed = ev.probedPaths.filter(p => p.exposed);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
        <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Network & Attack Surface (EASM)</h5>
        <div className="font-mono text-xs space-y-2 text-zinc-400">
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Resolved IP:</span>
            <span className="text-zinc-300 text-right break-all">{ev.resolvedIp || 'not resolved'}</span>
          </div>
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Nameserver:</span>
            <span className="text-zinc-300 text-right break-all">{ev.nameserver || 'not disclosed'}</span>
          </div>
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Protocol / Status:</span>
            <span className="text-zinc-300 text-right">{ev.protocol} · HTTP {ev.responseStatus}</span>
          </div>
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Server Header:</span>
            <span className="text-zinc-300 text-right break-all">{ev.serverHeader || 'suppressed (good)'}</span>
          </div>
          <div className="flex justify-between gap-3">
            <span className="text-[#52525b] shrink-0">Live Subdomains:</span>
            <span className="text-right">
              {ev.liveSubdomains.length > 0
                ? <span className="text-amber-400 break-all">{ev.liveSubdomains.slice(0, 4).join(', ')}{ev.liveSubdomains.length > 4 ? ` +${ev.liveSubdomains.length - 4} more` : ''}</span>
                : <span className="text-zinc-500">none of {ev.subdomainsChecked} checked</span>}
            </span>
          </div>
        </div>
      </div>

      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5 space-y-3">
        <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold">Dynamic Coverage (DAST)</h5>
        <div className="font-mono text-xs space-y-2 text-zinc-400">
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Sensitive Paths:</span>
            <span className="text-right">
              {exposed.length > 0
                ? <span className="text-red-400 break-all">{exposed.map(p => p.path).join(', ')} exposed</span>
                : <span className="text-[#22c55e]">{ev.probedPaths.length} probed, all locked down</span>}
            </span>
          </div>
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Crawl Coverage:</span>
            <span className="text-zinc-300 text-right">
              {ev.crawl
                ? `${ev.crawl.pagesVisited} page(s), ${ev.crawl.endpointsDiscovered} endpoint(s)`
                : 'root only'}
            </span>
          </div>
          <div className="flex justify-between gap-3 border-b border-[#27272a]/40 pb-1.5">
            <span className="text-[#52525b] shrink-0">Params Fuzzed:</span>
            <span className="text-zinc-300 text-right">{ev.activeProbesRun ? (ev.crawl?.paramsTested ?? 0) : 'skipped (unverified)'}</span>
          </div>
          <div className="flex justify-between gap-3">
            <span className="text-[#52525b] shrink-0">Detected Libraries:</span>
            <span className="text-right break-all">
              {ev.detectedLibraries.length > 0
                ? ev.detectedLibraries.map((l, i) => (
                    <span key={i} className={l.vulnerable ? 'text-red-400' : 'text-zinc-300'}>{l.name} {l.version}{i < ev.detectedLibraries.length - 1 ? ', ' : ''}</span>
                  ))
                : <span className="text-zinc-500">none flagged</span>}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
