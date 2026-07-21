import { Globe, CheckCircle, ExternalLink } from 'lucide-react';
import { Scan } from '../../types.js';

// Scan-history tab: URL search + status/severity filters over the scan list,
// rendered as a clickable table that opens each scan's report.
interface Props {
  scans: Scan[];
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  filterStatus: string;
  setFilterStatus: (v: string) => void;
  filterSeverity: string;
  setFilterSeverity: (v: string) => void;
  onViewReport: (scanId: string) => void;
}

export default function ScansTab({
  scans, searchQuery, setSearchQuery, filterStatus, setFilterStatus, filterSeverity, setFilterSeverity, onViewReport,
}: Props) {
  const filteredScans = scans.filter((scan) => {
    if (searchQuery.trim() && !scan.url.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    if (filterStatus !== 'all') {
      if (filterStatus === 'complete' && scan.status !== 'complete') return false;
      if (filterStatus === 'failed' && scan.status !== 'failed') return false;
      if (filterStatus === 'active' && ['complete', 'failed', 'canceled'].includes(scan.status)) return false;
    }
    if (filterSeverity !== 'all') {
      if (scan.status !== 'complete' || scan.severity !== filterSeverity) return false;
    }
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filter controls */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between pb-4 border-b border-[#27272a]/20">
        <div className="w-full md:max-w-xs bg-black border border-[#27272a] rounded px-3 py-1.5 flex items-center focus-within:border-[#22c55e] transition-colors">
          <Globe className="w-4 h-4 text-[#52525b] mr-2 shrink-0" />
          <input
            type="text"
            placeholder="Search target URL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-transparent text-white text-xs font-mono focus:outline-none w-full placeholder-[#52525b]"
          />
        </div>

        <div className="flex gap-3 w-full md:w-auto flex-wrap">
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-black border border-[#27272a] rounded px-3 py-1.5 text-xs font-mono text-[#a1a1aa] focus:outline-none focus:border-[#22c55e] cursor-pointer"
          >
            <option value="all">All States</option>
            <option value="complete">Complete Only</option>
            <option value="failed">Failed Only</option>
            <option value="active">Active (Queued/Scanning/Analyzing)</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-black border border-[#27272a] rounded px-3 py-1.5 text-xs font-mono text-[#a1a1aa] focus:outline-none focus:border-[#22c55e] cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High Only</option>
            <option value="medium">Medium Only</option>
            <option value="low">Low Only</option>
            <option value="info">Info Only</option>
          </select>
        </div>
      </div>

      {filteredScans.length === 0 ? (
        <div className="text-center py-12 bg-black rounded border border-dashed border-[#27272a]">
          <span className="text-xs text-[#52525b] font-mono block mb-2">No audits matched your search criteria</span>
          <p className="text-[11px] text-[#52525b] max-w-sm mx-auto font-mono">Try adjusting your filters or URL search queries to view older audits.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#27272a] text-[#52525b] font-mono text-[10px] uppercase tracking-wider pb-3">
                <th className="py-3 px-4">Audited Target URL</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Postures Score</th>
                <th className="py-3 px-4">Vulnerabilities</th>
                <th className="py-3 px-4 text-right">Execution Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#27272a]/20 text-xs font-mono">
              {filteredScans.map((scan) => {
                let statusBadge = (
                  <span className="bg-black text-[#52525b] font-mono text-[9px] uppercase px-2 py-0.5 rounded border border-[#27272a]">{scan.status}</span>
                );
                if (scan.status === 'complete') {
                  statusBadge = (
                    <span className="bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e] font-mono text-[9px] uppercase px-2 py-0.5 rounded flex items-center space-x-1.5 w-fit">
                      <CheckCircle className="w-3 h-3 text-[#22c55e] shrink-0" />
                      <span>Complete</span>
                    </span>
                  );
                } else if (scan.status === 'queued') {
                  statusBadge = <span className="bg-blue-950/40 border border-[#27272a] text-blue-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">Queued</span>;
                } else if (scan.status === 'scanning') {
                  statusBadge = <span className="bg-purple-950/40 border border-[#27272a] text-purple-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">Scanning...</span>;
                } else if (scan.status === 'analyzing') {
                  statusBadge = <span className="bg-amber-950/40 border border-[#27272a] text-amber-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">Analyzing AI...</span>;
                } else if (scan.status === 'failed') {
                  statusBadge = <span className="bg-[#f87171]/10 border border-[#f87171]/25 text-[#f87171] font-mono text-[9px] uppercase px-2 py-0.5 rounded">Failed</span>;
                } else if (scan.status === 'canceled') {
                  statusBadge = <span className="bg-black text-[#71717a] font-mono text-[9px] uppercase px-2 py-0.5 rounded border border-[#3f3f46]">Canceled</span>;
                }

                const scoreColor =
                  !scan.score ? 'text-zinc-500' :
                  scan.score >= 90 ? 'text-[#22c55e]' :
                  scan.score >= 70 ? 'text-amber-400' : 'text-[#f87171]';

                let severityBadge = <span className="text-[#52525b] font-mono text-[10px]">—</span>;
                if (scan.status === 'complete' && scan.severity) {
                  const colorClass =
                    scan.severity === 'critical' || scan.severity === 'high' ? 'bg-[#f87171]/10 text-[#f87171] font-bold border border-[#f87171]/20' :
                    scan.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/10' :
                    'bg-black text-[#a1a1aa] border border-[#27272a]';
                  severityBadge = <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${colorClass}`}>{scan.severity}</span>;
                }

                return (
                  <tr key={scan.id} onClick={() => onViewReport(scan.id)} className="hover:bg-black transition-colors cursor-pointer group">
                    <td className="py-3.5 px-4 font-mono font-bold text-white max-w-xs truncate">
                      <span className="flex items-center space-x-1.5">
                        <Globe className="w-3.5 h-3.5 text-[#52525b] shrink-0" />
                        <span>{scan.url}</span>
                      </span>
                    </td>
                    <td className="py-3.5 px-4">{statusBadge}</td>
                    <td className="py-3.5 px-4 font-mono font-black text-sm">
                      {scan.score ? <span className={scoreColor}>{scan.score}</span> : <span className="text-[#52525b] font-mono text-xs font-normal">Pending</span>}
                    </td>
                    <td className="py-3.5 px-4">{severityBadge}</td>
                    <td className="py-3.5 px-4 text-right font-mono text-[11px] text-[#52525b] group-hover:text-[#22c55e] transition-colors">
                      <div className="flex items-center justify-end space-x-1.5">
                        <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
                        <ExternalLink className="w-3 h-3 text-[#27272a] group-hover:text-[#22c55e] transition-colors shrink-0" />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
