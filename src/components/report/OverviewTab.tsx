import { Sparkles, ChevronDown, ChevronUp, Eye, AlertCircle, AlertTriangle } from 'lucide-react';
import { Scan, Finding } from '../../types.js';
import { bannerForPosture } from '../../../server/scoring.js';
import SeverityBar from '../SeverityBar.js';
import BrowserFrame from '../BrowserFrame.js';
import { categoryTabLabels, getCategoryCount, getCategorySeverity, getCategoryColor, type SecCategory } from './categories.js';
import EvidencePanels from './EvidencePanels.js';
import ScanCoveragePanel from './ScanCoveragePanel.js';

interface Props {
  scan: Scan;
  banner: ReturnType<typeof bannerForPosture>;
  findings: Finding[];
  showReasoning: boolean;
  setShowReasoning: (v: boolean) => void;
  setActiveTab: (t: SecCategory) => void;
}

export default function OverviewTab({ scan, banner, findings, showReasoning, setShowReasoning, setActiveTab }: Props) {
  return (
    <div className="space-y-6 animate-fade-in">
      {/* Executive Assessment summary */}
      <div className="bg-black/40 p-5 rounded border border-[#27272a] relative">
        <div className="absolute right-4 top-4 font-mono text-[9px] text-[#22c55e] uppercase border border-[#22c55e]/30 px-2 py-0.5 rounded flex items-center space-x-1 select-none">
          <Sparkles className="w-3 h-3" />
          <span>DeepSeek AI Analyst Verified</span>
        </div>
        <h3 className="text-xs font-bold font-mono text-white mb-2 uppercase tracking-wider flex items-center space-x-1.5">
          <span>Executive Summary</span>
        </h3>
        <p className="text-zinc-200 text-[13px] font-sans leading-relaxed prose-invert">
          {scan.aiSummary || 'Security pipeline completed. Report compiles diagnostics...'}
        </p>

        {scan.aiReasoning && (
          <div className="mt-4 pt-3 border-t border-[#27272a]/60">
            <button
              onClick={() => setShowReasoning(!showReasoning)}
              className="w-full flex items-center justify-between text-[#71717a] hover:text-white font-mono text-[10px] uppercase tracking-wider cursor-pointer"
            >
              <span className="flex items-center space-x-1.5">
                <Sparkles className="w-3 h-3 text-purple-300" />
                <span>How the AI assessed this (chain-of-thought)</span>
              </span>
              {showReasoning ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
            {showReasoning && (
              <div className="mt-2.5 p-3 bg-black/60 border border-[#27272a] rounded max-h-72 overflow-y-auto scrollbar-thin animate-fade-in">
                <code className="text-[10px] font-mono whitespace-pre-wrap leading-relaxed text-zinc-400">
                  {scan.aiReasoning}
                </code>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Detailed executive breakdown — DeepSeek's deeper, structured analysis. */}
      {scan.executiveBreakdown && (
        <div className="bg-black/40 p-5 rounded border border-[#27272a] space-y-5">
          <h3 className="text-xs font-bold font-mono text-white uppercase tracking-wider flex items-center space-x-1.5">
            <Sparkles className="w-3.5 h-3.5 text-purple-300" />
            <span>Detailed Executive Breakdown</span>
          </h3>

          <p className="text-zinc-200 text-[13px] font-sans leading-relaxed">
            {scan.executiveBreakdown.overview}
          </p>

          {scan.executiveBreakdown.riskAreas.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-[10px] font-mono text-[#71717a] uppercase tracking-wider font-bold">Key Risk Areas</h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {scan.executiveBreakdown.riskAreas.map((r, idx) => (
                  <div key={idx} className="p-3.5 bg-black border border-[#27272a] rounded-lg">
                    <span className="text-[13px] font-sans font-semibold text-white block mb-1">{r.area}</span>
                    <span className="text-[12px] font-sans text-zinc-400 leading-relaxed">{r.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="p-3.5 rounded-lg border border-amber-500/20 bg-amber-500/5">
            <h4 className="text-[10px] font-mono text-amber-400 uppercase tracking-wider font-bold mb-1.5">Business Impact</h4>
            <p className="text-[12px] font-sans text-amber-100/90 leading-relaxed">{scan.executiveBreakdown.businessImpact}</p>
          </div>

          {scan.executiveBreakdown.priorityActions.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-[10px] font-mono text-[#71717a] uppercase tracking-wider font-bold">Priority Actions (Ranked)</h4>
              <ol className="space-y-2">
                {scan.executiveBreakdown.priorityActions.map((action, idx) => (
                  <li key={idx} className="flex items-start space-x-2.5 text-[12px] font-sans text-zinc-200 leading-relaxed">
                    <span className="shrink-0 w-4 h-4 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 text-[#22c55e] text-[9px] font-mono font-bold flex items-center justify-center mt-0.5">{idx + 1}</span>
                    <span>{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}

      {/* Grid layout of the security pillars */}
      <div className="space-y-3">
        <h4 className="text-[10px] font-mono text-[#52525b] uppercase tracking-wider pl-1 font-bold">Dynamic Application Security & Pen-Testing Pillars</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {categoryTabLabels.map(cell => {
            const count = getCategoryCount(findings, cell.key);
            const stateText = getCategorySeverity(findings, cell.key);
            const colorClass = getCategoryColor(findings, cell.key);
            const cellCounts = findings
              .filter(f => f.category === cell.key && !f.isFalsePositive)
              .reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {} as Record<string, number>);

            return (
              <div
                key={cell.key}
                onClick={() => setActiveTab(cell.key)}
                className={`p-4 rounded-lg border transition-all cursor-pointer hover:border-[#3f3f46] hover:bg-black/40 ${colorClass}`}
              >
                <div className="flex justify-between items-start mb-2">
                  <cell.icon className="w-5 h-5 opacity-80" />
                  <span className="text-[10px] uppercase font-mono tracking-wider font-extrabold">{cell.label}</span>
                </div>
                <span className="text-[9px] font-mono text-zinc-500 block uppercase font-bold">{cell.term}</span>
                <div className="mt-3 flex items-baseline justify-between">
                  <span className="text-[10px] font-mono font-semibold">{stateText}</span>
                  <span className="text-lg font-mono font-black">{count}</span>
                </div>
                <SeverityBar counts={cellCounts} className="mt-2.5" />
              </div>
            );
          })}
        </div>
      </div>

      {/* Real diagnostic evidence behind the findings. */}
      <EvidencePanels scan={scan} />

      {/* Full-transparency coverage: exactly which checks ran against the target. */}
      <ScanCoveragePanel scan={scan} />

      {/* Visual recon — a headless-browser screenshot of the target's landing page. */}
      {scan.evidence?.screenshot && (
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h5 className="text-[10px] font-mono text-white uppercase tracking-wider font-bold flex items-center space-x-1.5">
              <Eye className="w-3.5 h-3.5 text-[#22c55e]" />
              <span>Visual Recon — Target Landing Page</span>
            </h5>
            <span className="text-[9px] font-mono text-[#71717a]">
              Captured {new Date(scan.evidence.screenshot.capturedAt).toLocaleString()} · {scan.evidence.screenshot.width}×{scan.evidence.screenshot.height}
            </span>
          </div>
          <a href={scan.evidence.screenshot.dataUri} target="_blank" rel="noreferrer" className="block hover:opacity-95 transition-opacity">
            <BrowserFrame url={scan.url}>
              <img
                src={scan.evidence.screenshot.dataUri}
                alt={`Screenshot of ${scan.url}`}
                className="w-full h-auto block"
                loading="lazy"
              />
            </BrowserFrame>
          </a>
          <p className="text-[10px] font-sans text-[#71717a] leading-relaxed">
            Rendered by a headless browser as an anonymous visitor would see it. Click to open full size.
          </p>
        </div>
      )}

      {/* Severity-proportionate summary banner (bannerForPosture). */}
      {banner && (
        <div className={`rounded p-4 flex items-center space-x-3 border ${
          banner.level === 'critical' ? 'bg-red-950/20 border-red-500/20' :
          banner.level === 'warning' ? 'bg-amber-950/20 border-amber-500/20' :
          'bg-[#0c0c0e] border-[#27272a]'
        }`}>
          {banner.level === 'critical'
            ? <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
            : banner.level === 'warning'
            ? <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
            : <AlertCircle className="w-5 h-5 text-[#52525b] shrink-0" />}
          <div>
            <p className={`text-xs font-mono font-bold uppercase tracking-wide ${
              banner.level === 'notice' ? 'text-[#a1a1aa]' : 'text-white'
            }`}>{banner.title}</p>
            <p className={`text-[11px] font-mono mt-0.5 leading-relaxed ${
              banner.level === 'critical' ? 'text-red-300/80' :
              banner.level === 'warning' ? 'text-amber-200/80' :
              'text-[#71717a]'
            }`}>
              {banner.message}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
