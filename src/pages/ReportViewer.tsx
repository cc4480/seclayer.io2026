import { useState } from 'react';
import { ArrowLeft, Download, Share2, Clock, Check, AlertTriangle, Sparkles } from 'lucide-react';
import { Scan } from '../types.js';
import { buildScanFixPrompt, actionableFindings } from '../lib/scanFixPrompt.js';
// Single source of truth for every risk figure/label shown here — the same
// module the server scanner and read-model score from. No risk value or label
// in this component is computed locally.
import { deriveSecurityPosture, bannerForPosture } from '../../server/scoring.js';
import { tokenForRiskLabel } from '../lib/severity.js';
import ScoreGauge from '../components/ScoreGauge.js';
import SeverityBar from '../components/SeverityBar.js';
import { downloadReportPdf } from '../lib/reportPdf.js';
import { useSuppression } from '../hooks/useSuppression.js';
import { type SecCategory } from '../components/report/categories.js';
import CategoryTabBar from '../components/report/CategoryTabBar.js';
import OverviewTab from '../components/report/OverviewTab.js';
import FindingsPanel from '../components/report/FindingsPanel.js';
import HeadersDrawer from '../components/report/HeadersDrawer.js';

interface ReportViewerProps {
  scan: Scan;
  previousScan?: Scan;
  onBack: () => void;
  onRefreshScans?: () => void;
}

export default function ReportViewer({ scan, previousScan, onBack, onRefreshScans }: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | SecCategory>('OVERVIEW');
  const [showRaw, setShowRaw] = useState(false);
  const [showReasoning, setShowReasoning] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedFixPrompt, setCopiedFixPrompt] = useState(false);
  const [copiedCodeId, setCopiedCodeId] = useState<string | null>(null);
  const [expandedApiRows, setExpandedApiRows] = useState<Record<string, boolean>>({});

  // Suppression / false-positive form state + handlers.
  const {
    suppressInputId, setSuppressInputId, suppressReason, setSuppressReason,
    isSuppressing, suppressError, setSuppressError, handleSaveSuppression, handleRemoveSuppressionDirectly,
  } = useSuppression(scan, onRefreshScans);

  const findings = scan.findings || [];
  // Derive the whole posture (score, grade, severity, posture rating, counts)
  // once, from the same shared module the server uses.
  const posture = deriveSecurityPosture(findings);
  const banner = bannerForPosture(findings);

  const handleShareClick = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handleCopyCode = (findingId: string, fixText: string) => {
    navigator.clipboard.writeText(fixText);
    setCopiedCodeId(findingId);
    setTimeout(() => setCopiedCodeId(null), 2000);
  };

  const handleDownloadPdf = () => downloadReportPdf(scan, posture, findings);

  // One consolidated, agent-ready remediation prompt covering every actionable
  // finding — the single "Complete Fix Prompt" hand-off (replaces per-finding ones).
  const fixableCount = actionableFindings(findings).length;
  const handleCopyFixPrompt = () => {
    navigator.clipboard.writeText(buildScanFixPrompt(scan));
    setCopiedFixPrompt(true);
    setTimeout(() => setCopiedFixPrompt(false), 2000);
  };

  // A scan that never completed has no real findings/score to report — showing
  // the normal report for it would misrepresent an empty findings list (from a
  // failed/incomplete scan) as a clean "no issues found" result.
  if (scan.status !== 'complete') {
    return (
      <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
        <div className="max-w-3xl mx-auto space-y-6 animate-fade-in">
          <button
            onClick={onBack}
            className="flex items-center space-x-2 text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4 text-[#22c55e]" />
            <span>Audit Workspace</span>
          </button>
          <div className="bg-[#0c0c0e] border border-[#f87171]/25 rounded p-8 flex items-start space-x-4">
            <AlertTriangle className="w-5 h-5 text-[#f87171] shrink-0 mt-0.5" />
            <div>
              <h2 className="text-white font-mono font-bold text-sm uppercase tracking-wider">
                {scan.status === 'failed' ? 'Scan Failed' : scan.status === 'canceled' ? 'Scan Canceled' : 'Scan Not Yet Complete'}
              </h2>
              <p className="text-[#a1a1aa] text-xs font-mono mt-2">
                {scan.status === 'failed'
                  ? (scan.error || 'This scan could not be completed. No report is available.')
                  : scan.status === 'canceled'
                  ? 'This scan was canceled before it finished. Its credit was refunded — launch a new scan whenever you\'re ready.'
                  : `This scan is still ${scan.status} — its report isn't ready yet.`}
              </p>
              <p className="text-[#52525b] text-xs font-mono mt-3">Target: {scan.url}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-5xl mx-auto space-y-8 animate-fade-in">

        {/* Navigation Action Header */}
        <div className="flex items-center justify-between">
          <button
            onClick={onBack}
            className="flex items-center space-x-2 text-[#a1a1aa] hover:text-white font-mono text-xs uppercase tracking-wider transition-colors cursor-pointer"
            id="report-back-btn"
          >
            <ArrowLeft className="w-4 h-4 text-[#22c55e]" />
            <span>Audit Workspace</span>
          </button>

          <div className="flex items-center space-x-3">
            {fixableCount > 0 && (
              <button
                onClick={handleCopyFixPrompt}
                title={`One complete prompt to fix all ${fixableCount} issue(s) — paste into Claude Code, Codex, Replit, Cursor, or Windsurf`}
                className="px-3.5 py-1.5 bg-purple-500/10 border border-purple-500/40 hover:border-purple-400 text-purple-200 hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
                id="report-fixprompt-btn"
              >
                {copiedFixPrompt ? <Check className="w-3.5 h-3.5 text-purple-300" /> : <Sparkles className="w-3.5 h-3.5 text-purple-300" />}
                <span>{copiedFixPrompt ? 'Copied Fix Prompt' : `Copy Fix Prompt (${fixableCount})`}</span>
              </button>
            )}
            <button
              onClick={handleShareClick}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-share-btn"
            >
              {copiedLink ? <Check className="w-3.5 h-3.5 text-[#22c55e]" /> : <Share2 className="w-3.5 h-3.5 text-[#52525b]" />}
              <span>{copiedLink ? 'Copied' : 'Share Link'}</span>
            </button>
            <button
              onClick={handleDownloadPdf}
              className="px-3.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer"
              id="report-download-btn"
            >
              <Download className="w-3.5 h-3.5 text-[#52525b]" />
              <span>Export Audit Findings</span>
            </button>
          </div>
        </div>

        {/* Audit Meta Summary Card */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded overflow-hidden shadow-2xl">
          <div className="bg-black/40 p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6 border-b border-[#27272a]">
            <div>
              <div className="flex items-center space-x-2.5">
                <span className="font-mono text-xs text-[#52525b] select-none">[Target Host]</span>
                <strong className="font-mono text-sm text-white tracking-wide break-all select-all">{scan.url}</strong>
              </div>
              <p className="text-[#52525b] text-xs mt-2 font-mono flex items-center space-x-4">
                <span className="flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5 text-[#52525b]" />
                  <span>Assessed: {new Date(scan.createdAt).toLocaleDateString()}</span>
                </span>
                <span>•</span>
                <span>Job ID: {scan.id}</span>
              </p>
            </div>

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 shrink-0">
              {previousScan && typeof previousScan.score === 'number' && (
                <div className="p-4 rounded border border-zinc-800 bg-black flex items-center space-x-5 h-full">
                  <div className="text-right">
                    <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Score Delta</span>
                    <span className={`text-xl font-mono font-black block mt-1 ${scan.score > previousScan.score ? 'text-green-500' : scan.score < previousScan.score ? 'text-red-500' : 'text-zinc-500'}`}>
                      {scan.score > previousScan.score ? '+' : ''}{scan.score - previousScan.score}
                    </span>
                  </div>
                  <div className="border-l border-zinc-800 pl-4 text-right">
                    <span className="text-[9px] font-mono text-zinc-500 uppercase block tracking-wider select-none">Findings Delta</span>
                    <span className={`text-xl font-mono font-black block mt-1 ${findings.length < (previousScan.findings || []).length ? 'text-green-500' : findings.length > (previousScan.findings || []).length ? 'text-amber-500' : 'text-zinc-500'}`}>
                      {findings.length > (previousScan.findings || []).length ? '+' : ''}{findings.length - (previousScan.findings || []).length}
                    </span>
                  </div>
                </div>
              )}
              <div className="p-4 rounded-lg border border-[#27272a] bg-black/30 flex items-center gap-5 h-full shrink-0">
                <ScoreGauge score={posture.score} grade={posture.grade} size={124} />
                <div className="border-l border-[#27272a] pl-5 space-y-3">
                  <div>
                    <span className="text-[10px] font-mono text-[#71717a] uppercase block tracking-wider select-none">Posture Rating</span>
                    <span className={`text-sm font-bold uppercase tracking-wider block mt-1 ${tokenForRiskLabel(posture.postureRating).text}`}>{posture.postureRating}</span>
                  </div>
                  <div>
                    <span className="text-[10px] font-mono text-[#71717a] uppercase block tracking-wider select-none mb-1.5">Findings</span>
                    <SeverityBar counts={posture.findingsBySeverity} className="w-32" />
                    <span className="text-[10px] font-mono text-[#71717a] mt-1.5 block">
                      {posture.activeCount === 0 ? 'None found' : `${posture.confirmedCount} confirmed · ${posture.needsVerificationCount} to verify`}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Core AppSec Framework Segmented Matrix tabs */}
          <CategoryTabBar activeTab={activeTab} setActiveTab={setActiveTab} findings={findings} />

          <div className="p-6">
            {activeTab === 'OVERVIEW' ? (
              <OverviewTab
                scan={scan}
                banner={banner}
                findings={findings}
                showReasoning={showReasoning}
                setShowReasoning={setShowReasoning}
                setActiveTab={setActiveTab}
              />
            ) : (
              <FindingsPanel
                findings={findings}
                activeTab={activeTab}
                copiedCodeId={copiedCodeId}
                handleCopyCode={handleCopyCode}
                expandedApiRows={expandedApiRows}
                setExpandedApiRows={setExpandedApiRows}
                suppressInputId={suppressInputId}
                setSuppressInputId={setSuppressInputId}
                suppressReason={suppressReason}
                setSuppressReason={setSuppressReason}
                isSuppressing={isSuppressing}
                suppressError={suppressError}
                setSuppressError={setSuppressError}
                handleSaveSuppression={handleSaveSuppression}
                handleRemoveSuppressionDirectly={handleRemoveSuppressionDirectly}
              />
            )}
          </div>
        </div>

        {/* Raw Header Output Inspection drawer */}
        <HeadersDrawer scan={scan} findings={findings} showRaw={showRaw} setShowRaw={setShowRaw} />

      </div>
    </div>
  );
}
