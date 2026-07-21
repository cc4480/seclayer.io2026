import type { Dispatch, SetStateAction } from 'react';
import { Zap, Check, Clipboard, AlertTriangle, Sparkles, Copy } from 'lucide-react';
import { Finding } from '../../types.js';
import { isProven } from '../../../server/scoring.js';
import { SEVERITY_TOKENS } from '../../lib/severity.js';
import EvidenceReceipt from './EvidenceReceipt.js';

export interface FindingCardProps {
  finding: Finding;
  copiedCodeId: string | null;
  handleCopyCode: (id: string, text: string) => void;
  expandedApiRows: Record<string, boolean>;
  setExpandedApiRows: Dispatch<SetStateAction<Record<string, boolean>>>;
  suppressInputId: string | null;
  setSuppressInputId: (id: string | null) => void;
  suppressReason: string;
  setSuppressReason: (v: string) => void;
  isSuppressing: boolean;
  suppressError: string | null;
  setSuppressError: (v: string | null) => void;
  handleSaveSuppression: (finding: Finding) => void;
  handleRemoveSuppressionDirectly: (title: string) => void;
}

export default function FindingCard(props: FindingCardProps) {
  const {
    finding, copiedCodeId, handleCopyCode, expandedApiRows, setExpandedApiRows,
    suppressInputId, setSuppressInputId, suppressReason, setSuppressReason,
    isSuppressing, suppressError, setSuppressError, handleSaveSuppression, handleRemoveSuppressionDirectly,
  } = props;

  // Severity chip styling from the shared token map (single source of truth).
  const severityColor = finding.isFalsePositive
    ? 'bg-zinc-800 text-zinc-400 border border-zinc-700/60 font-medium'
    : (SEVERITY_TOKENS[finding.severity]?.chip ?? 'bg-black text-[#52525b] border border-[#27272a]');

  return (
    <div
      className={`border rounded p-5 transition-colors shadow ${
        finding.isFalsePositive
          ? 'bg-[#0f0f11]/60 border-zinc-800 border-dashed opacity-70 hover:border-zinc-750'
          : 'bg-black border-[#27272a]/90 hover:border-[#3f3f46]'
      }`}
    >
      {/* Title element */}
      <div className="flex flex-wrap items-start justify-between gap-2 mb-3">
        <div className="flex items-center space-x-2.5">
          <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${severityColor}`}>
            {finding.isFalsePositive ? 'SUPPRESSED (FP)' : finding.severity}
          </span>
          {!finding.isFalsePositive && isProven(finding) && (
            <span className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border border-[#22c55e]/40 bg-[#22c55e]/10 text-[#22c55e] flex items-center gap-1">
              <Zap className="w-2.5 h-2.5 shrink-0" /> Proven
            </span>
          )}
          {finding.confidence && (
            <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded border bg-black ${
              finding.confidence === 'high' ? 'border-[#22c55e]/30 text-[#22c55e]' :
              finding.confidence === 'medium' ? 'border-amber-500/30 text-amber-500' :
              'border-zinc-500/30 text-zinc-500'
            }`}>
              Conf: {finding.confidence}
            </span>
          )}
          {finding.owasp && (
            <span
              title={finding.owasp}
              className="text-[9px] font-mono uppercase px-2 py-0.5 rounded border border-purple-500/30 bg-black text-purple-300"
            >
              {finding.owasp.split(' – ')[0]}
            </span>
          )}
          <h5 className={`text-xs font-bold font-mono tracking-tight leading-snug ${finding.isFalsePositive ? 'text-zinc-500 line-through' : 'text-white'}`}>{finding.title}</h5>
        </div>
        <span className="text-[10px] text-[#52525b] font-mono tracking-wide">ID: {finding.id}</span>
      </div>

      {/* Detail summary */}
      <div className="mb-4">
        <p className={`text-[13px] font-sans leading-relaxed pl-1 ${finding.isFalsePositive ? 'text-zinc-500' : 'text-zinc-300'}`}>
          {finding.description}
        </p>
        {finding.impact && !finding.isFalsePositive && (
          <p className="text-[12px] font-sans leading-relaxed mt-2 pl-1 text-amber-300/90">
            <strong className="text-amber-400 font-semibold">Impact:</strong> {finding.impact}
          </p>
        )}
      </div>

      {!finding.isFalsePositive && finding.evidence && (
        <EvidenceReceipt finding={finding} expandedApiRows={expandedApiRows} setExpandedApiRows={setExpandedApiRows} handleCopyCode={handleCopyCode} />
      )}

      {/* Detailed Remediation code fix payload block */}
      <div className={`p-4 rounded border ${finding.isFalsePositive ? 'bg-zinc-950/40 border-zinc-850' : 'bg-[#0c0c0e] border-[#27272a]'}`}>
        <div className="flex justify-between items-center mb-1.5">
          <span className="text-[#52525b] font-mono text-[9px] uppercase tracking-wider">Automated Remediation Fix</span>
          <button
            onClick={() => handleCopyCode(finding.id, finding.fix)}
            className="text-[10px] font-mono text-[#52525b] hover:text-[#22c55e] flex items-center space-x-1 transition-colors cursor-pointer"
          >
            {copiedCodeId === finding.id ? (
              <><Check className="w-3 h-3 text-[#22c55e] shrink-0" /><span>Copied fix</span></>
            ) : (
              <><Clipboard className="w-3 h-3 text-[#52525b] shrink-0" /><span>Copy directive</span></>
            )}
          </button>
        </div>
        <div className="overflow-x-auto max-h-48 scrollbar-thin">
          <code className={`text-[11px] font-mono whitespace-pre leading-relaxed block py-1 ${finding.isFalsePositive ? 'text-zinc-600' : 'text-zinc-300'}`}>
            {finding.fix}
          </code>
        </div>
      </div>

      {/* "Fix with AI" — a ready-to-paste prompt for the user's own coding agent */}
      {finding.agentPrompt && !finding.isFalsePositive && (
        <div className="mt-3 p-4 rounded border border-purple-500/20 bg-purple-500/5">
          <div className="flex justify-between items-center mb-1.5">
            <span className="text-purple-300/80 font-mono text-[9px] uppercase tracking-wider flex items-center space-x-1.5">
              <Sparkles className="w-3 h-3" />
              <span>Fix With AI — paste into Cursor / Claude Code / Windsurf</span>
            </span>
            <button
              onClick={() => handleCopyCode(`agent-${finding.id}`, finding.agentPrompt!)}
              className="text-[10px] font-mono text-[#52525b] hover:text-purple-300 flex items-center space-x-1 transition-colors cursor-pointer"
            >
              {copiedCodeId === `agent-${finding.id}` ? (
                <><Check className="w-3 h-3 text-purple-300 shrink-0" /><span>Copied prompt</span></>
              ) : (
                <><Clipboard className="w-3 h-3 text-[#52525b] shrink-0" /><span>Copy prompt</span></>
              )}
            </button>
          </div>
          <div className="overflow-x-auto max-h-48 scrollbar-thin">
            <code className="text-[11px] font-mono whitespace-pre-wrap leading-relaxed block py-1 text-zinc-300">
              {finding.agentPrompt}
            </code>
          </div>
        </div>
      )}

      {/* False Positives Management UI Drawer Toggle */}
      <div className="mt-4 border-t border-[#27272a]/30 pt-3 flex flex-col">
        {suppressInputId === finding.id ? (
          <div className="bg-[#121214] border border-[#27272a]/80 p-3.5 rounded space-y-3 animate-fade-in">
            <label className="text-[10px] font-mono uppercase tracking-wider text-amber-500/90 font-bold block">
              Define Suppression Justification (Audit Trail)
            </label>
            <p className="text-[11px] text-[#52525b] font-mono">
              By declaring this finding a false positive or an excluded risk, its impact is subtracted from the final security score and rating, and the exemption will apply to future scans of this URL.
            </p>
            <input
              type="text"
              autoFocus
              placeholder="e.g. Host-level firewalls handle payload blocking / acceptable legacby boundary match."
              value={suppressReason}
              onChange={(e) => setSuppressReason(e.target.value)}
              className="w-full bg-black border border-[#27272a] rounded px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#22c55e] placeholder-zinc-700"
            />
            {suppressError && (
              <p className="text-[10px] font-mono text-red-400">{suppressError}</p>
            )}
            <div className="flex justify-end space-x-2">
              <button
                onClick={() => { setSuppressInputId(null); setSuppressError(null); }}
                className="px-2.5 py-1.5 border border-[#27272a] text-[#a1a1aa] hover:text-white bg-zinc-900 hover:bg-zinc-800 text-[10px] font-mono uppercase rounded cursor-pointer transition-all"
              >
                Close
              </button>
              <button
                onClick={() => handleSaveSuppression(finding)}
                disabled={isSuppressing}
                className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/35 text-[10px] font-mono uppercase rounded font-bold cursor-pointer transition-all"
              >
                {isSuppressing ? 'Processing...' : 'Suppress Finding'}
              </button>
            </div>
          </div>
        ) : (
          <div className="flex justify-between items-center">
            {finding.isFalsePositive ? (
              <div className="flex items-center justify-between w-full bg-zinc-900/40 border border-dashed border-zinc-800/80 px-3.5 py-2 rounded">
                <p className="text-[11px] font-mono text-zinc-500 flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-zinc-600 shrink-0" />
                  <span><strong>Exempted Risk:</strong> {finding.suppressionReason || 'Declared acceptable false positive risk.'}</span>
                </p>
                <button
                  disabled={isSuppressing}
                  onClick={() => handleRemoveSuppressionDirectly(finding.title)}
                  className="text-[10px] font-mono text-red-400 hover:text-red-300 underline cursor-pointer select-none transition-colors"
                >
                  Remove Exemption
                </button>
              </div>
            ) : (
              <>
                <span className="text-[10px] font-mono text-[#52525b]">Is this threat checked or invalid?</span>
                <button
                  onClick={() => { setSuppressInputId(finding.id); setSuppressReason(''); setSuppressError(null); }}
                  className="px-2.5 py-1 bg-zinc-900 border border-zinc-800/80 hover:border-amber-500/20 text-[#71717a] hover:text-amber-400 text-[10px] font-mono uppercase tracking-wider transition-all flex items-center space-x-1.5 cursor-pointer"
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Mark False Positive</span>
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
