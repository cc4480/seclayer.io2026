import { RefreshCw, Cpu } from 'lucide-react';
import { useScanPolling } from '../hooks/useScanPolling.js';
import { buildScanLogs } from '../components/scanProgress/scanLogs.js';
import ScanConsole from '../components/scanProgress/ScanConsole.js';
import PollErrorScreen from '../components/scanProgress/PollErrorScreen.js';

interface ScanProgressProps {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onCancel: () => void;
}

export default function ScanProgress({ scanId, onScanFinished, onCancel }: ScanProgressProps) {
  const { scan, progressPercent, pollError } = useScanPolling(scanId, onScanFinished, onCancel);
  const logs = buildScanLogs(scan);

  // Polling has permanently failed — surface it instead of spinning forever.
  if (pollError) {
    return <PollErrorScreen message={pollError} onBack={onCancel} />;
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-20 px-6 flex items-center justify-center">
      <div className="max-w-2xl w-full space-y-8 bg-[#0c0c0e] border border-[#27272a] p-8 rounded shadow-2xl relative overflow-hidden">

        {/* Background visual highlight */}
        <div className="absolute right-0 top-0 bg-[#22c55e]/5 w-96 h-96 rounded-full blur-3xl pointer-events-none" />

        <div className="text-center space-y-4">
          <div className="relative inline-flex items-center justify-center w-20 h-20 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded-full mb-2">
            <RefreshCw className="w-8 h-8 text-[#22c55e] animate-spin" />
            <div className="absolute inset-2 border-2 border-dashed border-[#22c55e]/10 rounded-full" />
          </div>

          <div>
            <span className="text-[10px] font-mono text-[#22c55e] uppercase tracking-widest block font-bold mb-1">
              Active Black-Box Penetration Audit
            </span>
            <h1 className="text-xl font-bold font-mono text-white max-w-md mx-auto truncate select-all">
              {scan?.url || 'Awaiting connection...'}
            </h1>
          </div>
        </div>

        {/* Dynamic progression loader */}
        <div className="space-y-3">
          <div className="flex justify-between items-baseline font-mono text-xs">
            <span className="text-[#52525b]">Scan Pipeline Progression</span>
            <span className="text-[#22c55e] font-bold">{progressPercent}%</span>
          </div>
          <div className="w-full bg-black h-2.5 rounded overflow-hidden border border-[#27272a] relative after:absolute after:inset-0 after:bg-gradient-to-r after:from-transparent after:via-[#22c55e]/15 after:to-transparent after:animate-shimmer after:pointer-events-none">
            <div
              className="bg-gradient-to-r from-[#22c55e] to-emerald-400 h-full transition-all duration-700 rounded-full relative"
              style={{ width: `${progressPercent}%` }}
            >
              {/* Pulsing shadow tip emitter */}
              <span className="absolute right-0 top-0 bottom-0 w-3 bg-white/45 blur-[1.5px] rounded-full animate-pulse" />
            </div>
          </div>

          {/* Secondary Non-Animated Buffer Status Bar */}
          <div className="pt-1.5 pb-2.5 space-y-1 border-t border-[#27272a]/20 mt-1">
            <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#22c55e] inline-block animate-pulse" />
                <span>Buffer Sub-Task: <span className="text-zinc-350 normal-case font-bold">{
                  scan?.status === 'queued' ? 'Validating target & resolving DNS' :
                  scan?.status === 'scanning' ? 'Headers, secrets, libraries, subdomains & path probing' :
                  scan?.status === 'analyzing' ? 'Active injection/API probes & report generation' :
                  scan?.status === 'complete' ? 'Report compiled & saved' :
                  'Initializing target pipeline...'
                }</span></span>
              </span>
              <span className="text-zinc-400 font-bold">{
                scan?.status === 'queued' ? '40%' :
                scan?.status === 'scanning' ? '70%' :
                scan?.status === 'analyzing' ? '92%' :
                scan?.status === 'complete' ? '100%' :
                '0%'
              }</span>
            </div>
            <div className="w-full bg-black h-1 rounded overflow-hidden border border-[#27272a]/60">
              <div
                className="bg-[#22c55e]/60 h-full transition-all duration-500 rounded-full"
                style={{
                  width: scan?.status === 'queued' ? '40%' :
                         scan?.status === 'scanning' ? '70%' :
                         scan?.status === 'analyzing' ? '92%' :
                         scan?.status === 'complete' ? '100%' :
                         '0%'
                }}
              />
            </div>
          </div>

          <div className="flex justify-between items-center text-[10px] font-mono text-[#52525b] uppercase mt-1">
            <span className={scan?.status === 'queued' ? 'text-[#22c55e] font-bold' : ''}>QUEUED</span>
            <span className="text-[#27272a]">→</span>
            <span className={scan?.status === 'scanning' ? 'text-purple-400 font-bold' : ''}>SCANNING</span>
            <span className="text-[#27272a]">→</span>
            <span className={scan?.status === 'analyzing' ? 'text-amber-400 font-bold' : ''}>ANALYZING AI</span>
            <span className="text-[#27272a]">→</span>
            <span className={scan?.status === 'complete' ? 'text-[#22c55e] font-bold' : ''}>COMPLETE</span>
          </div>
        </div>

        {/* Terminal logs */}
        <ScanConsole logs={logs} />

        {/* Actions panel */}
        <div
          id="cancel-scan-btn-container"
          className="border-t border-[#27272a] pt-5 space-y-4 font-mono text-xs text-[#52525b]"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-1.5">
              <Cpu className="w-4 h-4 text-[#22c55e] shrink-0" />
              <span>Scanning using Seclayer Daemon v2</span>
            </div>
            {scan && ['queued', 'scanning', 'analyzing'].includes(scan.status) ? (
              <button
                onClick={onCancel}
                className="text-[#52525b] hover:text-[#f87171] transition-colors cursor-pointer"
                id="cancel-scan-btn"
              >
                Cancel scan
              </button>
            ) : scan?.status === 'failed' ? (
              <button
                onClick={onCancel}
                className="text-[#52525b] hover:text-white transition-colors cursor-pointer"
                id="cancel-scan-btn"
              >
                Back to dashboard
              </button>
            ) : null}
          </div>
        </div>

      </div>
    </div>
  );
}
