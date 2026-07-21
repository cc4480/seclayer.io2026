import React, { useEffect, useState, useRef } from 'react';
import { Shield, ShieldAlert, Terminal, RefreshCw, Key, ChevronRight, Activity, Cpu } from 'lucide-react';
import { Scan } from '../types.js';

interface ScanProgressProps {
  scanId: string;
  onScanFinished: (scanId: string) => void;
  onCancel: () => void;
}

const MAX_CONSECUTIVE_POLL_ERRORS = 5;

export default function ScanProgress({ scanId, onScanFinished, onCancel }: ScanProgressProps) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [progressPercent, setProgressPercent] = useState(10);
  const [pollError, setPollError] = useState<string | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const finishedRef = useRef(false);

  // Poll for scan status (includes narrationLog, appended to server-side as
  // each real phase completes — see server.ts's processScanJob).
  useEffect(() => {
    let active = true;
    let consecutiveErrors = 0;

    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        if (!active) return;

        if (!res.ok) {
          throw new Error(res.status === 404 ? 'This scan no longer exists.' : `Server returned ${res.status}.`);
        }
        const data = await res.json();
        if (!active) return;

        if (!data.scan) throw new Error('Scan status is unavailable.');

        consecutiveErrors = 0;
        setPollError(null);
        const currentScan = data.scan as Scan;
        setScan(currentScan);

        if (currentScan.status === 'complete') {
          setProgressPercent(100);
          clearInterval(pollTimer);
          if (!finishedRef.current) {
            finishedRef.current = true;
            setTimeout(() => {
              if (active) onScanFinished(scanId);
            }, 1000);
          }
          return;
        }

        if (currentScan.status === 'failed') {
          setProgressPercent(100);
          clearInterval(pollTimer);
          return;
        }

        // Advance progression bar corresponding to state
        if (currentScan.status === 'queued') {
          setProgressPercent(20);
        } else if (currentScan.status === 'scanning') {
          setProgressPercent(50);
        } else if (currentScan.status === 'analyzing') {
          setProgressPercent(80);
        }
      } catch (err: any) {
        if (!active) return;
        console.error('Error polling scan status:', err);
        consecutiveErrors += 1;
        if (consecutiveErrors >= MAX_CONSECUTIVE_POLL_ERRORS) {
          clearInterval(pollTimer);
          setPollError(err?.message || 'Lost connection to the scan. Please return to the dashboard and try again.');
        }
      }
    };

    fetchStatus();
    const pollTimer = setInterval(fetchStatus, 3000);

    return () => {
      active = false;
      clearInterval(pollTimer);
    };
  }, [scanId]);

  // Real console lines: a few phase-transition markers, plus the actual
  // deepseek-v4-flash narration of what the scan found (scan.narrationLog) —
  // no scripted/generic filler describing steps that may not have run yet.
  const logs: string[] = [];
  if (scan) {
    logs.push(`[SYSTEM] Queued target URL: ${scan.url}`);
    logs.push(scan.status === 'queued'
      ? '[SYSTEM] Validating target and resolving DNS...'
      : '[SYSTEM] Target validated. Diagnostics underway...');

    if (scan.narrationLog && scan.narrationLog.length > 0) {
      scan.narrationLog.forEach((line) => logs.push(`[FLASH] ${line}`));
    } else if (scan.status === 'scanning') {
      logs.push(`[SCAN] Running diagnostics against ${scan.url}...`);
    }

    if (scan.status === 'analyzing' && !(scan.narrationLog && scan.narrationLog.length > 3)) {
      logs.push('[DEEPSEEK] Forwarding diagnostics to DeepSeek for analysis...');
    }
    if (scan.status === 'complete') {
      logs.push(`[SYSTEM] Report compiled. Security score: ${scan.score ?? 'N/A'}/100.`);
    }
    if (scan.status === 'failed') {
      logs.push(`[FATAL] Scanner terminated: ${scan.error || 'Connection Timeout'}`);
    }
  }

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length]);

  // Polling has permanently failed (server/network kept erroring) — surface it
  // instead of leaving the spinner running with no feedback forever.
  if (pollError) {
    return (
      <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-20 px-6 flex items-center justify-center">
        <div className="max-w-md w-full space-y-6 bg-[#0c0c0e] border border-[#f87171]/25 p-8 rounded shadow-2xl text-center">
          <ShieldAlert className="w-10 h-10 text-[#f87171] mx-auto" />
          <div>
            <h1 className="text-white font-mono font-bold text-sm uppercase tracking-wider">Lost Connection</h1>
            <p className="text-[#a1a1aa] text-xs font-mono mt-2">{pollError}</p>
          </div>
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-white text-xs font-mono uppercase tracking-wider rounded transition-all cursor-pointer"
          >
            Back to Dashboard
          </button>
        </div>
      </div>
    );
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

        {/* Terminal logs component */}
        <div className="bg-black border border-[#27272a] rounded p-5 overflow-hidden">
          <div className="flex items-center space-x-2 border-b border-[#27272a]/40 pb-3 mb-4">
            <Terminal className="w-4 h-4 text-[#22c55e] shrink-0" />
            <span className="text-[10px] font-mono text-[#52525b] uppercase tracking-widest">Scanner Console outputs</span>
          </div>

          <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] leading-relaxed text-[#a1a1aa] select-all scrollbar-thin">
            {logs.map((log, index) => {
              let textClass = 'text-[#a1a1aa]';
              if (log.includes('[SYSTEM]')) textClass = 'text-[#22c55e] font-semibold';
              if (log.includes('[FLASH]')) textClass = 'text-purple-400';
              if (log.includes('[DEEPSEEK]')) textClass = 'text-amber-400';
              if (log.includes('[FATAL]')) textClass = 'text-[#f87171] font-bold';
              return (
                <div key={index} className={textClass}>
                  {log}
                </div>
              );
            })}
            <div ref={logsEndRef} />
          </div>
        </div>

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
            {scan?.status !== 'complete' && (
              <button
                onClick={onCancel}
                className="text-[#52525b] hover:text-[#f87171] transition-colors cursor-pointer"
                id="cancel-scan-btn"
              >
                Cancel scan
              </button>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
