import { Scan, LiveEvent } from '../../types.js';

// Renders the real-time ticker: each live event becomes a channel-prefixed line
// (e.g. "[PROBE] → SQL injection: firing …") that logLineClass then colors. This
// is the live path used while a scan runs; buildScanLogs below is the fallback
// for a finished scan re-opened later (rendered from the persisted narrationLog).
export function liveEventsToLogs(events: LiveEvent[]): string[] {
  return events.map((e) => `[${e.channel.toUpperCase()}] ${e.text}`);
}

// Derives the scanner console lines from the current scan state: a few
// phase-transition markers plus the real deepseek-v4-flash narration
// (scan.narrationLog) appended server-side as each phase completes — no
// scripted filler describing steps that may not have run yet. Pure function of
// the scan, so the console is a straight render of its output.
export function buildScanLogs(scan: Scan | null): string[] {
  const logs: string[] = [];
  if (!scan) return logs;

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
  return logs;
}

// Maps a log line's channel prefix to its Tailwind text color.
export function logLineClass(log: string): string {
  // A proven exploit stands out regardless of channel — it's the headline event.
  if (log.includes('✓ CONFIRMED')) return 'text-[#f87171] font-bold';
  if (log.includes('[SYSTEM]')) return 'text-[#22c55e] font-semibold';
  if (log.includes('[RECON]')) return 'text-sky-400';
  if (log.includes('[PROBE]')) return 'text-amber-400';
  if (log.includes('[RESULT]')) return 'text-[#22c55e]';
  if (log.includes('[FLASH]')) return 'text-purple-400';
  if (log.includes('[DEEPSEEK]')) return 'text-amber-400';
  if (log.includes('[FATAL]')) return 'text-[#f87171] font-bold';
  return 'text-[#a1a1aa]';
}
