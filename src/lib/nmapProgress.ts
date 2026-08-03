import { LiveEvent } from '../types.js';

// A snapshot of nmap's own progress, derived from the raw `--stats-every 10s`
// stderr lines the backend already forwards verbatim on the 'recon' channel
// (see server/nmap/run.ts) — nothing new from the server, purely a frontend
// read of text that was already being shown, turned into something visual.
export interface NmapProgress {
  phase: string;         // nmap's own phase name verbatim, e.g. "SYN Stealth Scan", "Service scan", "NSE"
  percent: number | null; // 0-100, or null when we know the phase but haven't seen a Timing line for it yet
  eta?: string;           // raw clock time from "ETC: 12:34"
  remaining?: string;     // raw "H:MM:SS remaining" text
  elapsed?: string;       // raw "H:MM:SS elapsed" text from the paired Stats: line
}

// e.g. "SYN Stealth Scan Timing: About 35.71% done; ETC: 12:34 (0:10:52 remaining)"
// or, without an ETC clause: "NSE Timing: About 96.71% done"
const TIMING_RE = /^(.+?) Timing: About ([\d.]+)% done(?:; ETC: (\S+) \(([^)]+) remaining\))?/;
// e.g. "Stats: 0:01:30 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan"
const STATS_RE = /^Stats: (\S+) elapsed;.*?undergoing (.+?)\s*$/;

export function parseNmapProgress(events: LiveEvent[]): NmapProgress | null {
  let latest: NmapProgress | null = null;

  for (const e of events) {
    if (e.channel !== 'recon') continue;

    const timing = TIMING_RE.exec(e.text);
    if (timing) {
      latest = {
        phase: timing[1].trim(),
        percent: Math.min(100, Math.max(0, parseFloat(timing[2]))),
        eta: timing[3],
        remaining: timing[4],
      };
      continue;
    }

    const stats = STATS_RE.exec(e.text);
    if (stats) {
      const phase = stats[2].trim();
      // Same phase as our last known snapshot: refresh the elapsed time but
      // keep whatever percent a prior Timing: line already gave us — a bare
      // Stats: line carries no percent of its own, and losing a known
      // percent every 10s (until the next paired Timing: line arrives)
      // would make the bar flicker back to indeterminate. Compared
      // case-insensitively: nmap itself isn't consistent about it (e.g. the
      // Stats: line says "undergoing Service Scan" while the paired line is
      // "Service scan Timing: ...").
      latest = latest && latest.phase.toLowerCase() === phase.toLowerCase()
        ? { ...latest, elapsed: stats[1] }
        : { phase, percent: null, elapsed: stats[1] };
    }
  }

  return latest;
}
