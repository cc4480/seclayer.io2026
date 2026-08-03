import type { NmapProgress } from '../../lib/nmapProgress.js';

// Renders nmap's own progress (parsed from its real --stats-every stderr
// lines, already forwarded to ScanConsole below this unmodified — nothing is
// hidden, this is a visual on top of the same data) as an actual phase +
// percent bar, closer to what running nmap in a terminal looks like than a
// scrolling log alone.
export default function NmapProgressBar({ progress }: { progress: NmapProgress | null }) {
  if (!progress) {
    return (
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[10px] font-mono">
          <span className="text-[#52525b] uppercase tracking-wider">Initializing…</span>
        </div>
        <div className="h-1.5 bg-[#18181b] rounded-full overflow-hidden">
          <div className="h-full w-1/3 bg-purple-500/50 rounded-full animate-shimmer" />
        </div>
      </div>
    );
  }

  const { phase, percent, remaining, eta } = progress;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-[10px] font-mono flex-wrap gap-x-3">
        <span className="text-purple-300 uppercase tracking-wider font-bold">{phase}</span>
        <span className="text-[#52525b]">
          {percent != null ? `${percent.toFixed(1)}%` : 'starting…'}
          {remaining ? ` · ETC ${eta} (${remaining} left)` : ''}
        </span>
      </div>
      <div className="h-1.5 bg-[#18181b] rounded-full overflow-hidden">
        {percent != null ? (
          <div
            className="h-full bg-purple-400 rounded-full transition-all duration-500"
            style={{ width: `${Math.max(2, percent)}%` }}
          />
        ) : (
          <div className="h-full w-1/3 bg-purple-500/50 rounded-full animate-shimmer" />
        )}
      </div>
    </div>
  );
}
