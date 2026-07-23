import { useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';
import { logLineClass } from './scanLogs.js';

// The scanner console: renders the derived log lines with per-channel coloring
// and keeps itself scrolled to the newest line as they stream in.
export default function ScanConsole({ logs }: { logs: string[] }) {
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length]);

  return (
    <div className="bg-black border border-[#27272a] rounded p-5 overflow-hidden">
      <div className="flex items-center space-x-2 border-b border-[#27272a]/40 pb-3 mb-4">
        <Terminal className="w-4 h-4 text-[#22c55e] shrink-0" />
        <span className="text-[10px] font-mono text-[#52525b] uppercase tracking-widest">Scanner Console outputs</span>
      </div>

      <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-[11px] leading-relaxed text-[#a1a1aa] select-all scrollbar-thin">
        {logs.map((log, index) => (
          <div key={index} className={logLineClass(log)}>
            {log}
          </div>
        ))}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
