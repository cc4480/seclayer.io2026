import { Coins, Gift } from 'lucide-react';

// Developer-console header banner: account context + available credit balance
// (or a free-beta indicator when scans cost nothing).
export default function DashboardHeader({ email, credits, freeMode }: { email: string; credits: number; freeMode?: boolean }) {
  return (
    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0c0c0e] p-6 rounded border border-[#27272a] relative overflow-hidden">
      <div className="absolute top-0 right-0 w-80 h-80 bg-[#22c55e]/5 rounded-full blur-[80px] pointer-events-none" />
      <div className="relative z-10 w-full md:w-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-tighter text-white mb-1">Developer Console</h1>
          <p className="text-[#a1a1aa] text-xs font-mono">Account context: <span className="text-white">{email}</span></p>
        </div>
      </div>
      <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-6 relative z-10 w-full md:w-auto">
        <div className="text-right flex items-center justify-between w-full md:w-auto md:block pt-4 border-t border-[#27272a]/40 md:pt-0 md:border-0">
          <span className="text-[10px] font-mono text-[#52525b] uppercase block md:mb-0.5">{freeMode ? 'Access' : 'Available Balance'}</span>
          {freeMode ? (
            <span className="text-2xl font-mono font-black text-[#22c55e] flex items-center space-x-2">
              <Gift className="w-5 h-5 text-[#22c55e] shrink-0" />
              <span>Free <span className="text-xs font-normal text-[#52525b] font-mono">beta — unlimited scans</span></span>
            </span>
          ) : (
            <span className="text-2xl font-mono font-black text-[#22c55e] flex items-center space-x-2">
              <Coins className="w-5 h-5 text-[#22c55e] shrink-0" />
              <span>{credits} <span className="text-xs font-normal text-[#52525b] font-mono">scans</span></span>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
