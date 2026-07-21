import { CheckCircle, Coins } from 'lucide-react';

export default function PricingSection({ onSelectPack }: { onSelectPack: (packName: 'single' | 'pack5' | 'pack20') => void }) {
  return (
    <div className="max-w-6xl mx-auto py-24 px-6">
      <div className="text-center mb-16">
        <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">Simple Pay-As-You-Go</p>
        <h2 className="text-3xl font-bold font-mono tracking-tighter text-white">Purchase Credits. Run Scans. Zero Lock-In.</h2>
        <p className="text-[#a1a1aa] text-xs font-mono mt-3 max-w-md mx-auto">No subscriptions, no hidden clauses. Every scan consumes exactly 1 credit. Buy only what you need, when you need to deploy.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">

        {/* Card 1 - Single Scan */}
        <div className="bg-[#0c0c0e] border border-[#27272a] hover:border-[#3f3f46] rounded p-8 flex flex-col relative transition-all group" id="price-card-single">
          <h3 className="font-mono text-[#52525b] text-xs uppercase tracking-widest mb-2">Single Scan</h3>
          <div className="flex items-baseline space-x-1 mb-6">
            <span className="text-4xl font-mono font-black text-white">$29</span>
            <span className="text-[#52525b] text-xs font-mono">/ flat</span>
          </div>
          <ul className="space-y-3 mb-8 text-[#a1a1aa] flex-1 text-xs font-mono">
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>1 Full Black-Box Penetration Test</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>DeepSeek Generated AI Summary report</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>Actionable remediation fixes per issue</span>
            </li>
            <li className="text-[#52525b] pl-5">No commitment, simple pay-per-deploy.</li>
          </ul>
          <button
            onClick={() => onSelectPack('single')}
            className="w-full py-2.5 bg-[#18181b] hover:bg-[#27272a] text-white hover:text-[#22c55e] text-xs font-mono font-bold uppercase tracking-wider border border-[#27272a] rounded transition-all flex items-center justify-center space-x-2 cursor-pointer"
            id="price-btn-single"
          >
            <span>Order credit</span>
            <Coins className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Card 2 - 5-Scan Pack (Most Popular) */}
        <div className="bg-[#0c0c0e] border border-[#22c55e]/60 rounded p-8 flex flex-col relative transition-all shadow-xl shadow-[#22c55e]/5" id="price-card-pack5">
          <div className="absolute top-0 right-8 -translate-y-1/2 bg-[#22c55e] text-black font-mono font-bold text-[10px] uppercase tracking-widest px-3 py-1 rounded">
            Best Seller
          </div>
          <h3 className="font-mono text-[#22c55e] text-xs uppercase tracking-widest mb-2">5-Scan pack</h3>
          <div className="flex items-baseline space-x-1 mb-6">
            <span className="text-4xl font-mono font-black text-white">$99</span>
            <span className="text-[#a1a1aa] text-xs font-mono">/ $19.80 per scan</span>
          </div>
          <ul className="space-y-3 mb-8 text-[#a1a1aa] flex-1 text-xs font-mono">
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>5 Full Scan Credits (No expiry)</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>Web Dashboard + Historical Reports</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>Full API and MCP Server access integrations</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>PDF Download and shareable report link exports</span>
            </li>
            <li className="text-[#22c55e] font-mono text-[10px] uppercase tracking-wide pl-5">Save over 30% upfront</li>
          </ul>
          <button
            onClick={() => onSelectPack('pack5')}
            className="w-full py-3 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded transition-all flex items-center justify-center space-x-2 shadow-lg shadow-[#22c55e]/10 active:scale-98 cursor-pointer"
            id="price-btn-pack5"
          >
            <span>Get 5-Scan Pack</span>
            <Coins className="w-4 h-4" />
          </button>
        </div>

        {/* Card 3 - 20-Scan Pack */}
        <div className="bg-[#0c0c0e] border border-[#27272a] hover:border-[#3f3f46] rounded p-8 flex flex-col relative transition-all group" id="price-card-pack20">
          <h3 className="font-mono text-[#52525b] text-xs uppercase tracking-widest mb-2">20-Scan pack</h3>
          <div className="flex items-baseline space-x-1 mb-6">
            <span className="text-4xl font-mono font-black text-white">$299</span>
            <span className="text-[#52525b] text-xs font-mono">/ ~$14.95 per scan</span>
          </div>
          <ul className="space-y-3 mb-8 text-[#a1a1aa] flex-1 text-xs font-mono">
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>20 Full Scan Credits (Ideal for teams)</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>Generate dedicated developer API Keys</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>Priority queue audit speeds</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
              <span>Priority premium helpdesk support</span>
            </li>
            <li className="text-[#52525b] pl-5">Perfect for fast agencies or CI/CD automations.</li>
          </ul>
          <button
            onClick={() => onSelectPack('pack20')}
            className="w-full py-2.5 bg-[#18181b] hover:bg-[#27272a] text-white hover:text-[#22c55e] text-xs font-mono font-bold uppercase tracking-wider border border-[#27272a] rounded transition-all flex items-center justify-center space-x-2 cursor-pointer"
            id="price-btn-pack20"
          >
            <span>Get 20-Scan Pack</span>
            <Coins className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>
    </div>
  );
}
