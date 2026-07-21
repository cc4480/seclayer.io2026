import { Shield } from 'lucide-react';
import { Finding } from '../../types.js';
import { categoryTabLabels, getCategoryCount, getCategorySeverity, type SecCategory } from './categories.js';

// The AppSec framework tab strip: Executive Overview plus one tab per security
// pillar, each badged with a severity-coloured finding count.
interface Props {
  activeTab: 'OVERVIEW' | SecCategory;
  setActiveTab: (t: 'OVERVIEW' | SecCategory) => void;
  findings: Finding[];
}

export default function CategoryTabBar({ activeTab, setActiveTab, findings }: Props) {
  return (
    <div className="flex overflow-x-auto border-b border-[#27272a] bg-black/20 select-none scrollbar-none">
      <button
        onClick={() => setActiveTab('OVERVIEW')}
        className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider font-semibold transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
          activeTab === 'OVERVIEW'
            ? 'border-[#22c55e] text-white bg-black/40'
            : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
        }`}
      >
        <Shield className="w-4 h-4 text-[#22c55e]" />
        <span>Executive Overview</span>
      </button>

      {categoryTabLabels.map(cat => {
        const count = getCategoryCount(findings, cat.key);
        const label = getCategorySeverity(findings, cat.key);
        // Colour the count by real severity, not merely "count > 0".
        const alertBadge = label === 'CRITICAL' || label === 'HIGH RISK'
          ? 'bg-red-500/10 text-red-400 border border-red-500/25'
          : label === 'MODERATE'
          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/25'
          : label === 'LOW RISK'
          ? 'bg-blue-500/10 text-blue-400 border border-blue-500/25'
          : label === 'INFO'
          ? 'bg-zinc-500/10 text-zinc-300 border border-zinc-500/25'
          : 'bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/25';
        return (
          <button
            key={cat.key}
            onClick={() => setActiveTab(cat.key)}
            className={`px-5 py-4 border-b-2 text-xs font-mono uppercase tracking-wider transition-all flex items-center space-x-2 shrink-0 cursor-pointer ${
              activeTab === cat.key
                ? 'border-[#22c55e] text-white bg-black/40'
                : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
            }`}
          >
            <cat.icon className={`w-4 h-4 ${activeTab === cat.key ? 'text-[#22c55e]' : 'text-[#52525b]'}`} />
            <span className="font-bold">{cat.label}</span>
            <span className={`text-[10px] px-1.5 py-0.2 ml-1 rounded font-mono ${alertBadge}`}>
              {count}
            </span>
          </button>
        );
      })}
    </div>
  );
}
