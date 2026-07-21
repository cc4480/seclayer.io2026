import { Coins, RefreshCw, ArrowRight } from 'lucide-react';

// Credit-purchase card (Stripe sandbox): pick a pack, redirect to checkout.
interface Props {
  buyPack: 'single' | 'pack5' | 'pack20';
  setBuyPack: (p: 'single' | 'pack5' | 'pack20') => void;
  isBuying: boolean;
  isPerformingAction: boolean;
  handleBuyCredits: () => void;
}

export default function CreditPacks({ buyPack, setBuyPack, isBuying, isPerformingAction, handleBuyCredits }: Props) {
  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <div className="flex items-center space-x-2.5 mb-4">
        <div className="p-1.5 bg-black border border-[#27272a] rounded text-[#22c55e]">
          <Coins className="w-4 h-4" />
        </div>
        <h2 className="text-sm font-bold font-mono text-white">Purchase Credits (Stripe Sandbox)</h2>
      </div>
      <p className="text-[#a1a1aa] text-xs font-mono mb-6">
        Need more scan capacity? To top up scan credits, choose a credit volume package below. We've set up a preconfigured Stripe test integration that performs instant top-ups dynamically.
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
        {[
          { id: 'single', name: '1 Scan Credit', price: '$29', label: '$29/Scan' },
          { id: 'pack5', name: '5-Scan Pack', price: '$99', label: 'Save 30%' },
          { id: 'pack20', name: '20-Scan Pack', price: '$299', label: 'Save 50%' }
        ].map((pack) => (
          <div
            key={pack.id}
            onClick={() => setBuyPack(pack.id as any)}
            className={`p-4 rounded border text-center cursor-pointer transition-all ${
              buyPack === pack.id ? 'border-[#22c55e] bg-[#22c55e]/5' : 'border-[#27272a] hover:border-[#3f3f46] bg-black'
            }`}
          >
            <span className="text-[10px] font-mono text-[#52525b] block uppercase mb-1">{pack.name}</span>
            <strong className="text-lg font-mono text-white block">{pack.price}</strong>
            <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded inline-block mt-1 ${
              buyPack === pack.id ? 'bg-[#22c55e]/20 text-[#22c55e]' : 'bg-[#18181b] text-[#52525b]'
            }`}>{pack.label}</span>
          </div>
        ))}
      </div>

      <button
        onClick={handleBuyCredits}
        disabled={isBuying || isPerformingAction}
        className="w-full py-3 bg-[#18181b] hover:bg-[#27272a] border border-[#27272a] text-white hover:text-[#22c55e] text-xs font-mono font-bold uppercase tracking-widest rounded transition-all flex items-center justify-center space-x-2 cursor-pointer"
        id="buy-credits-btn"
      >
        {isBuying ? (
          <>
            <RefreshCw className="w-4 h-4 text-[#22c55e] animate-spin" />
            <span>Redirecting to stripe checkout...</span>
          </>
        ) : (
          <>
            <span>Acquire {buyPack === 'single' ? '1 scan credit' : buyPack === 'pack5' ? '5 credits pack' : '20 credits pack'}</span>
            <ArrowRight className="w-4 h-4" />
          </>
        )}
      </button>
    </div>
  );
}
