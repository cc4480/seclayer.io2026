import { ShieldAlert } from 'lucide-react';

// Shown when scan polling has permanently failed — surfaces the reason and a way
// back instead of leaving the spinner running with no feedback forever.
export default function PollErrorScreen({ message, onBack }: { message: string; onBack: () => void }) {
  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-20 px-6 flex items-center justify-center">
      <div className="max-w-md w-full space-y-6 bg-[#0c0c0e] border border-[#f87171]/25 p-8 rounded shadow-2xl text-center">
        <ShieldAlert className="w-10 h-10 text-[#f87171] mx-auto" />
        <div>
          <h1 className="text-white font-mono font-bold text-sm uppercase tracking-wider">Lost Connection</h1>
          <p className="text-[#a1a1aa] text-xs font-mono mt-2">{message}</p>
        </div>
        <button
          onClick={onBack}
          className="px-4 py-2 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] text-white text-xs font-mono uppercase tracking-wider rounded transition-all cursor-pointer"
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}
