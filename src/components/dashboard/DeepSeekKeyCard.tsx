import { useState } from 'react';
import { Sparkles, RefreshCw, Check, Trash2 } from 'lucide-react';

interface Props {
  deepseekKeySet: boolean;
  deepseekKeyPreview: string | null;
  saveDeepseekKey: (key: string) => Promise<{ ok: boolean; message?: string }>;
}

// Bring-your-own-key card (shown in free mode): a user pastes their own DeepSeek
// API key so their scans get full AI-generated reports instead of the built-in
// local summaries. The raw key is write-only — the server only ever returns a
// masked preview.
export default function DeepSeekKeyCard({ deepseekKeySet, deepseekKeyPreview, saveDeepseekKey }: Props) {
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    const key = value.trim();
    if (!key) return;
    setSaving(true);
    setError('');
    setSaved(false);
    const res = await saveDeepseekKey(key);
    setSaving(false);
    if (res.ok) {
      setValue('');
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } else {
      setError(res.message || 'Could not save the key.');
    }
  };

  const remove = async () => {
    setSaving(true);
    setError('');
    await saveDeepseekKey('');
    setSaving(false);
  };

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <div className="flex items-center space-x-2.5 mb-4">
        <div className="p-1.5 bg-black border border-[#27272a] rounded text-[#22c55e]">
          <Sparkles className="w-4 h-4" />
        </div>
        <h2 className="text-sm font-bold font-mono text-white">Personal AI Key (DeepSeek)</h2>
      </div>
      <p className="text-[#a1a1aa] text-xs font-mono mb-4 leading-relaxed">
        Scans are free — and by default use built-in local report summaries. Add your own{' '}
        <a href="https://platform.deepseek.com" target="_blank" rel="noreferrer" className="text-[#22c55e] hover:underline">DeepSeek API key</a>{' '}
        to unlock full AI-generated executive reports and live scan narration, billed to your own DeepSeek account.
      </p>

      {deepseekKeySet && (
        <div className="mb-3 flex items-center justify-between gap-3 bg-black border border-[#22c55e]/25 rounded p-2.5">
          <span className="text-[10px] font-mono text-[#a1a1aa] flex items-center gap-2 min-w-0">
            <Check className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
            <span className="text-[#22c55e] uppercase font-bold shrink-0">Active</span>
            <code className="text-white truncate">{deepseekKeyPreview}</code>
          </span>
          <button
            onClick={remove}
            disabled={saving}
            className="px-2.5 py-1.5 bg-[#18181b] border border-[#27272a] hover:bg-[#f87171] hover:text-white text-[#f87171] rounded text-[9px] uppercase font-bold tracking-wider transition-all cursor-pointer disabled:opacity-40 flex items-center gap-1 shrink-0"
          >
            <Trash2 className="w-3 h-3" /> Remove
          </button>
        </div>
      )}

      <div className="flex flex-col sm:flex-row gap-2">
        <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
          <input
            type="password"
            className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
            placeholder={deepseekKeySet ? 'Paste a new key to replace it…' : 'sk-…'}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') void submit(); }}
            id="deepseek-key-input"
            autoComplete="off"
          />
        </div>
        <button
          type="button"
          onClick={() => void submit()}
          disabled={saving || !value.trim()}
          className="px-4 py-2 bg-[#18181b] hover:bg-[#27272a] text-white text-[11px] font-mono font-bold uppercase tracking-wider border border-[#27272a] rounded transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer whitespace-nowrap flex items-center justify-center gap-1.5"
          id="deepseek-key-save"
        >
          {saving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : saved ? 'Saved ✓' : deepseekKeySet ? 'Replace' : 'Save Key'}
        </button>
      </div>
      {error && <div className="text-[#f87171] text-[10px] font-mono mt-2">{error}</div>}
      <p className="text-[9px] text-[#52525b] font-mono mt-3">Your key is stored securely and never shown again — only used to generate your reports.</p>
    </div>
  );
}
