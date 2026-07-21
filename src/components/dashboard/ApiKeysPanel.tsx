import { Key, Plus, Trash2, Terminal, ShieldCheck } from 'lucide-react';
import { ApiKey } from '../../types.js';

// Developer API keys panel (right column): generate/copy/revoke MCP keys, plus a
// short MCP integration help card.
interface Props {
  apiKeys: ApiKey[];
  justGeneratedKey: { id: string; rawKey: string } | null;
  onDismissGeneratedKey: () => void;
  onGenerateKey: () => void;
  onRevokeKey: (keyId: string) => void;
  copiedKeyId: string | null;
  handleCopyKey: (keyText: string, keyId: string) => void;
}

export default function ApiKeysPanel({
  apiKeys, justGeneratedKey, onDismissGeneratedKey, onGenerateKey, onRevokeKey, copiedKeyId, handleCopyKey,
}: Props) {
  return (
    <>
      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2.5">
            <div className="p-1.5 bg-black border border-[#27272a] rounded text-[#22c55e]">
              <Key className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-bold font-mono text-white">Developer API Keys</h2>
          </div>
          <button onClick={onGenerateKey} className="px-2.5 py-1.5 bg-black border border-[#27272a] hover:border-[#22c55e]/30 hover:text-[#22c55e] rounded text-white text-[10px] font-bold font-mono uppercase tracking-wider transition-all flex items-center space-x-1 cursor-pointer" id="generate-api-key-btn">
            <Plus className="w-3.5 h-3.5" />
            <span>Generate Key</span>
          </button>
        </div>
        <p className="text-[#a1a1aa] text-xs font-mono mb-6">
          Generate API key headers for your AI agents (Cursor, Claude Code, Windsurf) to query the MCP tool. Consumes credits from your main balance.
        </p>

        {justGeneratedKey && (
          <div className="mb-4 p-3.5 rounded border border-[#22c55e]/30 bg-[#22c55e]/5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#22c55e] font-bold">New key — copy it now, it won't be shown again</span>
              <button onClick={onDismissGeneratedKey} className="text-[9px] font-mono uppercase text-[#52525b] hover:text-white cursor-pointer">Dismiss</button>
            </div>
            <div className="flex items-center gap-2">
              <code className="text-xs font-mono text-white font-bold select-all break-all flex-1">{justGeneratedKey.rawKey}</code>
              <button onClick={() => handleCopyKey(justGeneratedKey.rawKey, justGeneratedKey.id)} className="px-2 py-1 rounded bg-[#18181b] border border-[#27272a] text-[#a1a1aa] hover:text-[#22c55e] font-mono text-[9px] uppercase tracking-wide transition-all shrink-0 cursor-pointer">
                {copiedKeyId === justGeneratedKey.id ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        {apiKeys.length === 0 ? (
          <div className="text-center py-6 bg-black rounded border border-[#27272a]">
            <span className="text-xs text-[#52525b] font-mono">No active keys generated yet</span>
          </div>
        ) : (
          <div className="space-y-3">
            {apiKeys.map((key) => (
              <div key={key.id} className={`p-3.5 rounded border bg-black border-[#27272a] flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-opacity ${key.active ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>
                <div className="space-y-1">
                  <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                    <code className="text-xs font-mono text-[#22c55e] font-bold select-all">{key.keyPreview}</code>
                    <span className={`text-[8px] font-mono px-1 py-0.25 rounded ${key.active ? 'bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e]' : 'bg-[#18181b] text-[#52525b]'}`}>
                      {key.active ? 'Active' : 'Revoked'}
                    </span>
                  </div>
                  <span className="text-[9px] text-[#52525b] font-mono block">
                    Generated: {new Date(key.createdAt).toLocaleDateString()}
                    {key.id !== justGeneratedKey?.id && ' · full key only shown once, at creation'}
                  </span>
                </div>
                <div className="flex items-center space-x-2 shrink-0">
                  {key.active && (
                    <button onClick={() => onRevokeKey(key.id)} className="p-1.5 rounded text-[#52525b] hover:text-[#f87171] hover:bg-[#18181b] transition-colors cursor-pointer" title="Revoke Key" id={`revoke-key-${key.id}`}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Documentation Help card */}
      <div className="bg-[#0c0c0e]/65 border border-[#27272a] rounded p-6 relative overflow-hidden">
        <div className="absolute right-0 bottom-0 pointer-events-none opacity-5 translate-x-1/10 translate-y-1/10">
          <Terminal className="w-48 h-48 text-white" />
        </div>
        <h3 className="font-mono text-xs text-[#22c55e] font-bold uppercase tracking-wider mb-2">MCP Integration Help</h3>
        <p className="text-[#a1a1aa] text-xs mb-4 font-mono">Set up Cursor with Seclayer by introducing a new command type:</p>
        <div className="bg-black p-3 rounded font-mono text-[10px] text-zinc-300 select-all leading-relaxed border border-[#27272a] break-all mb-4">
          npx -y @seclayer/mcp --key <span className="text-[#22c55e]">{justGeneratedKey?.rawKey || "YOUR_API_KEY"}</span>
        </div>
        <span className="text-[10px] text-[#52525b] flex items-center space-x-1 font-mono">
          <ShieldCheck className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
          <span>Provides the seclayer_scan tool context natively</span>
        </span>
      </div>
    </>
  );
}
