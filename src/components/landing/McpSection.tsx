import { useState } from 'react';
import { Key } from 'lucide-react';

export default function McpSection({ onNavigate }: { onNavigate: (view: string, arg?: string) => void }) {
  const [activeMcpTab, setActiveMcpTab] = useState<'claude' | 'cursor' | 'manual'>('claude');

  return (
    <div className="bg-[#0c0c0e] border-t border-b border-[#27272a] py-24 px-6 relative">
      <div className="max-w-5xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">

        <div className="lg:col-span-6">
          <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">SaaS / MCP Server Dual Model</p>
          <h2 className="text-3xl sm:text-4xl font-mono font-bold tracking-tighter mb-6 text-white">
            Pentest in your editor using <br />
            <span className="text-[#22c55e] font-mono font-bold">[ sec ]layer MCP</span>
          </h2>
          <p className="text-[#a1a1aa] text-xs font-mono mb-6 leading-relaxed">
            Before you hit deploy, trigger a pen-test directly inside your preferred AI Coding Assistants (like VSCode Cursor, Claude Code, Windsurf, or Bolt).
          </p>
          <p className="text-[#a1a1aa] text-xs font-mono mb-8 leading-relaxed">
            The Seclayer Model Context Protocol (MCP) server securely bridges scan credits into developer environments. Simply provide your prepaid API Key, and query live vulnerabilities in natural language.
          </p>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => onNavigate('dashboard')}
              className="px-5 py-2.5 bg-[#18181b] hover:bg-[#27272a] text-white hover:text-[#22c55e] border border-[#27272a] font-mono text-xs uppercase tracking-widest rounded transition-all flex items-center space-x-2 cursor-pointer"
              id="landing-mcp-cta"
            >
              <Key className="w-4 h-4 text-[#22c55e]" />
              <span>Get API Key</span>
            </button>
          </div>
        </div>

        <div className="lg:col-span-6 bg-black border border-[#27272a] rounded overflow-hidden p-6 shadow-2xl">
          {/* Window control circles */}
          <div className="flex items-center space-x-1.5 mb-5 border-b border-[#27272a] pb-3">
            <div className="w-2.5 h-2.5 rounded bg-red-500/60" />
            <div className="w-2.5 h-2.5 rounded bg-yellow-500/60" />
            <div className="w-2.5 h-2.5 rounded bg-[#22c55e]/60" />
            <span className="text-[#52525b] font-mono text-[10px] ml-4">Terminal: seclayer-mcp</span>
          </div>

          {/* MCP CLI Code Switcher tabs */}
          <div className="flex space-x-2 border-b border-[#27272a] mb-4 pb-1">
            <button
              onClick={() => setActiveMcpTab('claude')}
              className={`px-3 py-1 font-mono text-[11px] border-b-2 transition-all pb-1.5 ${
                activeMcpTab === 'claude'
                  ? 'border-[#22c55e] text-[#22c55e]'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              Claude Code
            </button>
            <button
              onClick={() => setActiveMcpTab('cursor')}
              className={`px-3 py-1 font-mono text-[11px] border-b-2 transition-all pb-1.5 ${
                activeMcpTab === 'cursor'
                  ? 'border-[#22c55e] text-[#22c55e]'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              Cursor Config
            </button>
            <button
              onClick={() => setActiveMcpTab('manual')}
              className={`px-3 py-1 font-mono text-[11px] border-b-2 transition-all pb-1.5 ${
                activeMcpTab === 'manual'
                  ? 'border-[#22c55e] text-[#22c55e]'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              Usage Syntax
            </button>
          </div>

          {/* Terminal Code Content */}
          <div className="bg-black p-2 text-xs font-mono select-all">
            {activeMcpTab === 'claude' && (
              <div className="space-y-2 text-[#a1a1aa]">
                <p className="text-[#52525b]">{"# Add the seclayer MCP tool to your active agent environment"}</p>
                <p className="text-zinc-300">
                  <span className="text-rose-400">claude</span> mcp add seclayer -- npx -y @seclayer/mcp --key <span className="text-[#22c55e]">YOUR_SECLAYER_API_KEY</span>
                </p>
                <p className="text-[#52525b] mt-4">{"# Once activated, ask Claude Code directly:"}</p>
                <p className="text-zinc-200">
                  "{'Run an audit check on https://staging-checkout.mydomain.io before deploying.'}"
                </p>
              </div>
            )}

            {activeMcpTab === 'cursor' && (
              <div className="space-y-2 text-[#a1a1aa]">
                <p className="text-[#52525b]">{"// Insert into Settings > Features > MCP > Add New Server"}</p>
                <div className="bg-[#0c0c0e] p-3 rounded border border-[#27272a] text-[11px] overflow-x-auto text-zinc-300 space-y-1">
                  <p>Name: <span className="text-[#22c55e]">seclayer</span></p>
                  <p>Type: <span className="text-purple-400">command</span></p>
                  <p>Command:</p>
                  <p className="text-[10px] text-[#a1a1aa] bg-black p-1.5 rounded select-all font-mono whitespace-nowrap border border-[#27272a]">
                    npx -y @seclayer/mcp --key <span className="text-[#22c55e]">YOUR_API_KEY</span>
                  </p>
                </div>
              </div>
            )}

            {activeMcpTab === 'manual' && (
              <div className="space-y-2 text-[#a1a1aa]">
                <p className="text-[#52525b]">{"// How your agent calls the tool once the server is configured"}</p>
                <p className="text-[#22c55e]">seclayer_scan({' {'}</p>
                <p className="pl-4">url: <span className="text-amber-500">"https://dev-payments.corp.sh"</span></p>
                <p className="text-[#22c55e]">{'}'})</p>
                <p className="text-[#52525b] mt-2">{"// The API key is set once at server startup (--key), never per call."}</p>
              </div>
            )}
          </div>

        </div>

      </div>
    </div>
  );
}
