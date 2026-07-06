import React, { useState } from 'react';
import { Shield, ArrowRight, Zap, Coins, Globe, Key, Terminal, Code, Clock, Eye, Download, Play, CheckCircle } from 'lucide-react';
import { motion } from 'motion/react';

interface LandingProps {
  onStartTrial: (initialUrl: string) => void;
  onNavigate: (view: string, arg?: string) => void;
  onSelectPack: (packName: 'single' | 'pack5' | 'pack20') => void;
  userEmail: string;
}

export default function Landing({ onStartTrial, onNavigate, onSelectPack, userEmail }: LandingProps) {
  const [targetUrl, setTargetUrl] = useState('');
  const [activeMcpTab, setActiveMcpTab] = useState<'claude' | 'cursor' | 'manual'>('claude');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    onStartTrial(targetUrl.trim());
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] selection:bg-[#22c55e]/30 selection:text-[#22c55e]">
      
      {/* Hero & Background Ambient Grid */}
      <div className="relative py-24 px-6 overflow-hidden border-b border-[#27272a] bg-[radial-gradient(120%_120%_at_50%_0%,rgba(34,197,94,0.05)_0%,rgba(9,9,11,0)_80%)]">
        {/* Aesthetic background matrix layout */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.01)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.01)_1px,transparent_1px)] bg-[size:48px_48px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

        <div className="max-w-4xl mx-auto text-center relative z-10 flex flex-col items-center">
          
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center space-x-2 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded py-1.5 px-3 mb-8"
          >
            <span className="w-2 h-2 rounded-full bg-[#22c55e] animate-pulse" />
            <span className="text-[#22c55e] font-mono text-xs uppercase tracking-widest pl-1">Seclayer v2.0 is now live</span>
          </motion.div>

          <motion.h1 
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="text-4xl sm:text-6xl font-mono tracking-tighter font-bold max-w-3xl mb-6 text-white leading-[1.1]"
          >
            Security layer for <br />
            <span className="text-[#22c55e]">
              every single deploy
            </span>
          </motion.h1>

          <motion.p 
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-[#a1a1aa] text-base max-w-xl mb-12 font-mono"
          >
            A black-box penetration testing platform. Submit a URL, purchase scan credits, and receive a plain-English AI-generated penetration testing report.
            <strong className="text-white"> Zero setup, zero subscription required.</strong>
          </motion.p>

          {/* Core URL scan trigger input */}
          <motion.form 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            onSubmit={handleSubmit}
            className="w-full max-w-2xl bg-[#0c0c0e] border border-[#27272a] rounded p-2.5 flex flex-col sm:flex-row items-center space-y-3 sm:space-y-0 sm:space-x-3 shadow-xl mb-8 hover:border-[#3f3f46] transition-colors"
          >
            <div className="relative flex-1 w-full pl-3 flex items-center">
              <Globe className="w-5 h-5 text-[#52525b] mr-3 shrink-0" />
              <input
                type="text"
                placeholder="Enter workspace, API or site URL (e.g., test-app.dev)..."
                className="bg-transparent text-white text-sm font-mono w-full focus:outline-none placeholder-[#52525b]"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                id="landing-url-input"
              />
            </div>
            <button
              type="submit"
              className="w-full sm:w-auto px-6 py-3 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded transition-all flex items-center justify-center space-x-2 shrink-0 active:scale-98 cursor-pointer"
              id="landing-url-submit"
            >
              <span>Audit Now</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </motion.form>

          {/* Quick Stats Banner */}
          <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-3 font-mono text-[10px] uppercase text-[#52525b] tracking-widest bg-[#0c0c0e] py-1.5 px-4 rounded border border-[#27272a] mb-8">
            <span>[+] Over 12,480 security audits executed</span>
            <span className="text-[#27272a]">|</span>
            <span>[+] API Endpoint coverage up to TLS 1.3</span>
          </div>


        </div>
      </div>

      {/* Core Pay-Per-Scan Pricing Cards */}
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

      {/* Dual Distribution Pitch: MCP Server for Developer Ecosystem */}
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
                    <span className="text-rose-400">claude</span> mcp add seclayer -- apiKey="<span className="text-[#22c55e]">YOUR_SECLAYER_API_KEY</span>"
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
                  <p className="text-[#52525b]">{"// Raw integration request block syntax"}</p>
                  <p className="text-[#22c55e]">toolSeclayerScan({' {'}</p>
                  <p className="pl-4">url: <span className="text-amber-500">"https://dev-payments.corp.sh"</span>,</p>
                  <p className="pl-4">apiKey: <span className="text-amber-500">"sl_live_83b19fc9c011e..."</span></p>
                  <p className="text-[#22c55e]">{'}'})</p>
                </div>
              )}
            </div>

          </div>

        </div>
      </div>

      {/* Trust Signpost / Interactive sample report previewer */}
      <div className="max-w-4xl mx-auto py-24 px-6">
        <div className="text-center mb-12">
          <p className="text-[#22c55e] font-mono text-xs uppercase tracking-widest mb-3">Live Sample Report</p>
          <h2 className="text-3xl font-mono tracking-tighter font-extrabold text-white">Inspect an Audited Posture Output</h2>
          <p className="text-[#a1a1aa] text-xs font-mono mt-3">Click on the sample report below to view executive summaries, risk severities, and developer recommended fixes.</p>
        </div>

        {/* Card of Sample Posture Report */}
        <div className="bg-black border border-[#27272a] rounded overflow-hidden shadow-xl" id="sample-report-card">
          {/* Header Row */}
          <div className="bg-[#0c0c0e] border-b border-[#27272a] p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
              <div className="flex items-center space-x-2.5">
                <span className="font-mono text-sm text-[#52525b]">[Target]</span>
                <strong className="font-mono text-sm text-white">staging-portal.payments-corp.net</strong>
                <span className="bg-[#f87171]/10 border border-[#f87171]/20 text-[#f87171] font-mono text-[9px] uppercase px-2 py-0.5 rounded">
                  High Risk Posture
                </span>
              </div>
              <p className="text-[#52525b] text-xs mt-1.5 font-mono">Assessed: 2026-05-24 • 1 Credit Consumed</p>
            </div>
            <div className="flex items-center space-x-3 shrink-0">
              <div className="text-right">
                <span className="text-[10px] font-mono text-[#52525b] uppercase block leading-none">POSTURE SCORE</span>
                <span className="text-3xl font-mono font-black text-[#f87171] leading-none">41<span className="text-xs text-[#52525b] font-normal">/100</span></span>
              </div>
            </div>
          </div>

          {/* Body */}
          <div className="p-6 space-y-6">
            {/* Executive Summary */}
            <div className="bg-[#0c0c0e] border-l-2 border-[#f87171]/50 p-4 rounded-r">
              <h4 className="font-mono text-xs text-[#f87171] uppercase tracking-widest mb-1.5">Executive Summary (AI generated)</h4>
              <p className="text-[#a1a1aa] text-xs font-mono leading-relaxed">
                The target gateway exhibits multiple severe perimeter configuration issues. A critical development configuration file <code className="bg-black px-1 py-0.5 rounded text-[#f87171] font-mono">/.env</code> was detected and successfully downloaded, yielding plaintext database credentials and custom decryption keys. Additionally, the completely absent Content-Security-Policy (CSP) exposes the user routing interface to standard browser injection exploits. Hardening of server-level configuration structures represents an immediate priority.
              </p>
            </div>

            {/* Findings Lists */}
            <div className="space-y-4">
              <h4 className="font-mono text-xs text-[#52525b] uppercase tracking-widest">Deficiencies Detected (2)</h4>
              
              {/* Finding 1 */}
              <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="bg-[#f87171] text-black text-[9px] font-mono font-bold uppercase py-0.5 px-1.5 rounded">Critical</span>
                    <h5 className="text-white text-xs font-mono font-bold">Dotfile Storage Exposure: /.env Configuration Leak</h5>
                  </div>
                  <span className="text-[10px] text-[#52525b] font-mono">Access Control</span>
                </div>
                <p className="text-[#a1a1aa] text-xs font-mono mb-3">
                  The application allows public HTTP GET requests to resolve the root configuration files. An attacker querying the path downloaded vital keys, API tokens, and private connection links.
                </p>
                <div className="bg-black p-3 rounded border border-[#27272a] text-xs text-[#22c55e] font-mono">
                  <span className="text-[#52525b] block text-[9px] font-mono uppercase tracking-wider mb-1">Developer Remediation Fix:</span>
                  Update nginx host blocks to return 403 Forbidden to dotfiles: <br />
                  <code className="bg-black border border-[#27272a] text-[#a1a1aa] p-1 rounded inline-block mt-1 font-mono text-[10px]">location ~ /\. {'{'} deny all; {'}'}</code>
                </div>
              </div>

               {/* Finding 2 */}
              <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
                <div className="flex justify-between items-start mb-2 flex-wrap gap-2">
                  <div className="flex items-center space-x-2">
                    <span className="bg-amber-500 text-black text-[9px] font-mono font-bold uppercase py-0.5 px-1.5 rounded">High</span>
                    <h5 className="text-white text-xs font-mono font-bold">Missing Content-Security-Policy (CSP)</h5>
                  </div>
                  <span className="text-[10px] text-[#52525b] font-mono">Headers Security</span>
                </div>
                <p className="text-[#a1a1aa] text-xs font-mono mb-3">
                  The browser loads scripts, styling, or frames from arbitrary sources. This allows dynamic placement of malicious keyloggers or click-capture targets on staging forms.
                </p>
                <div className="bg-black p-3 rounded border border-[#27272a] text-xs text-[#22c55e] font-mono animate-none">
                  <span className="text-[#52525b] block text-[9px] font-mono uppercase tracking-wider mb-1">Developer Remediation Fix:</span>
                  Configure gateway headers block: <br />
                  <code className="bg-black border border-[#27272a] text-[#a1a1aa] p-1 rounded inline-block mt-1 font-mono text-[10px]">add_header Content-Security-Policy "default-src 'self';"</code>
                </div>
              </div>

            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-[#27272a] bg-[#0c0c0e] py-12 text-[#a1a1aa] text-xs font-mono text-center">
        <div className="max-w-7xl mx-auto px-6 space-y-4">
          <p className="text-[11px]">Domain: <strong className="text-white">seclayer.io</strong> • Stack: React + Express + DeepSeek AI</p>
          <p className="text-[#52525b]">© 2026 Seclayer Penetration Technologies. All rights reserved. Support: hello@seclayer.io</p>
        </div>
      </footer>

    </div>
  );
}
