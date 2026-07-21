// Static sample report preview shown on the landing page.
export default function SampleReportSection() {
  return (
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
  );
}
