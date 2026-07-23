import type { FormEvent } from 'react';
import { Play, Globe, ShieldCheck, AlertTriangle, Eye, Zap, ArrowRight } from 'lucide-react';
import { useDomainVerification } from '../../hooks/useDomainVerification.js';

type Identity = { authHeader: string; ownResource: string; ownMarker: string };

interface Props {
  scanUrl: string;
  setScanUrl: (v: string) => void;
  authHeader: string;
  setAuthHeader: (v: string) => void;
  showAdvanced: boolean;
  setShowAdvanced: (v: boolean) => void;
  bolaEnabled: boolean;
  setBolaEnabled: (v: boolean) => void;
  bolaA: Identity;
  setBolaA: (v: Identity) => void;
  bolaB: Identity;
  setBolaB: (v: Identity) => void;
  errorText: string;
  isPerformingAction: boolean;
  launchScan: (active: boolean) => void;
  handleScanSubmit: (e: FormEvent) => void;
  dv: ReturnType<typeof useDomainVerification>;
  freeMode?: boolean;
}

// The primary "trigger a pen-test" form: target URL, domain-verification prompt,
// optional authenticated + two-identity BOLA advanced options, and the passive /
// active red-team launch buttons.
export default function ScanLauncher(props: Props) {
  const {
    scanUrl, setScanUrl, authHeader, setAuthHeader, showAdvanced, setShowAdvanced,
    bolaEnabled, setBolaEnabled, bolaA, setBolaA, bolaB, setBolaB,
    errorText, isPerformingAction, launchScan, handleScanSubmit, dv, freeMode,
  } = props;

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <div className="flex items-center space-x-2.5 mb-4">
        <div className="p-1.5 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e]">
          <Play className="w-4 h-4" />
        </div>
        <h2 className="text-sm font-bold font-mono text-white">Trigger Penetration Test</h2>
      </div>
      <p className="text-[#a1a1aa] text-xs font-mono mb-6">
        Enter any public staging, production or application URL. Seclayer runs modern black-box scans checking HTTP headers security, Technology signatures leakage, directories exposures, SSL certificates validity, and cookie flags.
      </p>

      <form onSubmit={handleScanSubmit} className="space-y-4">
        <div>
          <label className="text-[11px] font-mono uppercase tracking-wider text-[#52525b] ml-1 block mb-2">Target URL</label>
          <div className="flex bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors">
            <div className="flex items-center text-[#52525b] pl-3 pr-1.5 font-mono text-xs">
              <Globe className="w-4 h-4 text-[#52525b] mr-1.5" />
              <span>https://</span>
            </div>
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
              placeholder="test-shop-staging.mydomain.io"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              disabled={isPerformingAction}
              id="target-url-input"
            />
          </div>
        </div>

        {dv.currentDomain && (
          <div className={`p-3 rounded border text-[11px] font-mono flex items-start space-x-2 ${
            dv.currentDomainVerified ? 'border-[#22c55e]/25 bg-[#22c55e]/5 text-[#22c55e]' : 'border-amber-500/25 bg-amber-500/5 text-amber-400'
          }`}>
            <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1.5">
              {dv.currentDomainVerified ? (
                <span>Ownership verified for <strong>{dv.currentDomain}</strong> — full active exploit testing (SQLi/XSS/SSRF/API) is enabled for this scan.</span>
              ) : (
                <>
                  <span>
                    Unverified target — this scan will run passive recon only (headers, TLS, DNS, exposed files). Verify ownership of <strong>{dv.currentDomain}</strong> via DNS TXT record or well-known file to unlock active exploit probes.
                  </span>
                  <div className="flex items-center flex-wrap gap-2 pt-0.5">
                    <button type="button" onClick={dv.handleStartVerification} disabled={dv.isVerifying} className="px-2 py-1 rounded bg-black border border-amber-500/30 text-amber-400 hover:border-amber-500/60 font-mono text-[9px] uppercase tracking-wide transition-all disabled:opacity-50 cursor-pointer">
                      Verify via DNS/File
                    </button>
                    {dv.verifyInfo && dv.verifyInfo.domain === dv.currentDomain && !dv.verifyInfo.verified && (
                      <button type="button" onClick={dv.handleCheckVerification} disabled={dv.isVerifying} className="px-2 py-1 rounded bg-black border border-[#27272a] text-[#a1a1aa] hover:text-white font-mono text-[9px] uppercase tracking-wide transition-all disabled:opacity-50 cursor-pointer">
                        {dv.isVerifying ? 'Checking…' : 'I’ve added it — Check Now'}
                      </button>
                    )}
                  </div>
                  {dv.verifyInfo && dv.verifyInfo.domain === dv.currentDomain && !dv.verifyInfo.verified && (
                    <div className="mt-1 p-2.5 bg-black/60 border border-[#27272a] rounded space-y-2 text-[#a1a1aa]">
                      <div>
                        <span className="text-[#52525b]">Option 1 — DNS TXT record:</span><br />
                        Name: <code className="text-white select-all">{dv.verifyInfo.txtRecord.name}</code><br />
                        Value: <code className="text-white select-all">{dv.verifyInfo.txtRecord.value}</code>
                      </div>
                      <div>
                        <span className="text-[#52525b]">Option 2 — well-known file:</span><br />
                        Host <code className="text-white select-all">https://{dv.currentDomain}{dv.verifyInfo.wellKnownFile.path}</code><br />
                        containing exactly: <code className="text-white select-all">{dv.verifyInfo.wellKnownFile.content}</code>
                      </div>
                    </div>
                  )}
                  {dv.verifyError && <div className="text-[#f87171]">{dv.verifyError}</div>}
                </>
              )}
            </div>
          </div>
        )}

        <div>
          <button type="button" onClick={() => setShowAdvanced(!showAdvanced)} className="text-[11px] font-mono text-[#52525b] hover:text-white uppercase tracking-wider flex items-center space-x-1 transition-colors">
            <span>{showAdvanced ? '- Hide Advanced Options' : '+ Show Advanced Options (Authenticated Scans)'}</span>
          </button>

          {showAdvanced && (
            <div className="mt-3 p-3 bg-black/40 border border-[#27272a] rounded space-y-3">
              <div>
                <label className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1">Authentication (optional)</label>
                <p className="text-[10px] font-mono text-[#a1a1aa] mb-2">Applied to every request — root, crawl, probes and templates. Use a Bearer/Basic token, or an explicit header like <span className="text-[#22c55e]">Cookie: session=…</span> or <span className="text-[#22c55e]">X-API-Key: …</span>.</p>
                <input type="text" className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors" placeholder="Bearer eyJhbGci…   |   Cookie: session=…   |   X-API-Key: …" value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} disabled={isPerformingAction} id="auth-header-input" />
              </div>

              <div className="pt-3 border-t border-[#27272a]/60">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={bolaEnabled} onChange={(e) => setBolaEnabled(e.target.checked)} disabled={isPerformingAction} className="accent-[#22c55e]" id="bola-enable" />
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#52525b]">Prove BOLA / IDOR — cross-tenant access (two test identities)</span>
                </label>
                {bolaEnabled && (
                  <div className="mt-2 space-y-3">
                    <p className="text-[10px] font-mono text-[#a1a1aa]">Give two accounts you own on this target. We sign in as <span className="text-[#22c55e]">A</span>, try to read <span className="text-[#22c55e]">B's</span> object, and only report <span className="text-[#22c55e]">PROVEN</span> if A receives B's data while a logged-out request is denied. Requires a verified domain.</p>
                    {([['A', bolaA, setBolaA], ['B', bolaB, setBolaB]] as const).map(([tag, val, set]) => (
                      <div key={tag} className="grid grid-cols-1 md:grid-cols-3 gap-2">
                        <div className="md:col-span-3 text-[9px] font-mono uppercase tracking-wider text-[#22c55e]">Identity {tag} (tenant-{tag})</div>
                        <input type="text" className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors" placeholder="Auth: Bearer …  |  Cookie: session=…" value={val.authHeader} onChange={(e) => set({ ...val, authHeader: e.target.value })} disabled={isPerformingAction} />
                        <input type="text" className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors" placeholder="Owned resource: /api/orders/1001" value={val.ownResource} onChange={(e) => set({ ...val, ownResource: e.target.value })} disabled={isPerformingAction} />
                        <input type="text" className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors" placeholder="Marker (optional): bob@…" value={val.ownMarker} onChange={(e) => set({ ...val, ownMarker: e.target.value })} disabled={isPerformingAction} />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {errorText && (
          <div className="bg-[#f87171]/10 border border-[#f87171]/20 text-[#f87171] text-xs p-3 rounded flex items-center space-x-2 font-mono">
            <AlertTriangle className="w-4 h-4 text-[#f87171] shrink-0" />
            <span>{errorText}</span>
          </div>
        )}

        <div className="flex flex-col gap-2 pt-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#52525b]">Cost per scan: <strong className="text-[#22c55e]">{freeMode ? 'Free during beta' : '1 credit'}</strong></span>
            {dv.currentDomain && (
              <span className="text-[9px] font-mono text-[#52525b]">
                {dv.currentDomainVerified ? 'Red-team unlocked for this domain' : 'Red-team requires DNS/file verification first'}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => void launchScan(false)} disabled={isPerformingAction || !scanUrl.trim()} className="px-4 py-2.5 bg-black border border-[#27272a] hover:border-[#3f3f46] text-[#a1a1aa] hover:text-white text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0 cursor-pointer" id="passive-scan-btn">
              <Eye className="w-3.5 h-3.5" />
              <span>Passive Scan</span>
            </button>
            <button type="submit" disabled={isPerformingAction || !scanUrl.trim()} className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0 cursor-pointer" id="trigger-scan-btn">
              <Zap className="w-3.5 h-3.5" />
              <span>Active Red-Team Scan</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
