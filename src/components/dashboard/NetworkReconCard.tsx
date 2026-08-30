import { useState, type FormEvent } from 'react';
import { Radar, Globe, ShieldCheck, AlertTriangle, ArrowRight } from 'lucide-react';
import { useNmap } from '../../hooks/useNmap.js';
import { useDomainVerification } from '../../hooks/useDomainVerification.js';
import { useNmapEvents } from '../../hooks/useNmapEvents.js';
import ScanConsole from '../scanProgress/ScanConsole.js';
import NmapProgressBar from '../scanProgress/NmapProgressBar.js';
import { liveEventsToLogs } from '../scanProgress/scanLogs.js';
import { parseNmapProgress } from '../../lib/nmapProgress.js';

interface Props {
  nm: ReturnType<typeof useNmap>;
  userId: string;
  freeMode?: boolean;
  devSkipDomainVerification?: boolean;
}

// Trigger card for Network Reconnaissance (nmap) — a fully independent scan
// surface: its own target input, its own domain-verification instance, its
// own inline live-progress ticker (reusing ScanConsole/liveEventsToLogs
// unmodified). Never touches the AppSec scan flow or posture score. Results
// are viewed in the "Network Scans" history tab, not here — this card only
// launches and shows progress while one is running.
export default function NetworkReconCard({ nm, userId, freeMode, devSkipDomainVerification }: Props) {
  const dv = useDomainVerification(nm.targetUrl, userId);
  // Fast (top-1000-port) scan by default — finishes in ~1-2 min even behind a
  // CDN. Deep opts into the exhaustive all-65535-port sweep (minutes, up to the
  // full host-timeout against a filtering CDN).
  const [deep, setDeep] = useState(false);
  const inFlight = nm.nmapScans.find((s) => s.status === 'queued' || s.status === 'scanning');
  const events = useNmapEvents(inFlight?.id || '');
  const logs = liveEventsToLogs(events);
  const progress = parseNmapProgress(events);

  const canLaunch = !inFlight && (dv.currentDomainVerified || !!devSkipDomainVerification);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canLaunch) return;
    void nm.launchScan(nm.targetUrl, deep);
  };

  return (
    <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
      <div className="flex items-center space-x-2.5 mb-4">
        <div className="p-1.5 bg-[#22c55e]/10 border border-[#22c55e]/20 rounded text-[#22c55e]">
          <Radar className="w-4 h-4" />
        </div>
        <h2 className="text-sm font-bold font-mono text-white">Network Reconnaissance</h2>
      </div>
      <p className="text-[#a1a1aa] text-xs font-mono mb-6">
        An nmap sweep of a verified target — service &amp; version fingerprints, OS guess, and NSE vulnerability-script hits. Scans the top 1,000 ports by default (fast); tick <em className="text-[#a1a1aa] not-italic">Deep scan</em> for all 65,535. Self-hosted only, and a fully independent scan from the AppSec report above: it never affects your posture score.
      </p>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="text-[11px] font-mono uppercase tracking-wider text-[#52525b] ml-1 block mb-2">Target URL or IP</label>
          <div className="flex bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors">
            <div className="flex items-center text-[#52525b] pl-3 pr-1.5 font-mono text-xs">
              <Globe className="w-4 h-4 text-[#52525b] mr-1.5" />
            </div>
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
              placeholder="scan-target.mydomain.io"
              value={nm.targetUrl}
              onChange={(e) => nm.setTargetUrl(e.target.value)}
              disabled={nm.isLaunching || !!inFlight}
              id="nmap-target-url-input"
            />
          </div>
        </div>

        {dv.currentDomain && !inFlight && (
          <div className={`p-3 rounded border text-[11px] font-mono flex items-start space-x-2 ${
            dv.currentDomainVerified ? 'border-[#22c55e]/25 bg-[#22c55e]/5 text-[#22c55e]'
              : devSkipDomainVerification ? 'border-purple-500/30 bg-purple-500/5 text-purple-300'
              : 'border-amber-500/25 bg-amber-500/5 text-amber-400'
          }`}>
            <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1.5">
              {dv.currentDomainVerified ? (
                <span>Ownership verified for <strong>{dv.currentDomain}</strong> — network reconnaissance is enabled for this target.</span>
              ) : devSkipDomainVerification ? (
                <span>Dev mode — ownership check bypassed (<code>DEV_SKIP_DOMAIN_VERIFICATION</code>). Only scan targets you own; this is disabled in production.</span>
              ) : (
                <>
                  <span>
                    Network reconnaissance requires proven ownership of <strong>{dv.currentDomain}</strong> — verify via DNS TXT record or well-known file first.
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

        {nm.launchError && (
          <div className="bg-[#f87171]/10 border border-[#f87171]/20 text-[#f87171] text-xs p-3 rounded flex items-center space-x-2 font-mono">
            <AlertTriangle className="w-4 h-4 text-[#f87171] shrink-0" />
            <span>{nm.launchError}</span>
          </div>
        )}

        {inFlight ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-[10px] font-mono text-[#52525b]">
              <span className="text-purple-400 uppercase tracking-wider">● Scanning {inFlight.url}…</span>
              <span>Started {new Date(inFlight.startedAt || inFlight.createdAt).toLocaleTimeString()}</span>
            </div>
            <NmapProgressBar progress={progress} />
            <ScanConsole logs={logs.length ? logs : ['[SYSTEM] Launching…']} />
          </div>
        ) : (
          <div className="flex items-center justify-between pt-2">
            <label className="flex items-start gap-2 text-[10px] font-mono text-[#a1a1aa] cursor-pointer select-none" htmlFor="nmap-deep-toggle">
              <input
                id="nmap-deep-toggle"
                type="checkbox"
                checked={deep}
                onChange={(e) => setDeep(e.target.checked)}
                disabled={nm.isLaunching}
                className="mt-0.5 accent-[#22c55e] cursor-pointer"
              />
              <span>
                <span className="text-white">Deep scan</span> — all 65,535 ports (slower, minutes)
                <span className="block text-[#52525b]">
                  Default scans the top 1,000 ports · {freeMode ? 'Free during beta' : '1 credit'} · service/OS/vuln-script depth
                </span>
              </span>
            </label>
            <button
              type="submit"
              disabled={nm.isLaunching || !nm.targetUrl.trim() || !canLaunch}
              className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0 cursor-pointer"
              id="nmap-launch-btn"
            >
              <Radar className="w-3.5 h-3.5" />
              <span>{nm.isLaunching ? 'Launching…' : 'Run Network Recon'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </form>
    </div>
  );
}
