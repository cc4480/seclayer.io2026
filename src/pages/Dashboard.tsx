import React, { useState, useEffect } from 'react';
import { 
  Shield, Play, Plus, Trash2, Key, HelpCircle, 
  Clock, Coins, Globe, Terminal, RefreshCw, CheckCircle, 
  ExternalLink, ArrowRight, AlertTriangle, ShieldCheck,
  Code, Copy, FileText
} from 'lucide-react';
import { Scan, ApiKey, User } from '../types.js';

interface DashboardProps {
  user: User;
  scans: Scan[];
  apiKeys: ApiKey[];
  credits: number;
  transactions: any[];
  justGeneratedKey: { id: string; rawKey: string } | null;
  onDismissGeneratedKey: () => void;
  onInitiateScan: (url: string, authHeader?: string) => void;
  onGenerateKey: () => void;
  onRevokeKey: (keyId: string) => void;
  onPurchaseCredits: (packName: 'single' | 'pack5' | 'pack20') => void;
  onViewReport: (scanId: string) => void;
  isPerformingAction: boolean;
}

export default function Dashboard({
  user,
  scans,
  apiKeys,
  credits,
  transactions,
  justGeneratedKey,
  onDismissGeneratedKey,
  onInitiateScan,
  onGenerateKey,
  onRevokeKey,
  onPurchaseCredits,
  onViewReport,
  isPerformingAction
}: DashboardProps) {
  const [scanUrl, setScanUrl] = useState('');
  const [authHeader, setAuthHeader] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [buyPack, setBuyPack] = useState<'single' | 'pack5' | 'pack20'>('pack5');
  const [isBuying, setIsBuying] = useState(false);
  const [errorText, setErrorText] = useState('');

  // Production-ready addition state variables
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'scans' | 'billing' | 'exclusions' | 'monitoring' | 'api-docs'>('scans');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [prevCredits, setPrevCredits] = useState(credits);
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

  // Dynamic false positives suppression rules states
  const [suppressRules, setSuppressRules] = useState<any[]>([]);
  const [isDeletingRule, setIsDeletingRule] = useState<string | null>(null);

  // Monitoring targets
  const [monitoredTargets, setMonitoredTargets] = useState<any[]>([]);
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorFreq, setMonitorFreq] = useState(7);
  const [monitorDay, setMonitorDay] = useState('Monday');
  const [monitorTime, setMonitorTime] = useState('09:00');
  const [isAddingMonitor, setIsAddingMonitor] = useState(false);

  // Alert webhook (Slack-compatible)
  const [webhookUrl, setWebhookUrl] = useState(user.notifyWebhook || '');
  const [webhookSaving, setWebhookSaving] = useState(false);
  const [webhookSaved, setWebhookSaved] = useState(false);

  const saveWebhook = async () => {
    setWebhookSaving(true);
    setWebhookSaved(false);
    try {
      const res = await fetch('/api/user/webhook', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl.trim() })
      });
      if (res.ok) {
        setWebhookSaved(true);
        setTimeout(() => setWebhookSaved(false), 2500);
      }
    } catch (err) {
      console.error('Error saving webhook:', err);
    } finally {
      setWebhookSaving(false);
    }
  };

  const fetchSuppressRules = async () => {
    try {
      const res = await fetch(`/api/suppressions`);
      if (res.ok) {
        const data = await res.json();
        setSuppressRules(data.suppressions || []);
      }
    } catch (err) {
      console.error('Error loading exclusion rules:', err);
    }
  };

  const fetchMonitoredTargets = async () => {
    try {
      const res = await fetch(`/api/monitoring`);
      if (res.ok) {
        const data = await res.json();
        setMonitoredTargets(data.monitoredTargets || []);
      }
    } catch (err) {
      console.error('Error loading monitoring targets:', err);
    }
  };

  useEffect(() => {
    fetchSuppressRules();
    fetchMonitoredTargets();
  }, [user.id, scans]);

  const handleAddMonitor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!monitorUrl.trim()) return;
    setIsAddingMonitor(true);

    let scheduleString = `Every day at ${monitorTime}`;
    if (monitorFreq === 7) {
      scheduleString = `Every ${monitorDay} at ${monitorTime}`;
    } else if (monitorFreq === 30) {
      scheduleString = `Monthly on the 1st at ${monitorTime}`;
    }

    try {
      const res = await fetch('/api/monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: monitorUrl, frequencyDays: monitorFreq, scheduleString })
      });
      if (res.ok) {
        setMonitorUrl('');
        fetchMonitoredTargets();
      }
    } finally {
      setIsAddingMonitor(false);
    }
  };

  const handleDeleteMonitor = async (id: string) => {
    try {
      const res = await fetch(`/api/monitoring/${id}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        fetchMonitoredTargets();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Toast notifier for balance changes
  useEffect(() => {
    if (credits > prevCredits) {
      setToastMsg(`Sandbox Top-up Successful! Added ${credits - prevCredits} scan credits.`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    }
    setPrevCredits(credits);
  }, [credits, prevCredits]);

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setErrorText('');
    const urlStr = scanUrl.trim();
    if (!urlStr) return;

    if (credits < 1) {
      setErrorText('Insufficient balances available. Please top-up credits to run a scan.');
      return;
    }

    onInitiateScan(urlStr, authHeader.trim() || undefined);
    setScanUrl('');
    setAuthHeader('');
  };

  const handleBuyCredits = async () => {
    setIsBuying(true);
    // Mimic the full stripe checkout redirect loop
    setTimeout(() => {
      onPurchaseCredits(buyPack);
      setIsBuying(false);
    }, 1200);
  };

  const handleCopyKey = (keyText: string, keyId: string) => {
    navigator.clipboard.writeText(keyText);
    setCopiedKeyId(keyId);
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  // --- Domain ownership verification ---
  // Active exploit probing (SQLi/XSS/SSRF/etc.) only runs once a domain is
  // verified; unverified targets still get a full passive scan. This panel
  // is UX sugar only — enforcement happens server-side regardless.
  const [domainVerifications, setDomainVerifications] = useState<any[]>([]);
  const [verifyInfo, setVerifyInfo] = useState<any | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState('');

  const fetchDomainVerifications = async () => {
    try {
      const res = await fetch('/api/domains');
      if (res.ok) {
        const data = await res.json();
        setDomainVerifications(data.domains || []);
      }
    } catch (err) {
      console.error('Error loading domain verifications:', err);
    }
  };

  useEffect(() => {
    fetchDomainVerifications();
  }, [user.id]);

  const currentDomain = (() => {
    const trimmed = scanUrl.trim();
    if (!trimmed) return '';
    try {
      const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      return new URL(withScheme).hostname.toLowerCase();
    } catch {
      return '';
    }
  })();

  const currentDomainVerified = domainVerifications.some((d) => d.domain === currentDomain && d.verified);

  const handleStartVerification = async () => {
    if (!currentDomain) return;
    setIsVerifying(true);
    setVerifyError('');
    try {
      const res = await fetch('/api/domains/verify/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim() })
      });
      const data = await res.json();
      if (res.ok) {
        setVerifyInfo(data);
        if (data.verified) fetchDomainVerifications();
      } else {
        setVerifyError(data.message || 'Could not start verification.');
      }
    } catch {
      setVerifyError('Could not start verification.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCheckVerification = async () => {
    if (!currentDomain) return;
    setIsVerifying(true);
    setVerifyError('');
    try {
      const res = await fetch('/api/domains/verify/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim() })
      });
      const data = await res.json();
      if (res.ok && data.verified) {
        setVerifyInfo(null);
        fetchDomainVerifications();
      } else {
        setVerifyError(data.message || 'Verification not detected yet.');
      }
    } catch {
      setVerifyError('Could not check verification.');
    } finally {
      setIsVerifying(false);
    }
  };

  const filteredScans = scans.filter((scan) => {
    // 1. URL search
    if (searchQuery.trim() && !scan.url.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    // 2. Status filter
    if (filterStatus !== 'all') {
      if (filterStatus === 'complete' && scan.status !== 'complete') return false;
      if (filterStatus === 'failed' && scan.status !== 'failed') return false;
      if (filterStatus === 'active' && ['complete', 'failed'].includes(scan.status)) return false;
    }
    // 3. Severity filter
    if (filterSeverity !== 'all') {
      if (scan.status !== 'complete' || scan.severity !== filterSeverity) return false;
    }
    return true;
  });

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-7xl mx-auto space-y-10">
        
        {/* Row 1: Header / Status banner */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0c0c0e] p-6 rounded border border-[#27272a] relative overflow-hidden">
          <div className="absolute top-0 right-0 w-80 h-80 bg-[#22c55e]/5 rounded-full blur-[80px] pointer-events-none" />
          
          <div className="relative z-10 w-full md:w-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div>
              <h1 className="text-2xl font-mono font-bold tracking-tighter text-white mb-1">Developer Console</h1>
              <p className="text-[#a1a1aa] text-xs font-mono">
                Account context: <span className="text-white">{user.email}</span>
              </p>
            </div>
          </div>
          
          <div className="flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-6 relative z-10 w-full md:w-auto">

            <div className="text-right flex items-center justify-between w-full md:w-auto md:block pt-4 border-t border-[#27272a]/40 md:pt-0 md:border-0">
              <span className="text-[10px] font-mono text-[#52525b] uppercase block md:mb-0.5">Available Balance</span>
              <span className="text-2xl font-mono font-black text-[#22c55e] flex items-center space-x-2">
                <Coins className="w-5 h-5 text-[#22c55e] shrink-0" />
                <span>{credits} <span className="text-xs font-normal text-[#52525b] font-mono">scans</span></span>
              </span>
            </div>
          </div>
        </div>

        {/* Bento Grid Layer */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* Left Block: quick scan launcher & pricing booster (col span 7) */}
          <div className="lg:col-span-7 space-y-8">
            
            {/* Quick Scan Launcher */}
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

                {currentDomain && (
                  <div className={`p-3 rounded border text-[11px] font-mono flex items-start space-x-2 ${
                    currentDomainVerified
                      ? 'border-[#22c55e]/25 bg-[#22c55e]/5 text-[#22c55e]'
                      : 'border-amber-500/25 bg-amber-500/5 text-amber-400'
                  }`}>
                    <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    <div className="flex-1 space-y-1.5">
                      {currentDomainVerified ? (
                        <span>Ownership verified for <strong>{currentDomain}</strong> — full active exploit testing (SQLi/XSS/SSRF/API) is enabled for this scan.</span>
                      ) : (
                        <>
                          <span>
                            Unverified target — this scan will run passive recon only (headers, TLS, DNS, exposed files). Verify ownership of <strong>{currentDomain}</strong> to unlock active exploit probes.
                          </span>
                          <div className="flex items-center flex-wrap gap-2 pt-0.5">
                            <button
                              type="button"
                              onClick={handleStartVerification}
                              disabled={isVerifying}
                              className="px-2 py-1 rounded bg-black border border-amber-500/30 text-amber-400 hover:border-amber-500/60 font-mono text-[9px] uppercase tracking-wide transition-all disabled:opacity-50 cursor-pointer"
                            >
                              Verify Ownership
                            </button>
                            {verifyInfo && verifyInfo.domain === currentDomain && !verifyInfo.verified && (
                              <button
                                type="button"
                                onClick={handleCheckVerification}
                                disabled={isVerifying}
                                className="px-2 py-1 rounded bg-black border border-[#27272a] text-[#a1a1aa] hover:text-white font-mono text-[9px] uppercase tracking-wide transition-all disabled:opacity-50 cursor-pointer"
                              >
                                {isVerifying ? 'Checking…' : 'I’ve added it — Check Now'}
                              </button>
                            )}
                          </div>
                          {verifyInfo && verifyInfo.domain === currentDomain && !verifyInfo.verified && (
                            <div className="mt-1 p-2.5 bg-black/60 border border-[#27272a] rounded space-y-2 text-[#a1a1aa]">
                              <div>
                                <span className="text-[#52525b]">Option 1 — DNS TXT record:</span><br />
                                Name: <code className="text-white select-all">{verifyInfo.txtRecord.name}</code><br />
                                Value: <code className="text-white select-all">{verifyInfo.txtRecord.value}</code>
                              </div>
                              <div>
                                <span className="text-[#52525b]">Option 2 — well-known file:</span><br />
                                Host <code className="text-white select-all">https://{currentDomain}{verifyInfo.wellKnownFile.path}</code><br />
                                containing exactly: <code className="text-white select-all">{verifyInfo.wellKnownFile.content}</code>
                              </div>
                            </div>
                          )}
                          {verifyError && <div className="text-[#f87171]">{verifyError}</div>}
                        </>
                      )}
                    </div>
                  </div>
                )}

                <div>
                  <button
                    type="button"
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    className="text-[11px] font-mono text-[#52525b] hover:text-white uppercase tracking-wider flex items-center space-x-1 transition-colors"
                  >
                    <span>{showAdvanced ? '- Hide Advanced Options' : '+ Show Advanced Options (Authenticated Scans)'}</span>
                  </button>
                  
                  {showAdvanced && (
                    <div className="mt-3 p-3 bg-black/40 border border-[#27272a] rounded space-y-3">
                      <div>
                        <label className="text-[10px] font-mono uppercase tracking-wider text-[#52525b] block mb-1">Authentication (optional)</label>
                        <p className="text-[10px] font-mono text-[#a1a1aa] mb-2">Applied to every request — root, crawl, probes and templates. Use a Bearer/Basic token, or an explicit header like <span className="text-[#22c55e]">Cookie: session=…</span> or <span className="text-[#22c55e]">X-API-Key: …</span>.</p>
                        <input
                          type="text"
                          className="bg-black border border-[#27272a] focus:border-[#22c55e] text-white text-xs font-mono w-full focus:outline-none p-2 rounded placeholder-[#52525b] transition-colors"
                          placeholder="Bearer eyJhbGci…   |   Cookie: session=…   |   X-API-Key: …"
                          value={authHeader}
                          onChange={(e) => setAuthHeader(e.target.value)}
                          disabled={isPerformingAction}
                          id="auth-header-input"
                        />
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

                <div className="flex items-center justify-between pt-2">
                  <span className="text-[10px] font-mono text-[#52525b]">
                    Cost per scan: <strong className="text-[#22c55e]">1 credit</strong>
                  </span>
                  <button
                    type="submit"
                    disabled={isPerformingAction || !scanUrl.trim()}
                    className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-mono font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center space-x-2 shrink-0 cursor-pointer"
                    id="trigger-scan-btn"
                  >
                    <span>Execute audit</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </form>
            </div>

            {/* Price Pack Booster */}
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
                      buyPack === pack.id 
                        ? 'border-[#22c55e] bg-[#22c55e]/5' 
                        : 'border-[#27272a] hover:border-[#3f3f46] bg-black'
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

          </div>

          {/* Right Block: API Keys (MCP client setup) (col span 5) */}
          <div className="lg:col-span-5 space-y-8">
            
            {/* Developer Keys management */}
            <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-2.5">
                  <div className="p-1.5 bg-black border border-[#27272a] rounded text-[#22c55e]">
                    <Key className="w-4 h-4" />
                  </div>
                  <h2 className="text-sm font-bold font-mono text-white">Developer API Keys</h2>
                </div>
                <button
                  onClick={onGenerateKey}
                  className="px-2.5 py-1.5 bg-black border border-[#27272a] hover:border-[#22c55e]/30 hover:text-[#22c55e] rounded text-white text-[10px] font-bold font-mono uppercase tracking-wider transition-all flex items-center space-x-1 cursor-pointer"
                  id="generate-api-key-btn"
                >
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
                    <button
                      onClick={onDismissGeneratedKey}
                      className="text-[9px] font-mono uppercase text-[#52525b] hover:text-white cursor-pointer"
                    >
                      Dismiss
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="text-xs font-mono text-white font-bold select-all break-all flex-1">{justGeneratedKey.rawKey}</code>
                    <button
                      onClick={() => handleCopyKey(justGeneratedKey.rawKey, justGeneratedKey.id)}
                      className="px-2 py-1 rounded bg-[#18181b] border border-[#27272a] text-[#a1a1aa] hover:text-[#22c55e] font-mono text-[9px] uppercase tracking-wide transition-all shrink-0 cursor-pointer"
                    >
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
                    <div
                       key={key.id}
                       className={`p-3.5 rounded border bg-black border-[#27272a] flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-opacity ${
                         key.active ? 'opacity-100' : 'opacity-40 pointer-events-none'
                       }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                          <code className="text-xs font-mono text-[#22c55e] font-bold select-all">
                            {key.keyPreview}
                          </code>
                          <span className={`text-[8px] font-mono px-1 py-0.25 rounded ${
                            key.active ? 'bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e]' : 'bg-[#18181b] text-[#52525b]'
                          }`}>
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
                          <button
                            onClick={() => onRevokeKey(key.id)}
                            className="p-1.5 rounded text-[#52525b] hover:text-[#f87171] hover:bg-[#18181b] transition-colors cursor-pointer"
                            title="Revoke Key"
                            id={`revoke-key-${key.id}`}
                          >
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
              <p className="text-[#a1a1aa] text-xs mb-4 font-mono">
                Set up Cursor with Seclayer by introducing a new command type:
              </p>
              <div className="bg-black p-3 rounded font-mono text-[10px] text-zinc-300 select-all leading-relaxed border border-[#27272a] break-all mb-4">
                npx -y @seclayer/mcp --key <span className="text-[#22c55e]">{justGeneratedKey?.rawKey || "YOUR_API_KEY"}</span>
              </div>
              <span className="text-[10px] text-[#52525b] flex items-center space-x-1 font-mono">
                <ShieldCheck className="w-3.5 h-3.5 text-[#22c55e] shrink-0" />
                <span>Provides the seclayer_scan tool context natively</span>
              </span>
            </div>

          </div>

        </div>

        {/* Row 3: Scans Queue, Histories list and Billing history */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6 relative">
          
          {/* Tabs header */}
          <div className="flex flex-wrap gap-1.5 border-b border-[#27272a]/80 mb-6">
            <button
              onClick={() => setActiveTab('scans')}
              className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
                activeTab === 'scans'
                  ? 'border-[#22c55e] text-white font-bold'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              [+] Vulnerability Scans History ({scans.length})
            </button>
            <button
              onClick={() => setActiveTab('monitoring')}
              className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
                activeTab === 'monitoring'
                  ? 'border-[#22c55e] text-white font-bold'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              [+] Continuous Monitoring
            </button>
            <button
              onClick={() => setActiveTab('exclusions')}
              className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
                activeTab === 'exclusions'
                  ? 'border-[#22c55e] text-white font-bold'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              [+] Risk Exclusions & FP Rules ({suppressRules.length})
            </button>
            <button
              onClick={() => setActiveTab('billing')}
              className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
                activeTab === 'billing'
                  ? 'border-[#22c55e] text-white font-bold'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              [+] Billing & Receipts Log ({transactions.length})
            </button>
            <button
              onClick={() => setActiveTab('api-docs')}
              className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
                activeTab === 'api-docs'
                  ? 'border-[#22c55e] text-white font-bold'
                  : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
              }`}
            >
              [+] API Documentation
            </button>
          </div>

          {activeTab === 'scans' && (
            <div className="space-y-4">
              {/* Filter controls */}
              <div className="flex flex-col md:flex-row gap-4 items-center justify-between pb-4 border-b border-[#27272a]/20">
                <div className="w-full md:max-w-xs bg-black border border-[#27272a] rounded px-3 py-1.5 flex items-center focus-within:border-[#22c55e] transition-colors">
                  <Globe className="w-4 h-4 text-[#52525b] mr-2 shrink-0" />
                  <input
                    type="text"
                    placeholder="Search target URL..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-transparent text-white text-xs font-mono focus:outline-none w-full placeholder-[#52525b]"
                  />
                </div>

                <div className="flex gap-3 w-full md:w-auto flex-wrap">
                  <select
                    value={filterStatus}
                    onChange={(e) => setFilterStatus(e.target.value)}
                    className="bg-black border border-[#27272a] rounded px-3 py-1.5 text-xs font-mono text-[#a1a1aa] focus:outline-none focus:border-[#22c55e] cursor-pointer"
                  >
                    <option value="all">All States</option>
                    <option value="complete">Complete Only</option>
                    <option value="failed">Failed Only</option>
                    <option value="active">Active (Queued/Scanning/Analyzing)</option>
                  </select>

                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="bg-black border border-[#27272a] rounded px-3 py-1.5 text-xs font-mono text-[#a1a1aa] focus:outline-none focus:border-[#22c55e] cursor-pointer"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical Only</option>
                    <option value="high">High Only</option>
                    <option value="medium">Medium Only</option>
                    <option value="low">Low Only</option>
                    <option value="info">Info Only</option>
                  </select>
                </div>
              </div>

              {filteredScans.length === 0 ? (
                <div className="text-center py-12 bg-black rounded border border-dashed border-[#27272a]">
                  <span className="text-xs text-[#52525b] font-mono block mb-2">No audits matched your search criteria</span>
                  <p className="text-[11px] text-[#52525b] max-w-sm mx-auto font-mono">Try adjusting your filters or URL search queries to view older audits.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[#27272a] text-[#52525b] font-mono text-[10px] uppercase tracking-wider pb-3">
                        <th className="py-3 px-4">Audited Target URL</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Postures Score</th>
                        <th className="py-3 px-4">Vulnerabilities</th>
                        <th className="py-3 px-4 text-right">Execution Date</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#27272a]/20 text-xs font-mono">
                      {filteredScans.map((scan) => {
                        // Status Badge selection
                        let statusBadge = (
                          <span className="bg-black text-[#52525b] font-mono text-[9px] uppercase px-2 py-0.5 rounded border border-[#27272a]">
                            {scan.status}
                          </span>
                        );
                        if (scan.status === 'complete') {
                          statusBadge = (
                            <span className="bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e] font-mono text-[9px] uppercase px-2 py-0.5 rounded flex items-center space-x-1.5 w-fit">
                              <CheckCircle className="w-3 h-3 text-[#22c55e] shrink-0" />
                              <span>Complete</span>
                            </span>
                          );
                        } else if (scan.status === 'queued') {
                          statusBadge = (
                            <span className="bg-blue-950/40 border border-[#27272a] text-blue-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">
                              Queued
                            </span>
                          );
                        } else if (scan.status === 'scanning') {
                          statusBadge = (
                            <span className="bg-purple-950/40 border border-[#27272a] text-purple-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">
                              Scanning...
                            </span>
                          );
                        } else if (scan.status === 'analyzing') {
                          statusBadge = (
                            <span className="bg-amber-950/40 border border-[#27272a] text-amber-400 font-mono text-[9px] uppercase px-2 py-0.5 rounded animate-pulse">
                              Analyzing AI...
                            </span>
                          );
                        } else if (scan.status === 'failed') {
                          statusBadge = (
                            <span className="bg-[#f87171]/10 border border-[#f87171]/25 text-[#f87171] font-mono text-[9px] uppercase px-2 py-0.5 rounded">
                              Failed
                            </span>
                          );
                        }

                        // Score calculation badge
                        const scoreColor = 
                          !scan.score ? 'text-zinc-500' :
                          scan.score >= 90 ? 'text-[#22c55e]' :
                          scan.score >= 70 ? 'text-amber-400' : 'text-[#f87171]';

                        // Severity calculation Badge
                        let severityBadge = (
                          <span className="text-[#52525b] font-mono text-[10px]">—</span>
                        );
                        if (scan.status === 'complete' && scan.severity) {
                          const colorClass = 
                            scan.severity === 'critical' || scan.severity === 'high' ? 'bg-[#f87171]/10 text-[#f87171] font-bold border border-[#f87171]/20' : 
                            scan.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/10' :
                            'bg-black text-[#a1a1aa] border border-[#27272a]';
                          severityBadge = (
                            <span className={`text-[9px] font-mono uppercase px-2 py-0.5 rounded ${colorClass}`}>
                              {scan.severity}
                            </span>
                          );
                        }

                        return (
                          <tr 
                            key={scan.id} 
                            onClick={() => onViewReport(scan.id)}
                            className="hover:bg-black transition-colors cursor-pointer group"
                          >
                            <td className="py-3.5 px-4 font-mono font-bold text-white max-w-xs truncate">
                              <span className="flex items-center space-x-1.5">
                                <Globe className="w-3.5 h-3.5 text-[#52525b] shrink-0" />
                                <span>{scan.url}</span>
                              </span>
                            </td>
                            <td className="py-3.5 px-4">{statusBadge}</td>
                            <td className="py-3.5 px-4 font-mono font-black text-sm">
                              {scan.score ? (
                                <span className={scoreColor}>{scan.score}</span>
                              ) : (
                                <span className="text-[#52525b] font-mono text-xs font-normal">Pending</span>
                              )}
                            </td>
                            <td className="py-3.5 px-4">{severityBadge}</td>
                            <td className="py-3.5 px-4 text-right font-mono text-[11px] text-[#52525b] group-hover:text-[#22c55e] transition-colors">
                              <div className="flex items-center justify-end space-x-1.5">
                                <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
                                <ExternalLink className="w-3 h-3 text-[#27272a] group-hover:text-[#22c55e] transition-colors shrink-0" />
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab === 'monitoring' && (
            <div className="space-y-6 animate-fade-in text-xs font-mono">
              <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
                <Clock className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-white text-xs uppercase font-bold">Continuous Security Monitoring</h4>
                  <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
                    Set up automated, recurring scans for your critical infrastructure. Monitoring tasks will automatically deduct credits from your balance per execution.
                  </p>
                </div>
              </div>

              <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
                <h3 className="text-sm font-bold font-mono text-white mb-1.5">Alert Webhook <span className="text-[10px] text-[#52525b] font-normal">(Slack-compatible, optional)</span></h3>
                <p className="text-[10px] text-[#a1a1aa] mb-3">Get notified when any scan (manual or monitored) finds high/critical issues. Paste a Slack incoming webhook or any JSON endpoint.</p>
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
                    <input
                      type="text"
                      className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
                      placeholder="https://hooks.slack.com/services/…"
                      value={webhookUrl}
                      onChange={(e) => setWebhookUrl(e.target.value)}
                      id="webhook-input"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={saveWebhook}
                    disabled={webhookSaving}
                    className="px-4 py-2 bg-[#18181b] hover:bg-[#27272a] text-white text-[11px] font-mono font-bold uppercase tracking-wider border border-[#27272a] rounded transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
                  >
                    {webhookSaving ? 'Saving…' : webhookSaved ? 'Saved ✓' : webhookUrl.trim() ? 'Save Webhook' : 'Disable'}
                  </button>
                </div>
              </div>

              <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
                <h3 className="text-sm font-bold font-mono text-white mb-4">Add Monitor Target</h3>
                <form onSubmit={handleAddMonitor} className="flex flex-col gap-3">
                  <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
                    <Globe className="w-4 h-4 text-[#52525b] mx-2" />
                    <input
                      type="text"
                      className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
                      placeholder="https://production.api.yoursite.com"
                      value={monitorUrl}
                      onChange={(e) => setMonitorUrl(e.target.value)}
                      disabled={isAddingMonitor}
                    />
                  </div>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
                      <select
                        value={monitorFreq}
                        onChange={(e) => setMonitorFreq(Number(e.target.value))}
                        className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer"
                        disabled={isAddingMonitor}
                      >
                        <option value={1} className="bg-black">Daily</option>
                        <option value={7} className="bg-black">Weekly</option>
                        <option value={30} className="bg-black">Monthly</option>
                      </select>
                    </div>
                    
                    {monitorFreq === 7 && (
                      <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
                        <select
                          value={monitorDay}
                          onChange={(e) => setMonitorDay(e.target.value)}
                          className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer"
                          disabled={isAddingMonitor}
                        >
                          <option value="Monday" className="bg-black">Monday</option>
                          <option value="Tuesday" className="bg-black">Tuesday</option>
                          <option value="Wednesday" className="bg-black">Wednesday</option>
                          <option value="Thursday" className="bg-black">Thursday</option>
                          <option value="Friday" className="bg-black">Friday</option>
                          <option value="Saturday" className="bg-black">Saturday</option>
                          <option value="Sunday" className="bg-black">Sunday</option>
                        </select>
                      </div>
                    )}
                    
                    <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
                      <input
                        type="time"
                        value={monitorTime}
                        onChange={(e) => setMonitorTime(e.target.value)}
                        className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer [color-scheme:dark]"
                        disabled={isAddingMonitor}
                      />
                    </div>
                    
                    <button
                      type="submit"
                      disabled={isAddingMonitor || !monitorUrl.trim()}
                      className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer w-full sm:w-auto ml-auto"
                    >
                      {isAddingMonitor ? <RefreshCw className="w-4 h-4 animate-spin text-black" /> : <Plus className="w-4 h-4 text-black" />}
                      <span>Add Monitor</span>
                    </button>
                  </div>
                </form>
              </div>

              <div className="space-y-3">
                {monitoredTargets.length === 0 ? (
                  <div className="text-center py-8 bg-black rounded border border-[#27272a]">
                    <span className="text-xs text-[#52525b] font-mono">No active monitoring targets configured</span>
                  </div>
                ) : (
                  monitoredTargets.map((target) => (
                    <div key={target.id} className="p-4 bg-black border border-[#27272a] rounded flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                      <div className="space-y-1.5">
                        <div className="flex items-center space-x-2">
                          <Globe className="w-4 h-4 text-[#52525b]" />
                          <span className="text-white font-bold uppercase text-xs">{target.url}</span>
                          <span className="bg-[#22c55e]/10 text-[#22c55e] text-[9px] px-2 py-0.5 rounded border border-[#22c55e]/30">ACTIVE</span>
                        </div>
                        <div className="text-[#a1a1aa] text-[10px] flex items-center space-x-3">
                          <span>Schedule: {target.scheduleString || `Every ${target.frequencyDays} ${target.frequencyDays === 1 ? 'day' : 'days'}`}</span>
                          <span>&bull;</span>
                          <span>Next scan: {new Date(target.nextScanAt).toLocaleDateString()}</span>
                        </div>
                      </div>
                      <button
                        onClick={() => handleDeleteMonitor(target.id)}
                        className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:bg-[#f87171] hover:text-white text-[#f87171] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer w-fit"
                      >
                        Remove
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {activeTab === 'exclusions' && (
            <div className="space-y-6 animate-fade-in">
              <div className="bg-amber-500/5 border border-amber-500/10 rounded p-4 flex items-start space-x-3.5">
                <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-white font-mono text-xs uppercase font-bold">Rule-based Exclusion Ledger & False Positive Controls</h4>
                  <p className="text-[11px] font-mono text-[#a1a1aa] leading-relaxed">
                    Security managers can override individual vulnerabilities by declaring them "False Positives" or "Exempt Risks". When an exclusion rule is defined, future testing sequences on that URL automatically filter out matching threats, recalculating the Posture Score to reflect verified, accepted, or compensated risks.
                  </p>
                </div>
              </div>

              {suppressRules.length === 0 ? (
                <div className="text-center py-16 bg-black rounded border border-dashed border-[#27272a] flex flex-col items-center">
                  <ShieldCheck className="w-10 h-10 text-zinc-600 mb-3" />
                  <span className="text-xs text-white uppercase font-bold font-mono">No Active Exclusion Rules</span>
                  <p className="text-[11px] text-[#52525b] mt-1.5 font-mono max-w-sm">
                    All vulnerability findings are currently factored into core security scores. To suppress an issue, open its security report details and trigger "Mark False Positive".
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {suppressRules.map((rule) => (
                    <div key={rule.id} className="bg-black/80 border border-[#27272a]/95 rounded p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:border-zinc-750 transition-colors">
                      <div className="space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[9px] font-mono uppercase bg-zinc-900 border border-zinc-700/60 text-zinc-400 px-2 py-0.5 rounded">
                            Target Host Exclusion
                          </span>
                          <span className="text-[11px] text-[#22c55e] font-mono font-bold select-all">{rule.targetUrl}</span>
                        </div>
                        <h5 className="text-white text-xs font-mono font-bold leading-snug">{rule.findingTitle}</h5>
                        <p className="text-zinc-500 text-[11px] font-mono leading-relaxed">
                          <strong className="text-zinc-400">Security Justification:</strong> {rule.reason || 'No justification provided'}
                        </p>
                        <span className="text-[9px] text-[#52525b] font-mono block">
                          Established: {new Date(rule.createdAt).toLocaleString()} • Exclusion ID: {rule.id}
                        </span>
                      </div>
                      
                      <button
                        onClick={async () => {
                          setIsDeletingRule(rule.id);
                          try {
                            const delRes = await fetch(`/api/suppressions/${rule.id}`, {
                              method: 'DELETE'
                            });
                            if (delRes.ok) {
                              fetchSuppressRules();
                            }
                          } catch (err) {
                            console.error('Failed to revoke suppression:', err);
                          } finally {
                            setIsDeletingRule(null);
                          }
                        }}
                        disabled={isDeletingRule === rule.id}
                        className="self-start sm:self-center px-3 py-1.5 bg-red-950/20 hover:bg-red-950/50 border border-red-900/40 text-[#f87171] hover:text-red-300 rounded text-[10px] font-mono uppercase tracking-wider transition-colors shrink-0 cursor-pointer"
                      >
                        {isDeletingRule === rule.id ? 'Revoking...' : 'Revoke Exclusion'}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'billing' && (
            <div className="space-y-4">
              {transactions.length === 0 ? (
                <div className="text-center py-12 bg-black rounded border border-dashed border-[#27272a]">
                  <span className="text-xs text-[#52525b] font-mono block mb-2">No billing transactions recorded yet</span>
                  <p className="text-[11px] text-[#52525b] max-w-sm mx-auto font-mono">Transactions appear here when credits are added or debited during evaluation scans.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-[#27272a] text-[#52525b] font-mono text-[10px] uppercase tracking-wider pb-3">
                        <th className="py-3 px-4">Transaction ID</th>
                        <th className="py-3 px-4">Action Type</th>
                        <th className="py-3 px-4">Amount</th>
                        <th className="py-3 px-4">Reference Reference ID</th>
                        <th className="py-3 px-4 text-right font-mono">Timestamp</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#27272a]/20 text-xs font-mono">
                      {transactions.map((tx) => {
                        const isCreditAdded = tx.amount > 0;
                        return (
                          <tr key={tx.id} className="hover:bg-black/60 transition-colors">
                            <td className="py-3.5 px-4 font-mono font-bold text-white uppercase">{tx.id || "tx_system"}</td>
                            <td className="py-3.5 px-4">
                              {tx.type === 'purchase' ? (
                                <span className="bg-[#22c55e]/10 border border-[#22c55e]/25 text-[#22c55e] px-2 py-0.5 rounded font-mono text-[9px] uppercase">
                                  Purchased Credits
                                </span>
                              ) : (
                                <span className="bg-amber-950/40 border border-[#27272a] text-amber-400 px-2 py-0.5 rounded font-mono text-[9px] uppercase">
                                  Audit Cost Deducted
                                </span>
                              )}
                            </td>
                            <td className={`py-3.5 px-4 font-bold ${isCreditAdded ? 'text-[#22c55e]' : 'text-rose-400'}`}>
                              {isCreditAdded ? `+${tx.amount}` : tx.amount} credits
                            </td>
                            <td className="py-3.5 px-4 text-[#a1a1aa] max-w-xs truncate font-mono text-[10px]">
                              {tx.stripeSessionId || tx.scanId || 'System Provision'}
                            </td>
                            <td className="py-3.5 px-4 text-right text-[#52525b] font-mono text-[11px]">
                              {new Date(tx.createdAt).toLocaleString()}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab === 'api-docs' && (
            <div className="space-y-6 animate-fade-in text-xs font-mono">
              <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
                <Code className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="text-white text-xs uppercase font-bold">API & MCP Integration Documentation</h4>
                  <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
                    Integrate Seclayer's automated penetration testing capabilities into your CI/CD pipelines, security orchestration tools, or LLM-based autonomous agents using our Model Context Protocol (MCP) standard endpoints.
                  </p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="bg-black border border-[#27272a] rounded overflow-hidden">
                  <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="bg-[#22c55e]/10 text-[#22c55e] px-2 py-0.5 rounded font-mono text-[9px] uppercase font-bold tracking-wider">POST</span>
                      <h3 className="text-white font-mono text-xs font-bold sm:text-sm">/api/mcp/scan</h3>
                    </div>
                    <span className="text-[10px] text-[#52525b] uppercase tracking-wider bg-[#18181b] px-2 py-1 rounded border border-[#27272a]">1 Credit / Request</span>
                  </div>
                  
                  <div className="p-5 space-y-6">
                    <p className="text-[#a1a1aa] text-[11px] font-sans">
                      Initiate an active security diagnostic sweep and exploit chain analysis against a target URI. Synchronously returns calculated posture scores, unified threat logic, and explicit schema findings formatted for agent context passing.
                    </p>

                    <div>
                      <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Request Parameter Schema (JSON)</h4>
                      <div className="relative group">
                        <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
{`{
  "url": "https://example.com",     // (Required) The fully qualified domain name to scan
  "apiKey": "sec_b7x9...",          // (Required) Your provisioned MCP API key
  "authHeader": "Bearer ey..."      // (Optional) Authorization header to pass to the target
}`}
                        </pre>
                        <button 
                          className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                          onClick={() => {
                            navigator.clipboard.writeText(`{\n  "url": "https://example.com",     // (Required) The fully qualified domain name to scan\n  "apiKey": "sec_b7x9...",          // (Required) Your provisioned MCP API key\n  "authHeader": "Bearer ey..."      // (Optional) Authorization header to pass to the target\n}`);
                            setToastMsg('Schema snippet copied to clipboard');
                            setShowToast(true);
                            setTimeout(() => setShowToast(false), 3000);
                          }}
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Interactive cURL Snippet</h4>
                      <div className="relative group">
                        <pre className="bg-[#18181b] border border-[#27272a] p-4 rounded text-[#22c55e] text-[10px] overflow-x-auto">
                          <code>
{`curl -X POST ${window.location.origin}/api/mcp/scan \\
  -H "Content-Type: application/json" \\
  -d '{
    "url": "https://example.com", 
    "apiKey": "YOUR_API_KEY"
  }'`}
                          </code>
                        </pre>
                        <button 
                          className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                          onClick={() => {
                            navigator.clipboard.writeText(`curl -X POST ${window.location.origin}/api/mcp/scan -H "Content-Type: application/json" -d '{\n  "url": "https://example.com", \n  "apiKey": "YOUR_API_KEY"\n}'`);
                            setToastMsg('cURL snippet copied to clipboard');
                            setShowToast(true);
                            setTimeout(() => setShowToast(false), 3000);
                          }}
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-white mb-2 uppercase tracking-tight text-[10px] font-bold">Response Data Envelope (200 OK)</h4>
                      <div className="relative group">
                        <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
{`{
  "success": true,
  "targetUrl": "https://api.example.com",
  "postureScore": 85,
  "vulnerabilityLevel": "medium",
  "analysisSummary": "Seclayer automated assessment identified 1 or more...",
  "securityFindings": [
    {
      "testName": "GraphQL Schema Introspection Exposed",
      "endpoint": "/graphql",
      "severity": "high",
      "description": "An active API endpoint probe discovered...",
      "fix": "Disable introspection blocks in the production backend..."
    }
  ],
  "creditsRemaining": 90
}`}
                        </pre>
                        <button 
                          className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                          onClick={() => {
                            navigator.clipboard.writeText(`{\n  "success": true,\n  "targetUrl": "https://api.example.com",\n  "postureScore": 85,\n  "vulnerabilityLevel": "medium",\n  "analysisSummary": "Seclayer automated assessment identified 1 or more...",\n  "securityFindings": [\n    {\n      "testName": "GraphQL Schema Introspection Exposed",\n      "endpoint": "/graphql",\n      "severity": "high",\n      "description": "An active API endpoint probe discovered...",\n      "fix": "Disable introspection blocks in the production backend..."\n    }\n  ],\n  "creditsRemaining": 90\n}`);
                            setToastMsg('Response envelope snippet copied to clipboard');
                            setShowToast(true);
                            setTimeout(() => setShowToast(false), 3000);
                          }}
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Node JS snippets etc. - Keep it minimal */}
                <div className="bg-black border border-[#27272a] rounded overflow-hidden">
                  <div className="bg-[#0c0c0e] px-4 py-3 border-b border-[#27272a] flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                       <FileText className="w-3.5 h-3.5 text-[#52525b]" />
                       <h3 className="text-white font-mono text-xs font-bold sm:text-sm">Example: TypeScript / Fetch</h3>
                    </div>
                  </div>
                  <div className="p-5">
                    <div className="relative group">
                      <pre className="bg-[#09090b] border border-[#27272a]/40 p-4 rounded text-[#a1a1aa] text-[10px] overflow-x-auto">
                          <code>
{`async function runSeclayerScan(target: string, key: string) {
  const response = await fetch('${window.location.origin}/api/mcp/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: target, apiKey: key })
  });

  if (!response.ok) throw new Error('Scan failed');
  
  const report = await response.json();
  console.log(\`Score: \${report.postureScore}/100\`);
  return report.securityFindings;
}`}
                          </code>
                      </pre>
                      <button 
                        className="absolute top-2 right-2 bg-[#27272a]/80 hover:bg-[#3f3f46] text-[#a1a1aa] hover:text-white p-1.5 rounded transition-all opacity-0 group-hover:opacity-100 cursor-pointer"
                        onClick={() => {
                          navigator.clipboard.writeText(`async function runSeclayerScan(target: string, key: string) {\n  const response = await fetch('${window.location.origin}/api/mcp/scan', {\n    method: 'POST',\n    headers: { 'Content-Type': 'application/json' },\n    body: JSON.stringify({ url: target, apiKey: key })\n  });\n\n  if (!response.ok) throw new Error('Scan failed');\n  \n  const report = await response.json();\n  console.log(\`Score: \${report.postureScore}/100\`);\n  return report.securityFindings;\n}`);
                          setToastMsg('TypeScript snippet copied to clipboard');
                          setShowToast(true);
                          setTimeout(() => setShowToast(false), 3000);
                        }}
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
                
              </div>
            </div>
          )}

        </div>

      </div>

      {/* Floating Status Toast Notifier */}
      {showToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0c0c0e] border border-[#22c55e] text-[#22c55e] px-4 py-3 rounded shadow-2xl shadow-green-950/20 font-mono text-xs flex items-center space-x-2 animate-bounce">
          <CheckCircle className="w-4 h-4 text-[#22c55e] shrink-0 animate-pulse" />
          <span>{toastMsg}</span>
        </div>
      )}

    </div>
  );
}
