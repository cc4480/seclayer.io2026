import { useState, useEffect, useRef, type FormEvent } from 'react';
import { CheckCircle, Info } from 'lucide-react';
import { Scan, ApiKey, User } from '../types.js';
import DashboardHeader from '../components/dashboard/DashboardHeader.js';
import { useDomainVerification } from '../hooks/useDomainVerification.js';
import { useMonitoring } from '../hooks/useMonitoring.js';
import ScanLauncher from '../components/dashboard/ScanLauncher.js';
import CreditPacks from '../components/dashboard/CreditPacks.js';
import DeepSeekKeyCard from '../components/dashboard/DeepSeekKeyCard.js';
import ApiKeysPanel from '../components/dashboard/ApiKeysPanel.js';
import ScansTab from '../components/dashboard/ScansTab.js';
import MonitoringTab from '../components/dashboard/MonitoringTab.js';
import ExclusionsTab from '../components/dashboard/ExclusionsTab.js';
import BillingTab from '../components/dashboard/BillingTab.js';
import ApiDocsTab from '../components/dashboard/ApiDocsTab.js';
import { copyToClipboard } from '../lib/clipboard.js';

// Persisted scan-launcher config so the advanced fields (auth header + the two
// BOLA identities) come pre-filled and never need re-entering — set them once and
// they stick across scans and reloads. Defaults match the bundled vulnerable test
// app so a BOLA run works out of the box; edit them for a real target and the
// edits persist.
const LS = {
  read<T>(key: string, fallback: T): T {
    try {
      const v = typeof localStorage !== 'undefined' ? localStorage.getItem(key) : null;
      return v != null ? (JSON.parse(v) as T) : fallback;
    } catch { return fallback; }
  },
  write(key: string, value: unknown) {
    try { if (typeof localStorage !== 'undefined') localStorage.setItem(key, JSON.stringify(value)); } catch { /* ignore */ }
  },
};
const DEFAULT_BOLA_A = { authHeader: 'Bearer tok-alice', ownResource: '/api/orders/1001', ownMarker: 'alice@vulnshop.test' };
const DEFAULT_BOLA_B = { authHeader: 'Bearer tok-bob', ownResource: '/api/orders/1002', ownMarker: 'bob@vulnshop.test' };

// Per-target memory: each scanned host remembers its own auth header + BOLA
// identities, keyed by hostname, so switching between your apps auto-fills that
// app's values. Layered on top of the global "last used" defaults above.
type TargetConfig = { authHeader?: string; bolaA?: typeof DEFAULT_BOLA_A; bolaB?: typeof DEFAULT_BOLA_B };
function readTargetConfig(host: string): TargetConfig | null {
  if (!host) return null;
  const all = LS.read<Record<string, TargetConfig>>('sl_targetConfigs', {});
  return all[host] || null;
}
function writeTargetConfig(host: string, cfg: TargetConfig) {
  if (!host) return;
  const all = LS.read<Record<string, TargetConfig>>('sl_targetConfigs', {});
  all[host] = cfg;
  LS.write('sl_targetConfigs', all);
}

interface DashboardProps {
  user: User;
  scans: Scan[];
  apiKeys: ApiKey[];
  credits: number;
  transactions: any[];
  justGeneratedKey: { id: string; rawKey: string } | null;
  onDismissGeneratedKey: () => void;
  refreshData: () => void;
  freeMode: boolean;
  devSkipDomainVerification: boolean;
  deepseekKeySet: boolean;
  deepseekKeyPreview: string | null;
  saveDeepseekKey: (key: string) => Promise<{ ok: boolean; message?: string }>;
  onInitiateScan: (url: string, authHeader?: string, bolaIdentities?: any, activeProbes?: boolean, aggressiveProbes?: boolean) => void;
  onGenerateKey: () => void;
  onRevokeKey: (keyId: string) => void;
  onPurchaseCredits: (packName: 'single' | 'pack5' | 'pack20') => void;
  onViewReport: (scanId: string) => void;
  isPerformingAction: boolean;
  checkoutNotice: 'success' | 'canceled' | null;
  onDismissCheckoutNotice: () => void;
}

export default function Dashboard({
  user, scans, apiKeys, credits, transactions, justGeneratedKey, onDismissGeneratedKey, refreshData, freeMode,
  devSkipDomainVerification, deepseekKeySet, deepseekKeyPreview, saveDeepseekKey,
  onInitiateScan, onGenerateKey, onRevokeKey, onPurchaseCredits, onViewReport, isPerformingAction,
  checkoutNotice, onDismissCheckoutNotice,
}: DashboardProps) {
  const [scanUrl, setScanUrl] = useState('');
  // Advanced config is pre-filled from localStorage (or sensible defaults) so
  // nothing has to be entered by hand, and any edits are remembered.
  const [authHeader, setAuthHeader] = useState(() => LS.read('sl_authHeader', ''));
  const [showAdvanced, setShowAdvanced] = useState(false);
  // Two-identity BOLA/IDOR cross-tenant test (docs/confirmed-evidence-spec.md §3.1a).
  const [bolaEnabled, setBolaEnabled] = useState(() => LS.read('sl_bolaEnabled', true));
  // Aggressive tier: more invasive (but non-destructive) probes — SSTI, LFI,
  // XXE, CORS, CRLF, open redirect, NoSQL. ON by default so the Active Red-Team
  // Scan is a single-click full sweep; uncheck it in Advanced Options for a
  // red-team-only run. Server-side it still only runs on a verified/owned target.
  const [aggressiveEnabled, setAggressiveEnabled] = useState(() => LS.read('sl_aggressiveEnabled', true));
  const [bolaA, setBolaA] = useState(() => LS.read('sl_bolaA', DEFAULT_BOLA_A));
  const [bolaB, setBolaB] = useState(() => LS.read('sl_bolaB', DEFAULT_BOLA_B));

  // Persist advanced config so the fields stay filled across scans and reloads.
  useEffect(() => { LS.write('sl_authHeader', authHeader); }, [authHeader]);
  useEffect(() => { LS.write('sl_bolaEnabled', bolaEnabled); }, [bolaEnabled]);
  useEffect(() => { LS.write('sl_aggressiveEnabled', aggressiveEnabled); }, [aggressiveEnabled]);
  useEffect(() => { LS.write('sl_bolaA', bolaA); }, [bolaA]);
  useEffect(() => { LS.write('sl_bolaB', bolaB); }, [bolaB]);
  const [buyPack, setBuyPack] = useState<'single' | 'pack5' | 'pack20'>('pack5');
  const [isBuying, setIsBuying] = useState(false);
  const [errorText, setErrorText] = useState('');

  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'scans' | 'billing' | 'exclusions' | 'monitoring' | 'api-docs'>('scans');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState('');
  const [toastTone, setToastTone] = useState<'success' | 'neutral'>('success');

  const dv = useDomainVerification(scanUrl, user.id);
  const m = useMonitoring(user, scans, refreshData);

  // --- Per-target memory ---
  // The current target's hostname (''/none until a URL is entered). Each host
  // remembers its own auth header + BOLA identities so switching between your
  // apps auto-fills that app's values; unknown hosts keep the last-used values.
  const currentHost = dv.currentDomain;
  const hostRef = useRef(currentHost);
  const loadedHostRef = useRef('');
  useEffect(() => { hostRef.current = currentHost; }, [currentHost]);
  // When the target host changes: load that host's saved config, or — for a host
  // we've never configured — reset to a clean slate so a PREVIOUS app's auth
  // token or identities never carry over to a different app (auth is per-app and
  // secret; BOLA falls back to the editable demo defaults).
  useEffect(() => {
    if (!currentHost || currentHost === loadedHostRef.current) return;
    loadedHostRef.current = currentHost;
    const cfg = readTargetConfig(currentHost);
    setAuthHeader(cfg && typeof cfg.authHeader === 'string' ? cfg.authHeader : '');
    setBolaA(cfg?.bolaA ?? DEFAULT_BOLA_A);
    setBolaB(cfg?.bolaB ?? DEFAULT_BOLA_B);
  }, [currentHost]);
  // Save the current fields under the current host whenever they change (via a
  // ref so a host switch alone never writes the previous host's values).
  useEffect(() => {
    if (hostRef.current) writeTargetConfig(hostRef.current, { authHeader, bolaA, bolaB });
  }, [authHeader, bolaA, bolaB]);

  const notify = (msg: string, tone: 'success' | 'neutral' = 'success') => {
    setToastMsg(msg);
    setToastTone(tone);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 4000);
  };

  // Show the real Stripe Checkout outcome once, then clear it so a later
  // remount/refresh doesn't re-show a stale notice. A credits-before-vs-after
  // comparison doesn't work here — Checkout is a full-page redirect away and
  // back, so this component (and any "previous credits" state) mounts fresh
  // with credits already at their post-purchase value.
  useEffect(() => {
    if (checkoutNotice === 'success') {
      notify('Payment successful — credits have been added to your balance.', 'success');
      onDismissCheckoutNotice();
    } else if (checkoutNotice === 'canceled') {
      notify('Checkout was canceled — no charge was made.', 'neutral');
      onDismissCheckoutNotice();
    }
  }, [checkoutNotice]);

  // Launch a scan in the chosen mode. `active` = red-team (real exploit probes),
  // which requires the target domain to already be verified via DNS TXT record
  // or well-known file. `active === false` = passive recon only, allowed on any URL.
  const launchScan = async (active: boolean) => {
    setErrorText('');
    const urlStr = scanUrl.trim();
    if (!urlStr) return;
    // In free mode scans cost nothing, so the credit gate is skipped.
    if (!freeMode && credits < 1) {
      setErrorText('Insufficient balances available. Please top-up credits to run a scan.');
      return;
    }

    let bolaIdentities: any = undefined;
    if (active && bolaEnabled) {
      const a = { label: 'tenant-A', authHeader: bolaA.authHeader.trim(), ownResource: bolaA.ownResource.trim(), ownMarker: bolaA.ownMarker.trim() || undefined };
      const b = { label: 'tenant-B', authHeader: bolaB.authHeader.trim(), ownResource: bolaB.ownResource.trim(), ownMarker: bolaB.ownMarker.trim() || undefined };
      if (!a.authHeader || !a.ownResource || !b.authHeader || !b.ownResource) {
        setErrorText('The BOLA test needs an auth credential and an owned resource path for BOTH identities.');
        return;
      }
      bolaIdentities = [a, b];
    }

    // Red-team requires this domain to already carry real DNS/file proof of
    // ownership. Guide the user to that flow instead of launching (the server
    // enforces this regardless; this just avoids a scan that silently downgrades
    // to passive-only). The dev-only DEV_SKIP_DOMAIN_VERIFICATION flag lifts this
    // gate for local probe testing (server-side flag; always off in production).
    if (active && !dv.currentDomainVerified && !devSkipDomainVerification) {
      setErrorText(`Active red-team needs ${dv.currentDomain || 'this domain'} verified via DNS TXT record or well-known file first — see above.`);
      void dv.handleStartVerification();
      return;
    }

    onInitiateScan(urlStr, authHeader.trim() || undefined, bolaIdentities, active, active && aggressiveEnabled);
  };

  // Enter key / form submit → the primary action (active red-team).
  const handleScanSubmit = (e: FormEvent) => {
    e.preventDefault();
    void launchScan(true);
  };

  const handleBuyCredits = async () => {
    setIsBuying(true);
    // Mimic the full stripe checkout redirect loop.
    setTimeout(() => {
      onPurchaseCredits(buyPack);
      setIsBuying(false);
    }, 1200);
  };

  const handleCopyKey = async (keyText: string, keyId: string) => {
    if (!(await copyToClipboard(keyText))) return;
    setCopiedKeyId(keyId);
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  const tabButton = (tab: typeof activeTab, label: string) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={`px-4 py-2 font-mono text-xs uppercase tracking-widest border-b-2 transition-all pb-3 cursor-pointer ${
        activeTab === tab ? 'border-[#22c55e] text-white font-bold' : 'border-transparent text-[#52525b] hover:text-[#a1a1aa]'
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] py-12 px-6">
      <div className="max-w-7xl mx-auto space-y-10">

        {/* Row 1: Header / Status banner */}
        <DashboardHeader email={user.email} credits={credits} freeMode={freeMode} />

        {/* Bento Grid Layer */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-7 space-y-8">
            <ScanLauncher
              scanUrl={scanUrl} setScanUrl={setScanUrl}
              authHeader={authHeader} setAuthHeader={setAuthHeader}
              showAdvanced={showAdvanced} setShowAdvanced={setShowAdvanced}
              bolaEnabled={bolaEnabled} setBolaEnabled={setBolaEnabled}
              bolaA={bolaA} setBolaA={setBolaA} bolaB={bolaB} setBolaB={setBolaB}
              aggressiveEnabled={aggressiveEnabled} setAggressiveEnabled={setAggressiveEnabled}
              errorText={errorText} isPerformingAction={isPerformingAction}
              launchScan={launchScan} handleScanSubmit={handleScanSubmit} dv={dv} freeMode={freeMode}
              devSkipDomainVerification={devSkipDomainVerification}
            />
            {freeMode ? (
              <DeepSeekKeyCard deepseekKeySet={deepseekKeySet} deepseekKeyPreview={deepseekKeyPreview} saveDeepseekKey={saveDeepseekKey} />
            ) : (
              <CreditPacks buyPack={buyPack} setBuyPack={setBuyPack} isBuying={isBuying} isPerformingAction={isPerformingAction} handleBuyCredits={handleBuyCredits} />
            )}
          </div>

          <div className="lg:col-span-5 space-y-8">
            <ApiKeysPanel
              apiKeys={apiKeys} justGeneratedKey={justGeneratedKey} onDismissGeneratedKey={onDismissGeneratedKey}
              onGenerateKey={onGenerateKey} onRevokeKey={onRevokeKey} copiedKeyId={copiedKeyId} handleCopyKey={handleCopyKey}
              freeMode={freeMode}
            />
          </div>
        </div>

        {/* Row 3: tabbed history / monitoring / exclusions / billing / docs */}
        <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-6 relative">
          <div className="flex flex-wrap gap-1.5 border-b border-[#27272a]/80 mb-6">
            {tabButton('scans', `[+] Vulnerability Scans History (${scans.length})`)}
            {tabButton('monitoring', '[+] Continuous Monitoring')}
            {tabButton('exclusions', `[+] Risk Exclusions & FP Rules (${m.suppressRules.length})`)}
            {tabButton('billing', `[+] Billing & Receipts Log (${transactions.length})`)}
            {tabButton('api-docs', '[+] API Documentation')}
          </div>

          {activeTab === 'scans' && (
            <ScansTab
              scans={scans}
              searchQuery={searchQuery} setSearchQuery={setSearchQuery}
              filterStatus={filterStatus} setFilterStatus={setFilterStatus}
              filterSeverity={filterSeverity} setFilterSeverity={setFilterSeverity}
              onViewReport={onViewReport}
            />
          )}
          {activeTab === 'monitoring' && <MonitoringTab m={m} onViewReport={onViewReport} />}
          {activeTab === 'exclusions' && <ExclusionsTab suppressRules={m.suppressRules} fetchSuppressRules={m.fetchSuppressRules} />}
          {activeTab === 'billing' && <BillingTab transactions={transactions} />}
          {activeTab === 'api-docs' && <ApiDocsTab notify={notify} />}
        </div>

      </div>

      {/* Floating Status Toast Notifier */}
      {showToast && (
        <div className={`fixed bottom-6 right-6 z-50 bg-[#0c0c0e] px-4 py-3 rounded shadow-2xl font-mono text-xs flex items-center space-x-2 animate-bounce ${
          toastTone === 'success' ? 'border border-[#22c55e] text-[#22c55e] shadow-green-950/20' : 'border border-[#3f3f46] text-[#a1a1aa] shadow-black/20'
        }`}>
          {toastTone === 'success' ? (
            <CheckCircle className="w-4 h-4 text-[#22c55e] shrink-0 animate-pulse" />
          ) : (
            <Info className="w-4 h-4 text-[#a1a1aa] shrink-0" />
          )}
          <span>{toastMsg}</span>
        </div>
      )}
    </div>
  );
}
