import { useState, useEffect, type FormEvent } from 'react';
import { CheckCircle, Info } from 'lucide-react';
import { Scan, ApiKey, User } from '../types.js';
import DashboardHeader from '../components/dashboard/DashboardHeader.js';
import { useDomainVerification } from '../hooks/useDomainVerification.js';
import { useMonitoring } from '../hooks/useMonitoring.js';
import ScanLauncher from '../components/dashboard/ScanLauncher.js';
import CreditPacks from '../components/dashboard/CreditPacks.js';
import ApiKeysPanel from '../components/dashboard/ApiKeysPanel.js';
import ScansTab from '../components/dashboard/ScansTab.js';
import MonitoringTab from '../components/dashboard/MonitoringTab.js';
import ExclusionsTab from '../components/dashboard/ExclusionsTab.js';
import BillingTab from '../components/dashboard/BillingTab.js';
import ApiDocsTab from '../components/dashboard/ApiDocsTab.js';

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
  onInitiateScan: (url: string, authHeader?: string, bolaIdentities?: any, activeProbes?: boolean) => void;
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
  onInitiateScan, onGenerateKey, onRevokeKey, onPurchaseCredits, onViewReport, isPerformingAction,
  checkoutNotice, onDismissCheckoutNotice,
}: DashboardProps) {
  const [scanUrl, setScanUrl] = useState('');
  const [authHeader, setAuthHeader] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  // Two-identity BOLA/IDOR cross-tenant test (docs/confirmed-evidence-spec.md §3.1a).
  const [bolaEnabled, setBolaEnabled] = useState(false);
  const emptyIdentity = { authHeader: '', ownResource: '', ownMarker: '' };
  const [bolaA, setBolaA] = useState({ ...emptyIdentity });
  const [bolaB, setBolaB] = useState({ ...emptyIdentity });
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
    // to passive-only).
    if (active && !dv.currentDomainVerified) {
      setErrorText(`Active red-team needs ${dv.currentDomain || 'this domain'} verified via DNS TXT record or well-known file first — see above.`);
      void dv.handleStartVerification();
      return;
    }

    onInitiateScan(urlStr, authHeader.trim() || undefined, bolaIdentities, active);
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

  const handleCopyKey = (keyText: string, keyId: string) => {
    navigator.clipboard.writeText(keyText);
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
              errorText={errorText} isPerformingAction={isPerformingAction}
              launchScan={launchScan} handleScanSubmit={handleScanSubmit} dv={dv} freeMode={freeMode}
            />
            {!freeMode && (
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
