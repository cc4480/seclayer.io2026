import { useState, useEffect, type FormEvent } from 'react';
import { CheckCircle } from 'lucide-react';
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
  onInitiateScan: (url: string, authHeader?: string, bolaIdentities?: any, activeProbes?: boolean) => void;
  onGenerateKey: () => void;
  onRevokeKey: (keyId: string) => void;
  onPurchaseCredits: (packName: 'single' | 'pack5' | 'pack20') => void;
  onViewReport: (scanId: string) => void;
  isPerformingAction: boolean;
}

export default function Dashboard({
  user, scans, apiKeys, credits, transactions, justGeneratedKey, onDismissGeneratedKey,
  onInitiateScan, onGenerateKey, onRevokeKey, onPurchaseCredits, onViewReport, isPerformingAction,
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
  const [prevCredits, setPrevCredits] = useState(credits);
  const [showToast, setShowToast] = useState(false);
  const [toastMsg, setToastMsg] = useState('');

  const dv = useDomainVerification(scanUrl, user.id);
  const m = useMonitoring(user, scans);

  const notify = (msg: string) => {
    setToastMsg(msg);
    setShowToast(true);
    setTimeout(() => setShowToast(false), 3000);
  };

  // Toast notifier for balance changes.
  useEffect(() => {
    if (credits > prevCredits) {
      setToastMsg(`Sandbox Top-up Successful! Added ${credits - prevCredits} scan credits.`);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
    }
    setPrevCredits(credits);
  }, [credits, prevCredits]);

  // Launch a scan in the chosen mode. `active` = red-team (real exploit probes),
  // which first requires an authorization attestation for the target domain.
  // `active === false` = passive recon only, allowed on any URL with no attestation.
  const launchScan = async (active: boolean) => {
    setErrorText('');
    const urlStr = scanUrl.trim();
    if (!urlStr) return;
    if (credits < 1) {
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

    // Red-team requires an authorization attestation for this domain (once per
    // domain — it then stays unlocked). Passive needs none.
    if (active) {
      const authorized = await dv.attestCurrentDomain();
      if (!authorized) {
        if (!dv.verifyError) setErrorText(`Active red-team needs you to confirm authorization for ${dv.currentDomain || 'this domain'}.`);
        return;
      }
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
        <DashboardHeader email={user.email} credits={credits} />

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
              launchScan={launchScan} handleScanSubmit={handleScanSubmit} dv={dv}
            />
            <CreditPacks buyPack={buyPack} setBuyPack={setBuyPack} isBuying={isBuying} isPerformingAction={isPerformingAction} handleBuyCredits={handleBuyCredits} />
          </div>

          <div className="lg:col-span-5 space-y-8">
            <ApiKeysPanel
              apiKeys={apiKeys} justGeneratedKey={justGeneratedKey} onDismissGeneratedKey={onDismissGeneratedKey}
              onGenerateKey={onGenerateKey} onRevokeKey={onRevokeKey} copiedKeyId={copiedKeyId} handleCopyKey={handleCopyKey}
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
          {activeTab === 'monitoring' && <MonitoringTab m={m} />}
          {activeTab === 'exclusions' && <ExclusionsTab suppressRules={m.suppressRules} fetchSuppressRules={m.fetchSuppressRules} />}
          {activeTab === 'billing' && <BillingTab transactions={transactions} />}
          {activeTab === 'api-docs' && <ApiDocsTab notify={notify} />}
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
