import { useEffect } from 'react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import PublicReport from './pages/PublicReport.js';
import DocsPage from './pages/DocsPage.js';
import LoginModal from './components/LoginModal.js';
import { useSeclayer } from './hooks/useSeclayer.js';
import { sameTarget } from './lib/targetUrl.js';

// A public shared-report deep link: /r/<token>. Detected before any auth flow so
// a logged-out visitor sees the read-only report, not the login/dashboard app.
function shareTokenFromPath(): string | null {
  const m = /^\/r\/([A-Za-z0-9_-]+)\/?$/.exec(window.location.pathname);
  return m ? m[1] : null;
}

export default function App() {
  // Early, hook-free branch: a share link renders the standalone public view and
  // never mounts the authenticated app (useSeclayer, nav, dashboard).
  const shareToken = shareTokenFromPath();
  if (shareToken) return <PublicReport token={shareToken} />;
  return <AuthedApp />;
}

function AuthedApp() {
  const {
    user, scans, apiKeys, credits, transactions, freeMode, devSkipDomainVerification, nmapAvailable, justGeneratedKey, setJustGeneratedKey,
    deepseekKeySet, deepseekKeyPreview, saveDeepseekKey,
    currentView, setCurrentView, selectedScanId, setSelectedScanId, showLogin, setShowLogin,
    isPerformingAction, activeScan, checkoutNotice, setCheckoutNotice,
    loadUserContext, handleNavigate, handleStartTrial, onInitiateScan, cancelScan,
    onGenerateKey, onRevokeKey, onPurchaseCredits, handleLogout,
  } = useSeclayer();

  // Per-route <title>, description and canonical for the two indexable views
  // (/, /docs). Client-side is enough for SEO here: Google renders JS, and the
  // served index.html already carries strong home-page defaults for the rest.
  useEffect(() => {
    const meta = currentView === 'docs'
      ? {
          path: '/docs',
          title: 'Documentation — how each Seclayer scan works | Seclayer',
          desc: 'How Seclayer scans: the seven AppSec pillars, active red-team probes, API-first (OpenAPI/Swagger) testing, network reconnaissance, and the PROVEN vs DETECTED evidence model.',
        }
      : {
          path: '/',
          title: 'Seclayer — Black-Box Penetration Testing SaaS & MCP Server',
          desc: 'Point Seclayer at a public URL and get a real black-box penetration test: signature-confirmed findings across seven AppSec categories, a plain-English AI report, and a ready-to-paste fix prompt for your coding agent. Pay per scan, zero setup, zero subscription.',
        };
    document.title = meta.title;
    document.querySelector('meta[name="description"]')?.setAttribute('content', meta.desc);
    const canonical = 'https://seclayer.io' + meta.path;
    document.querySelector('link[rel="canonical"]')?.setAttribute('href', canonical);
    document.querySelector('meta[property="og:url"]')?.setAttribute('content', canonical);
  }, [currentView]);

  return (
    <div className="bg-zinc-950 min-h-screen flex flex-col font-sans">

      {/* Universal navigation bar */}
      <Navbar
        currentView={currentView}
        onNavigate={handleNavigate}
        userEmail={user?.email || ''}
        credits={credits}
        freeMode={freeMode}
        onLogout={handleLogout}
        onLoginClick={() => setShowLogin(true)}
      />

      {/* Primary Page views router mapping */}
      <main className="flex-1">
        {currentView === 'landing' && (
          <Landing
            onStartTrial={handleStartTrial}
            onNavigate={handleNavigate}
            onSelectPack={(pack) => {
              if (!user) {
                setShowLogin(true);
                return;
              }
              onPurchaseCredits(pack);
              setCurrentView('dashboard');
            }}
          />
        )}

        {currentView === 'docs' && <DocsPage onNavigate={handleNavigate} />}

        {currentView === 'dashboard' && user && (
          <Dashboard
            user={user}
            scans={scans}
            apiKeys={apiKeys}
            credits={credits}
            transactions={transactions}
            justGeneratedKey={justGeneratedKey}
            onDismissGeneratedKey={() => setJustGeneratedKey(null)}
            refreshData={loadUserContext}
            freeMode={freeMode}
            devSkipDomainVerification={devSkipDomainVerification}
            nmapAvailable={nmapAvailable}
            deepseekKeySet={deepseekKeySet}
            deepseekKeyPreview={deepseekKeyPreview}
            saveDeepseekKey={saveDeepseekKey}
            onInitiateScan={onInitiateScan}
            onGenerateKey={onGenerateKey}
            onRevokeKey={onRevokeKey}
            onPurchaseCredits={onPurchaseCredits}
            onViewReport={(scanId) => {
              const checkScan = scans.find(s => s.id === scanId);
              if (checkScan && (checkScan.status === 'queued' || checkScan.status === 'scanning' || checkScan.status === 'analyzing')) {
                setSelectedScanId(scanId);
                setCurrentView('progress');
              } else {
                handleNavigate('report', scanId);
              }
            }}
            isPerformingAction={isPerformingAction}
            checkoutNotice={checkoutNotice}
            onDismissCheckoutNotice={() => setCheckoutNotice(null)}
          />
        )}

        {currentView === 'progress' && selectedScanId && (
          <ScanProgress
            scanId={selectedScanId}
            onScanFinished={(scanId) => {
              // Refresh history lists & immediately route to viewer page
              if (user) loadUserContext();
              handleNavigate('report', scanId);
            }}
            onCancel={() => {
              void cancelScan(selectedScanId);
              setCurrentView('dashboard');
              setSelectedScanId(null);
            }}
          />
        )}

        {currentView === 'report' && activeScan && (
          <ReportViewer
            scan={activeScan}
            previousScan={scans.filter(s => sameTarget(s.url, activeScan.url) && s.id !== activeScan.id && s.status === 'complete' && new Date(s.createdAt).getTime() < new Date(activeScan.createdAt).getTime()).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]}
            onBack={() => handleNavigate('dashboard')}
            onRefreshScans={() => loadUserContext()}
          />
        )}
      </main>

      {/* Passwordless Magic Sign-in popup option */}
      {showLogin && (
        <LoginModal
          onClose={() => setShowLogin(false)}
        />
      )}

    </div>
  );
}
