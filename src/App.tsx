import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import LoginModal from './components/LoginModal.js';
import { useSeclayer } from './hooks/useSeclayer.js';

export default function App() {
  const {
    user, scans, apiKeys, credits, transactions, freeMode, justGeneratedKey, setJustGeneratedKey,
    deepseekKeySet, deepseekKeyPreview, saveDeepseekKey,
    currentView, setCurrentView, selectedScanId, setSelectedScanId, showLogin, setShowLogin,
    isPerformingAction, activeScan, checkoutNotice, setCheckoutNotice,
    loadUserContext, handleNavigate, handleStartTrial, onInitiateScan, cancelScan,
    onGenerateKey, onRevokeKey, onPurchaseCredits, handleLogout,
  } = useSeclayer();

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
            previousScan={scans.filter(s => s.url === activeScan.url && s.id !== activeScan.id && s.status === 'complete' && new Date(s.createdAt).getTime() < new Date(activeScan.createdAt).getTime()).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]}
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
