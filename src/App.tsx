import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar.js';
import Landing from './pages/Landing.js';
import Dashboard from './pages/Dashboard.js';
import ReportViewer from './pages/ReportViewer.js';
import ScanProgress from './pages/ScanProgress.js';
import LoginModal from './components/LoginModal.js';
import { User, Scan, ApiKey } from './types.js';
import { ShieldAlert, RefreshCw } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [credits, setCredits] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);
  // The raw secret of a just-generated API key. The server only ever returns
  // it once (in the POST /api/keys response), so it lives in memory only —
  // never persisted, never re-fetchable, cleared on dismiss or reload.
  const [justGeneratedKey, setJustGeneratedKey] = useState<{ id: string; rawKey: string } | null>(null);
  
  // Navigation states
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report'>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [isPerformingAction, setIsPerformingAction] = useState(false);
  
  // Restore the session (if any) on load. Identity comes from the httpOnly
  // session cookie, so no userId is ever passed from the client.
  useEffect(() => {
    loadUserContext();
  }, []);

  const loadUserContext = async () => {
    setIsPerformingAction(true);
    try {
      // 1. Fetch user profile from the session cookie.
      const userRes = await fetch('/api/auth/me');
      if (userRes.ok) {
        const userData = await userRes.json();
        setUser(userData.user);
        setCredits(userData.user.credits);

        // 2. Fetch user's scans list
        const scansRes = await fetch('/api/scans');
        if (scansRes.ok) {
          const scansData = await scansRes.json();
          setScans(scansData.scans);
        }

        // 3. Fetch user's developer keys
        const keysRes = await fetch('/api/keys');
        if (keysRes.ok) {
          const keysData = await keysRes.json();
          setApiKeys(keysData.keys);
        }

        // 4. Fetch user credit transactions
        const creditsRes = await fetch('/api/credits');
        if (creditsRes.ok) {
          const creditsData = await creditsRes.json();
          setTransactions(creditsData.transactions || []);
        }
      } else {
        // No valid session — present the app in a logged-out state.
        setUser(null);
        setScans([]);
        setApiKeys([]);
        setCredits(0);
      }

      // Handle return from Stripe Checkout: land on the dashboard and clean the
      // query string. Credits arrive via the webhook, reflected by this reload.
      const params = new URLSearchParams(window.location.search);
      if (params.has('checkout_success') || params.has('checkout_canceled')) {
        if (userRes.ok) setCurrentView('dashboard');
        window.history.replaceState({}, '', window.location.pathname);
      }
    } catch (err) {
      console.error('Error loading user dashboard metrics:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleNavigate = (view: string, arg?: string) => {
    if (view === 'report' && arg) {
      setSelectedScanId(arg);
      setCurrentView('report');
    } else {
      setSelectedScanId(null);
      setCurrentView(view as any);
    }
    // Scroll smoothly back to top on transitions
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleStartTrial = (initialUrl: string) => {
    // If guest clicks landing page audit input, we route them into console 
    // and trigger the scan immediately! Outstanding, frictionless signup flow.
    if (!user) {
      setShowLogin(true);
      return;
    }
    setCurrentView('dashboard');
    setTimeout(() => {
      onInitiateScan(initialUrl);
    }, 400);
  };

  const onInitiateScan = async (url: string, authHeader?: string) => {
    if (!user) {
      setShowLogin(true);
      return;
    }

    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, authHeader })
      });

      if (res.ok) {
        const data = await res.json();
        // Optimistically deduct credit locally & add scan to list
        setCredits(prev => Math.max(0, prev - 1));
        setScans(prev => [data.scan, ...prev]);

        // Open scanning terminal screen
        setSelectedScanId(data.scan.id);
        setCurrentView('progress');

        // Refresh full state background metrics in parallel
        setTimeout(() => loadUserContext(), 1000);
      } else {
        const errData = await res.json();
        alert(errData.message || 'Scanning initiation failed');
      }
    } catch (err) {
      console.error('Core scan launch err:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onGenerateKey = async () => {
    if (!user) return;
    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (res.ok) {
        const data = await res.json();
        // The raw key is only ever present in this one response — capture it
        // now so it can be shown once, then reload the (masked) keys listing.
        setJustGeneratedKey({ id: data.key.id, rawKey: data.rawKey });
        loadUserContext();
      }
    } catch (err) {
      console.error('Key generation error:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onRevokeKey = async (keyId: string) => {
    if (!user) return;
    setIsPerformingAction(true);
    try {
      const res = await fetch(`/api/keys/${keyId}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        // Reload keys listing
        loadUserContext();
      }
    } catch (err) {
      console.error('Key revoking error:', err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  const onPurchaseCredits = async (packName: 'single' | 'pack5' | 'pack20') => {
    if (!user) {
      setShowLogin(true);
      return;
    }
    setIsPerformingAction(true);
    try {
      const res = await fetch('/api/credits/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pack: packName })
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.url) {
        // Redirect to Stripe's hosted checkout. Credits are granted by the
        // webhook after payment; we return to /dashboard?checkout_success=true.
        window.location.href = data.url;
        return;
      }
      alert(data.message || 'Checkout is currently unavailable. Please try again later.');
    } catch (err) {
      console.error('Purchase transactions failed:', err);
      alert('Could not start checkout. Please try again.');
    } finally {
      setIsPerformingAction(false);
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } catch {}
    setUser(null);
    setScans([]);
    setApiKeys([]);
    setCredits(0);
    setCurrentView('landing');
  };

  // Find active scan we are polling/viewing
  const activeScan = scans.find(s => s.id === selectedScanId);

  return (
    <div className="bg-zinc-950 min-h-screen flex flex-col font-sans">
      
      {/* Universal navigation bar */}
      <Navbar
        currentView={currentView}
        onNavigate={handleNavigate}
        userEmail={user?.email || ''}
        credits={credits}
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
            userEmail={user?.email || ''}
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
              setCurrentView('dashboard');
              setSelectedScanId(null);
            }}
          />
        )}

        {currentView === 'report' && activeScan && (
          <ReportViewer
            scan={activeScan}
            previousScan={scans.filter(s => s.url === activeScan.url && s.id !== activeScan.id && new Date(s.createdAt).getTime() < new Date(activeScan.createdAt).getTime()).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]}
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
