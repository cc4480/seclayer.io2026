import { useState, useEffect } from 'react';
import { User, Scan, ApiKey } from '../types.js';

// App-wide controller: owns session/data state, view navigation, and every
// action handler (scan launch, key lifecycle, credit purchase, logout). Kept
// out of App.tsx so the component is just the view router. Behavior is identical
// to when these lived inline in App.
export function useSeclayer() {
  const [user, setUser] = useState<User | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [credits, setCredits] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);
  // Free public-testing mode (server-controlled): scans cost no credits, so the
  // UI hides the paywall and credit gating. Sourced from /api/auth/me.
  const [freeMode, setFreeMode] = useState(false);
  // Dev-only (server-controlled): active red-team probes are unlocked without the
  // DNS/file domain-ownership step. Lets the launcher skip the verify gate while
  // testing locally. Always false in production. Sourced from /api/auth/me.
  const [devSkipDomainVerification, setDevSkipDomainVerification] = useState(false);
  // Personal DeepSeek key (bring-your-own-key) status. The raw key is never sent
  // to the client — only whether one is set and a masked preview.
  const [deepseekKeySet, setDeepseekKeySet] = useState(false);
  const [deepseekKeyPreview, setDeepseekKeyPreview] = useState<string | null>(null);
  // The raw secret of a just-generated API key. The server only ever returns
  // it once (in the POST /api/keys response), so it lives in memory only —
  // never persisted, never re-fetchable, cleared on dismiss or reload.
  const [justGeneratedKey, setJustGeneratedKey] = useState<{ id: string; rawKey: string } | null>(null);

  // Navigation states
  const [currentView, setCurrentView] = useState<'landing' | 'dashboard' | 'progress' | 'report'>('landing');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showLogin, setShowLogin] = useState(false);
  const [isPerformingAction, setIsPerformingAction] = useState(false);
  // Set once, right after returning from Stripe Checkout, so the dashboard can
  // show a real success/cancel message. A credits-before-vs-after comparison
  // doesn't work here: Checkout is a full-page redirect away and back, so this
  // whole app (and any "previous credits" state) remounts from scratch with
  // credits already at their post-purchase value by the time anything can
  // compare against it.
  const [checkoutNotice, setCheckoutNotice] = useState<'success' | 'canceled' | null>(null);

  // Wraps an async action in the shared busy flag + error logging every handler
  // otherwise repeated verbatim: flip isPerformingAction on, run the body,
  // always flip it off, and log (never throw) on failure. Per-handler guards
  // (e.g. "no user -> prompt login") stay at each call site so their early
  // returns keep their original semantics.
  const runAction = async (label: string, fn: () => Promise<void>) => {
    setIsPerformingAction(true);
    try {
      await fn();
    } catch (err) {
      console.error(label, err);
    } finally {
      setIsPerformingAction(false);
    }
  };

  // Restore the session (if any) on load. Identity comes from the httpOnly
  // session cookie, so no userId is ever passed from the client.
  useEffect(() => {
    loadUserContext();
  }, []);

  const loadUserContext = () => runAction('Error loading user dashboard metrics:', async () => {
    // 1. Fetch user profile from the session cookie.
    const userRes = await fetch('/api/auth/me');
    if (userRes.ok) {
      const userData = await userRes.json();
      setUser(userData.user);
      setCredits(userData.user.credits);
      setFreeMode(!!userData.freeMode);
      setDevSkipDomainVerification(!!userData.devSkipDomainVerification);
      setDeepseekKeySet(!!userData.deepseekKeySet);
      setDeepseekKeyPreview(userData.deepseekKeyPreview ?? null);

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

    // Handle return from Stripe Checkout: land on the dashboard, show a real
    // outcome message, and clean the query string. Credits arrive via the
    // webhook, reflected by this reload's fetched balance.
    const params = new URLSearchParams(window.location.search);
    if (params.has('checkout_success')) {
      if (userRes.ok) setCurrentView('dashboard');
      setCheckoutNotice('success');
      window.history.replaceState({}, '', window.location.pathname);
    } else if (params.has('checkout_canceled')) {
      if (userRes.ok) setCurrentView('dashboard');
      setCheckoutNotice('canceled');
      window.history.replaceState({}, '', window.location.pathname);
    }
  });

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

  const onInitiateScan = async (url: string, authHeader?: string, bolaIdentities?: any, activeProbes: boolean = true, aggressiveProbes: boolean = false) => {
    if (!user) {
      setShowLogin(true);
      return;
    }

    await runAction('Core scan launch err:', async () => {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, authHeader, bolaIdentities, activeProbes, aggressiveProbes })
      });

      if (res.ok) {
        const data = await res.json();
        // Optimistically deduct a credit locally (skipped in free mode, where
        // the server deducts nothing) & add the scan to the list.
        if (!freeMode) setCredits(prev => Math.max(0, prev - 1));
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
    });
  };

  // Cancels an in-flight scan and refunds its credit (server-side; see
  // db.cancelScan). Best-effort from the UI's perspective — the user is
  // returned to the dashboard regardless of the outcome, since the scan is
  // either now canceled or already reached a terminal state on its own.
  const cancelScan = async (scanId: string) => {
    try {
      await fetch(`/api/scans/${scanId}/cancel`, { method: 'POST' });
    } catch (err) {
      console.error('Cancel scan error:', err);
    } finally {
      loadUserContext();
    }
  };

  const onGenerateKey = async () => {
    if (!user) return;
    await runAction('Key generation error:', async () => {
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
    });
  };

  const onRevokeKey = async (keyId: string) => {
    if (!user) return;
    await runAction('Key revoking error:', async () => {
      const res = await fetch(`/api/keys/${keyId}`, { method: 'DELETE' });
      if (res.ok) {
        // Reload keys listing
        loadUserContext();
      }
    });
  };

  // Kept explicit (not via runAction) because its network-failure path shows a
  // distinct alert, unlike the log-only error handling every other action uses.
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

  // Save or clear the user's personal DeepSeek key. Returns the outcome so the
  // card can show inline validation errors; on success it updates the masked
  // status from the server's response.
  const saveDeepseekKey = async (key: string): Promise<{ ok: boolean; message?: string }> => {
    try {
      const res = await fetch('/api/user/deepseek-key', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setDeepseekKeySet(!!data.deepseekKeySet);
        setDeepseekKeyPreview(data.deepseekKeyPreview ?? null);
        return { ok: true };
      }
      return { ok: false, message: data.message || 'Could not save the key.' };
    } catch {
      return { ok: false, message: 'Could not save the key — check your connection and try again.' };
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

  return {
    user, scans, apiKeys, credits, transactions, freeMode, devSkipDomainVerification, justGeneratedKey, setJustGeneratedKey,
    deepseekKeySet, deepseekKeyPreview, saveDeepseekKey,
    currentView, setCurrentView, selectedScanId, setSelectedScanId, showLogin, setShowLogin,
    isPerformingAction, activeScan, checkoutNotice, setCheckoutNotice,
    loadUserContext, handleNavigate, handleStartTrial, onInitiateScan, cancelScan,
    onGenerateKey, onRevokeKey, onPurchaseCredits, handleLogout,
  };
}
