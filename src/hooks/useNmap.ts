import { useState, useEffect } from 'react';
import { NmapScan, User } from '../types.js';

// Network Reconnaissance (nmap) — fully independent of useSeclayer/useScanPolling:
// its own data, its own launch/cancel actions, its own in-flight polling. Mirrors
// useMonitoring's "list of independent jobs" shape (one hook object, per-row busy
// state) rather than the single-scan useScanPolling page-driven pattern, since
// this drives a history tab of many past scans, not one focused report view.
export function useNmap(user: User) {
  const [nmapScans, setNmapScans] = useState<NmapScan[]>([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [isLaunching, setIsLaunching] = useState(false);
  const [launchError, setLaunchError] = useState('');
  const [busyScanId, setBusyScanId] = useState<string | null>(null);

  const fetchNmapScans = async () => {
    try {
      const res = await fetch('/api/nmap/scans');
      if (res.ok) {
        const data = await res.json();
        setNmapScans(data.scans || []);
      }
    } catch (err) {
      console.error('Error loading network reconnaissance scans:', err);
    }
  };

  useEffect(() => {
    fetchNmapScans();
  }, [user.id]);

  // While any scan is still queued/scanning, keep refreshing until it resolves
  // — a full-depth nmap sweep runs for many minutes, so without this the row
  // would sit on "Scanning…" until a manual reload.
  useEffect(() => {
    const inFlight = nmapScans.some((s) => s.status === 'queued' || s.status === 'scanning');
    if (!inFlight) return;
    const timer = setInterval(fetchNmapScans, 5000);
    return () => clearInterval(timer);
  }, [nmapScans]);

  const launchScan = async (url: string) => {
    const urlStr = url.trim();
    if (!urlStr) return;
    setIsLaunching(true);
    setLaunchError('');
    try {
      const res = await fetch('/api/nmap/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlStr }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setTargetUrl('');
        await fetchNmapScans();
      } else {
        setLaunchError(data.message || 'Could not start the network reconnaissance scan.');
      }
    } catch {
      setLaunchError('Could not start the scan — check your connection and try again.');
    } finally {
      setIsLaunching(false);
    }
  };

  const cancelScan = async (id: string) => {
    setBusyScanId(id);
    try {
      const res = await fetch(`/api/nmap/scans/${id}/cancel`, { method: 'POST' });
      if (res.ok) await fetchNmapScans();
    } catch (err) {
      console.error('Error canceling network reconnaissance scan:', err);
    } finally {
      setBusyScanId(null);
    }
  };

  return {
    nmapScans, fetchNmapScans,
    targetUrl, setTargetUrl, isLaunching, launchError,
    busyScanId, launchScan, cancelScan,
  };
}
